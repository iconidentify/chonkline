//! Minimal read-only web property for the IRC server: a status page plus JSON
//! endpoints for live statistics and LLM-generated release notes. Hand-rolled
//! HTTP/1.1 over tokio to keep the daemon dependency-light. Read-only and
//! side-effect free — it never mutates server state.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::state::ServerState;

pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

fn html(body: &str) -> HttpResponse {
    HttpResponse { status: 200, content_type: "text/html; charset=utf-8", body: body.to_string() }
}
fn json(body: String) -> HttpResponse {
    HttpResponse { status: 200, content_type: "application/json", body }
}
fn text(status: u16, body: &str) -> HttpResponse {
    HttpResponse { status, content_type: "text/plain; charset=utf-8", body: body.to_string() }
}

/// Route one request path (query string already stripped) to a response. Pure
/// and synchronous so it can be unit-tested without a socket.
pub fn route(path: &str, stg: &ServerState) -> HttpResponse {
    match path {
        "/" | "/index.html" => html(PAGE_HTML),
        "/api/stats" => json(stats_json(stg)),
        "/api/releases" => json(releases_json(stg)),
        "/healthz" => text(200, "ok"),
        _ => text(404, "not found"),
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Live server statistics as JSON.
pub fn stats_json(stg: &ServerState) -> String {
    format!(
        "{{\"server\":{},\"version\":{},\"uptime_seconds\":{},\"users_online\":{},\"peak_users\":{},\"invisible\":{},\"operators\":{},\"channels\":{},\"registered_accounts\":{},\"registered_channels\":{},\"total_connections\":{},\"messages_relayed\":{}}}",
        json_str(&stg.name),
        json_str(stg.version),
        stg.uptime_secs(),
        stg.user_count(),
        stg.peak_users,
        stg.invis_count(),
        stg.oper_count(),
        stg.chan_count(),
        stg.accounts.count(),
        stg.chanreg.count(),
        stg.total_connections,
        stg.messages_relayed,
    )
}

/// Release notes JSON, read from IRC_RELEASE_NOTES_PATH each request so a
/// config update is picked up without a restart. Falls back to an empty set.
fn releases_json(stg: &ServerState) -> String {
    if let Some(path) = &stg.release_notes_path {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "{\"releases\":[]}".to_string()
}

/// Run the web listener until the process ends. Best-effort: bind failures and
/// per-connection errors are swallowed so the IRC service is never affected.
pub async fn serve_http(state: Arc<Mutex<ServerState>>, port: u16) {
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(_) => return,
    };
    serve_http_loop(state, listener).await;
}

/// Accept loop over an already-bound listener (split out for testing).
pub async fn serve_http_loop(state: Arc<Mutex<ServerState>>, listener: TcpListener) {
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => continue,
        };
        let state = state.clone();
        tokio::spawn(async move {
            // Read headers (bounded); we only need the request line.
            let mut buf = [0u8; 4096];
            let mut got = Vec::new();
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        got.extend_from_slice(&buf[..n]);
                        if got.windows(4).any(|w| w == b"\r\n\r\n") || got.len() > 16 * 1024 {
                            break;
                        }
                    }
                    Err(_) => return,
                }
            }
            let head = String::from_utf8_lossy(&got);
            let mut parts = head.split_whitespace();
            let _method = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("/");
            let path = target.split('?').next().unwrap_or("/");

            let resp = {
                let stg = state.lock().unwrap();
                route(path, &stg)
            };
            let payload = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
                resp.status,
                if resp.status == 200 { "OK" } else if resp.status == 404 { "Not Found" } else { "Error" },
                resp.content_type,
                resp.body.as_bytes().len(),
                resp.body,
            );
            let _ = sock.write_all(payload.as_bytes()).await;
            let _ = sock.flush().await;
        });
    }
}

/// The single-page web property. Fetches /api/stats (auto-refreshing) and
/// /api/releases and renders them; all styling and script are inline so the
/// daemon serves one self-contained document.
const PAGE_HTML: &str = include_str!("web/index.html");

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ServerState {
        ServerState::new("irc.test", "o", "p", "l1", "l2", "a@b.c", "127.0.0.1 6697")
    }

    #[test]
    fn stats_endpoint_is_valid_json_with_fields() {
        let s = state();
        let r = route("/api/stats", &s);
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "application/json");
        for key in ["\"server\":", "\"version\":", "\"uptime_seconds\":", "\"users_online\":", "\"messages_relayed\":", "\"peak_users\":"] {
            assert!(r.body.contains(key), "stats json missing {key}: {}", r.body);
        }
    }

    #[test]
    fn index_and_health_and_404() {
        let s = state();
        assert_eq!(route("/", &s).status, 200);
        assert!(route("/", &s).body.contains("chonkline") || route("/", &s).body.contains("Chonkline"));
        assert_eq!(route("/healthz", &s).status, 200);
        assert_eq!(route("/nope", &s).status, 404);
    }

    #[test]
    fn releases_defaults_to_empty_set() {
        let s = state();
        let r = route("/api/releases", &s);
        assert!(r.body.contains("releases"));
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[tokio::test]
    async fn serves_over_a_real_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let st = Arc::new(Mutex::new(state()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_http_loop(st, listener));

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /api/stats?x=1 HTTP/1.1\r\nHost: t\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = s.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"), "no 200: {resp}");
        assert!(resp.contains("application/json"), "wrong content type: {resp}");
        assert!(resp.contains("\"users_online\":"), "no stats body: {resp}");
    }
}
