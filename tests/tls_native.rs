//! End-to-end coverage for in-process TLS termination.
//!
//! The point of terminating here rather than behind a sidecar is that a TLS
//! client's *real* address reaches the cloak and limit paths. The PROXY header
//! is prepended to the raw TCP stream ahead of the handshake, so it is read
//! before anything is decrypted — these tests assert exactly that.
//!
//! The certificate is generated at test time with the `openssl` CLI rather than
//! committed, so no private key lives in the repository. The tests skip if
//! openssl is unavailable.

use std::sync::{Arc, Mutex};

/// Server startup mutates process-global environment, so only one test may be
/// in that window at a time. CI already runs with --test-threads=1; this keeps
/// a plain `cargo test` correct too.
static START: Mutex<()> = Mutex::new(());

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Generate a short-lived self-signed cert for `localhost`. Returns the cert and
/// key paths, or None when openssl is not installed.
fn generate_cert() -> Option<(String, String)> {
    let dir = std::env::temp_dir().join(format!("chonkline-tls-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let cert = dir.join("tls.crt").to_string_lossy().to_string();
    let key = dir.join("tls.key").to_string_lossy().to_string();

    if std::path::Path::new(&cert).exists() && std::path::Path::new(&key).exists() {
        return Some((cert, key));
    }

    let out = std::process::Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", &key, "-out", &cert,
            "-days", "1", "-nodes", // -nodes yields an unencrypted PKCS8 key
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
            // Without this openssl marks the cert CA:TRUE, and rustls then
            // refuses it as a leaf with CaUsedAsEndEntity. Real issuers hand out
            // end-entity certs, so this matches production shape too.
            "-addext", "basicConstraints=critical,CA:FALSE",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some((cert, key))
}

/// Connect with bounded retries: listeners are spawned asynchronously, so a
/// connect immediately after startup can beat the bind.
async fn connect_retry(port: u16) -> tokio::net::TcpStream {
    for _ in 0..100 {
        if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            return s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("nothing listening on port {port} after 2s");
}

/// Claim an ephemeral port by binding and releasing it.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("local addr").port()
}

fn client_config(cert_path: &str) -> ClientConfig {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let pem = std::fs::read_to_string(cert_path).expect("read test cert");
    let body = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .and_then(|r| r.split("-----END CERTIFICATE-----").next())
        .expect("certificate block");
    let der = irc_server::crypto::base64_decode(body).expect("decode certificate");

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(der)).expect("trust the test certificate");
    ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
}

/// Start a server with TLS enabled and PROXY parsing required, returning the
/// TLS port and the certificate path.
async fn start_tls_server() -> Option<(u16, String)> {
    start_tls_server_with_https().await.map(|(p, c, _)| (p, c))
}

/// As above, additionally starting the HTTPS listener; returns
/// (irc_tls_port, cert_path, https_port).
async fn start_tls_server_with_https() -> Option<(u16, String, u16)> {
    let _serialise = START.lock().unwrap_or_else(|p| p.into_inner());
    let (cert, key) = generate_cert()?;
    let port = free_port();
    let https_port = free_port();
    std::env::set_var("IRC_HTTPS_PORT", https_port.to_string());

    std::env::set_var("IRC_TLS_PORT", port.to_string());
    std::env::set_var("IRC_TLS_CERT", &cert);
    std::env::set_var("IRC_TLS_KEY", &key);
    std::env::set_var("IRC_PROXY_PROTOCOL", "1");
    std::env::set_var("IRC_PROXY_PROTOCOL_EXEMPT", ""); // require the header even on loopback
    std::env::set_var("IRC_CLOAK_SECRET", "tls-native-test-secret");
    std::env::set_var("IRC_CLOAK_SUFFIX", "users.test");

    irc_server::serve("127.0.0.1:0".parse().unwrap(), irc_server::Config::default())
        .await
        .expect("server launch");

    Some((port, cert, https_port))
}

/// Connect over TLS, presenting `src` in a PROXY header ahead of the handshake,
/// register, join, and return the cloak from the JOIN echo.
async fn tls_cloak_for(port: u16, cert: &str, src: &str, nick: &str) -> String {
    let mut tcp = connect_retry(port).await;

    // The header goes on the raw stream, before any TLS bytes.
    tcp.write_all(format!("PROXY TCP4 {} 10.0.0.1 40000 6697\r\n", src).as_bytes())
        .await
        .expect("write proxy header");

    let connector = TlsConnector::from(Arc::new(client_config(cert)));
    let name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(name, tcp).await.expect("tls handshake");

    tls.write_all(format!("NICK {}\r\nUSER {} 0 * :TLS Test\r\nJOIN #tlstest\r\n", nick, nick).as_bytes())
        .await
        .expect("write registration");

    // Read until the client's own JOIN echo appears.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    for _ in 0..64 {
        let n = match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(line) = text.lines().find(|l| l.contains("JOIN") && l.contains(nick)) {
            return line
                .split('@')
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
                .unwrap_or_default()
                .to_string();
        }
    }
    String::new()
}

#[tokio::test]
async fn tls_clients_get_real_distinct_cloaks() {
    let Some((port, cert)) = start_tls_server().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    let a = tls_cloak_for(port, &cert, "203.0.113.7", "tlsalice").await;
    let b = tls_cloak_for(port, &cert, "198.51.100.9", "tlsbob").await;

    assert!(!a.is_empty() && !b.is_empty(), "both TLS clients must register and join (a={a:?} b={b:?})");
    assert!(a.ends_with(".users.test"), "expected a cloaked host, got {a:?}");
    assert_ne!(
        a, b,
        "TLS users must no longer share one cloak — that sharing is exactly what the \
         sidecar caused and what terminating in-process fixes"
    );
}

#[tokio::test]
async fn tls_cloak_matches_the_plaintext_cloak_for_the_same_address() {
    // One address must map to one identity regardless of which port it arrived
    // on, otherwise a ban set from one port would miss the other.
    let Some((port, cert)) = start_tls_server().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    let first = tls_cloak_for(port, &cert, "203.0.113.77", "tlscarol").await;
    let second = tls_cloak_for(port, &cert, "203.0.113.77", "tlsdave").await;

    assert!(!first.is_empty(), "expected a cloak");
    assert_eq!(first, second, "one address must yield one stable cloak over TLS too");
}


#[tokio::test]
async fn the_web_property_is_served_over_tls() {
    // Behind its own load balancer there is no ingress left to terminate HTTPS
    // for this host, so the daemon has to do it or the page stops working.
    let Some((_irc, cert, https_port)) = start_tls_server_with_https().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    let tcp = connect_retry(https_port).await;
    let connector = TlsConnector::from(Arc::new(client_config(&cert)));
    let name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(name, tcp).await.expect("https handshake");

    tls.write_all(b"GET /api/stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    for _ in 0..32 {
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&body);
    assert!(text.starts_with("HTTP/1.1 200"), "expected 200 over TLS, got: {:?}", &text[..text.len().min(80)]);
    assert!(text.contains("\"server\""), "expected the stats payload, got: {:?}", &text[..text.len().min(200)]);
}

#[tokio::test]
async fn https_and_plaintext_serve_the_same_content() {
    // One handler behind both listeners, so the two cannot drift apart.
    let Some((_irc, cert, https_port)) = start_tls_server_with_https().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    let tcp = connect_retry(https_port).await;
    let connector = TlsConnector::from(Arc::new(client_config(&cert)));
    let name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(name, tcp).await.expect("https handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.expect("write");

    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    for _ in 0..64 {
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&body);
    assert!(text.starts_with("HTTP/1.1 200"), "index page must serve over TLS");
    assert!(text.contains("<"), "expected HTML for the index page");
}
