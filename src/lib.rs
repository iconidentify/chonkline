pub mod accounts;
pub mod bans;
pub mod channels;
pub mod cmds;
pub mod crypto;
pub mod http;
pub mod limits;
pub mod log;
pub mod ops;
pub mod proto;
pub mod proxyproto;
pub mod state;
pub mod tls;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;

/// Depth of the accepted-connection handoff queue (see the accept task below).
const ACCEPT_QUEUE: usize = 256;

/// Server identity and operational configuration.
pub struct Config {
    pub name: String,
    pub oper_user: String,
    pub oper_pass: String,
    pub admin_loc1: String,
    pub admin_loc2: String,
    pub admin_email: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            name: env_or("IRC_SERVER_NAME", "chonkline"),
            oper_user: env_or("IRC_OPER_USER", "oper"),
            oper_pass: env_or("IRC_OPER_PASS", "secret"),
            admin_loc1: env_or("IRC_ADMIN_LOC1", "Nowhere"),
            admin_loc2: env_or("IRC_ADMIN_LOC2", "No university"),
            admin_email: env_or("IRC_ADMIN_EMAIL", "admin@example.invalid"),
        }
    }
}

fn env_or(key: &str, default: &'static str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Run the IRC server on `addr` until the returned handle is dropped (which
/// aborts the listener loop and any liveness polling in flight). Returns the
/// bound address so tests can dial an ephemeral port.
pub async fn serve(addr: SocketAddr, cfg: Config) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    let listen_desc = format!("127.0.0.1 {}", local.port());
    let state: Arc<Mutex<state::ServerState>> = Arc::new(Mutex::new(state::ServerState::new(
        &cfg.name,
        &cfg.oper_user,
        &cfg.oper_pass,
        &cfg.admin_loc1,
        &cfg.admin_loc2,
        &cfg.admin_email,
        &listen_desc,
    )));

    // Optional web property (status page + stats/release-notes API). Runs on its
    // own listener; a bind failure never affects the IRC service.
    if let Some(http_port) = std::env::var("IRC_HTTP_PORT").ok().and_then(|v| v.parse::<u16>().ok()) {
        if http_port != 0 {
            let http_state = state.clone();
            tokio::spawn(async move { http::serve_http(http_state, http_port).await });
        }
    }

    // Optional TLS listener. Terminating in-process (rather than behind a
    // sidecar) is what lets a TLS client's real address reach the cloak and
    // limit paths: the PROXY header arrives ahead of the handshake on the raw
    // stream, so it is read before anything is decrypted.
    let tls_listener = match tls::configured() {
        Some((port, cert, key)) => match tls::acceptor_from_files(&cert, &key) {
            Ok(acceptor) => match TcpListener::bind((addr.ip(), port)).await {
                Ok(l) => {
                    log::event(log::INFO, "tls.listening", &[("port", &port.to_string())]);
                    Some((l, acceptor))
                }
                Err(e) => {
                    // A TLS bind failure must not take the plaintext port down.
                    log::event(log::ERROR, "tls.bind_failed", &[("port", &port.to_string()), ("error", &e.to_string())]);
                    None
                }
            },
            Err(e) => {
                log::event(log::ERROR, "tls.config_failed", &[("error", &e)]);
                None
            }
        },
        None => None,
    };

    // HTTPS for the web property, sharing the IRC certificate. Only starts when
    // both a port and a usable certificate are configured; a failure here never
    // affects the IRC listeners.
    if let Some(https_port) = std::env::var("IRC_HTTPS_PORT").ok().and_then(|v| v.parse::<u16>().ok()) {
        if https_port != 0 {
            if let Some((_, cert, key)) = tls::configured() {
                match tls::acceptor_from_files(&cert, &key) {
                    Ok(acceptor) => {
                        let https_state = state.clone();
                        tokio::spawn(async move { http::serve_https(https_state, https_port, acceptor).await });
                    }
                    Err(e) => log::event(log::ERROR, "https.config_failed", &[("error", &e)]),
                }
            }
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn(async move {
        // A dedicated task owns the listener; the supervisor below consumes
        // accepted connections from its channel and periodically polls
        // liveness (RFC 8.4), so cancellation is a single decision.
        let tick_secs: u64 = std::env::var("CHONKLINE_LIVENESS_TICK_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
        let mut iv = tokio::time::interval(Duration::from_secs(tick_secs.max(1)));
        // Round-4: fast-reconnect reclaim expiries resolve on a short cadence,
        // independently of the slow liveness interval above.
        let mut fast_iv = tokio::time::interval(Duration::from_millis(200));
        // Bounded queue: an unbounded one lets a connect flood accumulate live
        // sockets (each an fd) faster than the supervisor can drain them. At the
        // bound, backpressure reaches the listener and the kernel's own accept
        // backlog absorbs the burst instead of this process.
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel::<tokio::net::TcpStream>(ACCEPT_QUEUE);
        let _accept_task = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                if conn_tx.send(sock).await.is_err() {
                    break; // supervisor gone: stop accepting
                }
            }
        });

        // The TLS port gets its own bounded queue, so a flood on one port
        // cannot starve the other of accept slots.
        let (tls_tx, mut tls_rx) = tokio::sync::mpsc::channel::<tokio::net::TcpStream>(ACCEPT_QUEUE);
        let tls_acceptor = tls_listener.map(|(l, acceptor)| {
            tokio::spawn(async move {
                while let Ok((sock, _)) = l.accept().await {
                    if tls_tx.send(sock).await.is_err() {
                        break;
                    }
                }
            });
            acceptor
        });

        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            tokio::select! {
                conn = conn_rx.recv() => match conn {
                    Some(sock) => { ops::spawn_connection(&state, sock); }
                    None => break, // accept task ended: stop serving
                },
                tls_conn = tls_rx.recv(), if tls_acceptor.is_some() => {
                    if let (Some(sock), Some(acc)) = (tls_conn, tls_acceptor.as_ref()) {
                        ops::spawn_tls_connection(&state, sock, acc.clone());
                    }
                },
                _ = iv.tick() => {
                    ops::liveness_tick(&state);
                    // Aggregated refusal/flood counters surface here rather than
                    // one line per event, so a flood cannot flood the log.
                    log::flush_counters();
                    if let Ok(stg) = state.lock() {
                        log::heartbeat(stg.user_count(), stg.chan_count(), stg.sources.active_total(), stg.sources.tracked_sources());
                    }
                },
                _ = fast_iv.tick() => { ops::reclaim_tick(&state); },
            }
        }
    });

    Ok((local, task))
}

/// Synchronous bridge for in-process test scenarios: binds an ephemeral port, runs the server on a private runtime until the returned handle is dropped.
pub fn serve_sync() -> std::io::Result<(SocketAddr, Arc<AtomicBool>)> {
    let rt_now: &tokio::runtime::Runtime = Box::leak(Box::new(tokio::runtime::Builder::new_multi_thread().enable_all().build()?));

    let stop_now: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));



    let (local_now, _task_now): (SocketAddr, tokio::task::JoinHandle<()>) = rt_now.block_on(async move {
        serve("127.0.0.1:0".parse().expect("literal addr"), Config::default()).await.expect("server launch")
    });


    Ok((local_now, stop_now))


}
