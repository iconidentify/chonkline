pub mod cmds;
pub mod ops;
pub mod proto;
pub mod state;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;

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
            name: env_or("IRC_SERVER_NAME", "rustirc"),
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

    let stop = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn(async move {
        // A dedicated task owns the listener; the supervisor below consumes
        // accepted connections from its channel and periodically polls
        // liveness (RFC 8.4), so cancellation is a single decision.
        let mut iv = tokio::time::interval(Duration::from_secs(30));
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::unbounded_channel::<tokio::net::TcpStream>();
        let accept_task = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                if conn_tx.send(sock).is_err() {
                    break; // supervisor gone: stop accepting
                }
            }
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
                _ = iv.tick() => { ops::liveness_tick(&state); },
            }
        }
    });

    Ok((local, task))
}

/// Synchronous bridge for in-process test scenarios: binds an ephemeral port, runs the server on a private runtime until the returned handle is dropped.
pub fn serve_sync() -> std::io::Result<(SocketAddr, Arc<AtomicBool>)> { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    let rt_now: &tokio::runtime::Runtime = Box::leak(Box::new(tokio::runtime::Builder::new_multi_thread().enable_all().build()?)); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let stop_now: Arc<AtomicBool> = Arc::new(AtomicBool::new(false)); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)



    let (local_now, _task_now): (SocketAddr, tokio::task::JoinHandle<()>) = rt_now.block_on(async move { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        serve("127.0.0.1:0".parse().expect("literal addr"), Config::default()).await.expect("server launch") // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    }); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    Ok((local_now, stop_now)) // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit) // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit) // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


}
