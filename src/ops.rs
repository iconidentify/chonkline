use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};

use socket2::{SockRef, TcpKeepalive};

use crate::proto;
use crate::state::{norm_nick, ServerState};

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// Per-connection flood window (RFC 8.10): one message per two seconds is the
/// sustainable rate; bursts above six messages within two seconds have the
/// excess lines silently dropped.
const FLOOD_WINDOW: Duration = Duration::from_secs(2);
const FLOOD_BURST: usize = 6;

fn find_terminator(buf: &[u8]) -> Option<usize> {
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' || b == b'\r' {
            return Some(i);
        }
    }
    None
}

/// Strip a CR-LF / LF / CR terminator; returns the content length.
fn strip_terminator(seg: &mut [u8]) -> usize {
    let mut n = seg.len();
    if n > 0 && seg[n - 1] == b'\n' {
        n -= 1;
    }
    if n > 0 && seg[n - 1] == b'\r' {
        n -= 1;
    }
    n
}

/// Accept one client connection, run its read/write tasks, return the id.
pub fn spawn_connection(
    state: &Arc<Mutex<ServerState>>,
    sock: TcpStream,
) -> usize {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    // Peer address stands in for the client-supplied hostname and any ident/
    // reverse-DNS lookups, which are unavailable in this deployment.
    let host = sock
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or("0.0.0.0".into());

    // OS-level keepalive on every accepted socket: dead peers behind a load
    // balancer surface as half-open connections that no application-layer ping
    // can reach; TCP keeps them detected in ~30s instead of lingering forever.
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = SockRef::from(&sock).set_tcp_keepalive(&ka); // best effort: capability-less platforms keep the connection

    let (mut rd, mut wr) = sock.into_split();

    // Writer task: drain queued replies into the socket. Exits when its queue
    // closes (reader gone) or a write fails; dropping `wr` half-closes then.
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if wr.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            let _ = wr.flush().await; // best-effort per line batch
        }
    });

    let notify = Arc::new(Notify::new());
    park_unregistered(&state, id, host, tx.clone(), notify.clone());
    let st_owned = state.clone(); // owned copy: async-move captures by value only own values here
    tokio::spawn(async move {
        run_reader(st_owned, id, rd, notify).await;
    });

    id
}

/// Read loop: frames lines out of the byte stream (CR-LF / LF / CR per current
/// implementation practice), enforces the message-size limit (RFC 2.3) and
/// flood control (RFC 8.10), routes parsed commands to the dispatcher under
/// the state lock, and performs EOF cleanup on exit.
async fn run_reader(
    state: Arc<Mutex<ServerState>>,
    id: usize,
    mut rd: tokio::net::tcp::OwnedReadHalf,
    notify: Arc<Notify>,
) {
    let mut buf: Vec<u8> = Vec::with_capacity(proto::MAX_LINE_WITH_CRLF * 2);
    let mut flood: VecDeque<Instant> = VecDeque::new();

    loop {
        let mut chunk = [0u8; 1 << 16];
        tokio::select! {
            _ = notify.notified() => break,
            nres = rd.read(&mut chunk) => match nres {
                Ok(0) => break, // EOF from client
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            },
        }

        while let Some(pos) = find_terminator(&buf) {
            let term_end = if buf[pos] == b'\r' && pos + 1 < buf.len() && buf[pos + 1] == b'\n' {
                pos + 2
            } else {
                pos + 1
            };
            // RFC 2.3: a message must not exceed 512 octets counting the
            // trailing CR-LF. Overlong lines are dropped silently.
            if term_end > proto::MAX_LINE_WITH_CRLF {
                buf.drain(..term_end);
                continue;
            }
            let content: Vec<u8> = buf[..pos].to_vec();
            buf.drain(..term_end);

            if process_segment(&state, id, &mut flood, &content) {
                cleanup_on_eof(&state, id); // idempotent: no-ops when the session left cleanly via QUIT
                return;
            }
        }

        if buf.len() > 64 * 1024 {
            break; // pathological stream without terminators: drop connection
        }
    }

    cleanup_on_eof(&state, id);
}

/// Route one framed command line. Returns true when the session must close.
fn process_segment(
    state: &Arc<Mutex<ServerState>>,
    id: usize,
    flood: &mut VecDeque<Instant>,
    seg: &[u8],
) -> bool {
    if seg.is_empty() {
        return false; // empty messages are silently ignored (RFC 2.3.1)
    }
    let text = String::from_utf8_lossy(seg);
    match proto::parse(&text) {
        None => false, // grammar violations: dropped silently
        Some(cmd) => route(state, id, flood, &cmd),
    }
}

/// Session-level gates applied before command dispatch: prefix authenticity
/// (RFC 2.3), numeric-reply drops (RFC 2.4), the flood limit (RFC 8.10) and
/// the registration gate. Returns true when the session must close.
fn route(
    state: &Arc<Mutex<ServerState>>,
    id: usize,
    flood: &mut VecDeque<Instant>,
    cmd: &proto::Command,
) -> bool {
    if cmd.name.len() == 3 && cmd.name.chars().all(|c| c.is_ascii_digit()) {
        return false; // numeric replies from clients are dropped (RFC 2.4)
    }

    let quit = {
        let mut stg = state.lock().unwrap();

        if let Some(pfx) = &cmd.prefix {
            // Only the sender's own prefix may be carried; anything else is
            // ignored silently (RFC 2.3).
            let authentic = stg
                .find_by_id(id)
                .map(|u| u.registered && u.nick_key == norm_nick(pfx))
                .unwrap_or(false);
            if !authentic {
                return false;
            }
        }

        if let Some(u) = stg.find_by_id_mut(id) {
            u.last_rx = Instant::now(); // liveness bookkeeping (RFC 8.4)
        }

        // Flood control (RFC 8.10): excess over the burst is dropped silently.
        let now = Instant::now();
        flood.push_back(now);
        while let Some(front) = flood.front() {
            if now.duration_since(*front) > FLOOD_WINDOW {
                flood.pop_front();
            } else {
                break;
            }
        }
        if flood.len() > FLOOD_BURST {
            return false;
        }

        // Registration gate: everything but the pairing commands requires a
        // completed NICK/USER registration.
        let open = match cmd.name.as_str() {
            "NICK" | "USER" | "PASS" | "CAP" | "PING" | "PONG" => true,
            _ => stg.find_by_id(id).map(|u| u.registered).unwrap_or(false),
        };
        if !open {
            deliver_not_registered(&mut stg, id);
            return false;
        }

        // Round-4 fast-reconnect resolution: an inbound PONG from a connection that
        // holds an unanswered reclaim ping answers every held-back requester with
        // the collision refusal and clears both bookkeeping entries at once.
        if cmd.name == "PONG" && stg.ping_outstanding.remove(&id).is_some() {
            if let Some(mark) = stg.grace_reclaim.remove(&id) {
                for (rid, ref_now) in mark.pairings.iter().chain(mark.renames.iter()) {
                    crate::cmds::deliver_nickname_in_use(&mut stg, *rid, ref_now);
                }
            }
        }

        crate::cmds::dispatch(&mut stg, id, cmd)
    };
    quit
}

/// ERR_NOTREGISTERED (RFC numeric 451).
fn deliver_not_registered(stg: &mut ServerState, id: usize) {
    let p = stg.prefix();
    let nick = stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_else(|| "*".into());
    let line = proto::line(&p, "451", &format!("{} :You have not registered", nick));
    if let Some(u) = stg.find_by_id(id) {
        let _ = u.tx.send(line);
    }
}

/// Natural-closure path (EOF or socket death): when the session still holds an
/// identity in state, announce a quit message reflecting the event (RFC 8.7),
/// then remove it from every channel and nick table. Idempotent for clean
/// exits that already purged via QUIT/kill.
fn cleanup_on_eof(state: &Arc<Mutex<ServerState>>, id: usize) {
    let mut stg = state.lock().unwrap();
    match stg.find_by_id(id).map(|u| (u.registered, u.prefix())) {
        Some((true, pfx)) => {
            let line = proto::line(&pfx, "QUIT", ":Client connection lost");
            for other in stg.each_user() {
                if other.id == id {
                    continue;
                }
                let _ = other.tx.send(line.clone());
            }
        }
        Some(_) => {} // unregistered: nothing to announce
        None => return, // already gone via QUIT/kill/etc.
    }
    stg.eject_user(id);
    stg.drop_empty_channels();
    let _ = stg.evict(id); // removes the record and signals this connection's close
}

/// Register-time plumbing performed before any commands are read: parks the
/// pre-registration record so pairing slots (pending NICK/USER) can fill, and
/// wires the connection's close-notify for external terminations.
pub fn park_unregistered(
    state: &Arc<Mutex<ServerState>>,
    id: usize,
    host: String,
    tx: mpsc::UnboundedSender<String>,
    notify: Arc<Notify>,
) {
    let mut stg = state.lock().unwrap();
    if stg.find_by_id(id).is_some() {
        return; // already parked (should not happen); be harmless
    }
    stg.park_new(id, host, tx, notify);
}

/// Liveness polling (RFC 8.4): connections silent for too long receive a PING;
/// those that never answer are dropped with a quit message reflecting the event.
/// Liveness windows in seconds. Shipped defaults run ~30s ping / ~30s eviction
/// so a dead client is gone within roughly a minute; tests may shrink both via
/// environment overrides so reaping stays verifiable at test scale.
fn eviction_window() -> std::time::Duration {
    let secs: u64 = std::env::var("CHONKLINE_EVICTION_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
    std::time::Duration::from_secs(secs.max(1))
}

fn ping_after_window() -> std::time::Duration {
    let secs: u64 = std::env::var("CHONKLINE_PING_AFTER_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
    std::time::Duration::from_secs(secs.max(1))
}

/// Fast-reconnect reclaim windows (round-4). A nick-colliding connection whose
/// holder shows the stale signature below is pinged proactively at collision time
/// and given a short grace to answer; silence past the grace evicts the holder.
/// Environment overrides keep both knobs tunable per deployment. Single source of
/// truth: the collision-time predicate and marker installation in cmds delegate here.
pub(crate) fn reclaim_silence_window() -> std::time::Duration {
    let secs: u64 = std::env::var("CHONKLINE_RECLAIM_SILENCE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    std::time::Duration::from_secs(secs)
}

pub(crate) fn reclaim_grace_window() -> std::time::Duration {
    let secs: u64 = std::env::var("CHONKLINE_RECLAIM_GRACE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    std::time::Duration::from_secs(secs.max(1))
}

/// Resolve expired fast-reconnect reclaim markers (round-4): evict the contested
/// holder, then complete each held-back requester's deferred pairing or rename.
/// Runs on a short supervisor cadence so expiries land promptly without waiting
/// for the slow liveness interval.
pub fn reclaim_tick(state: &Arc<Mutex<ServerState>>) {
    let mut stg = state.lock().unwrap();

    let now = Instant::now();
    let expired_now: Vec<usize> = stg
        .grace_reclaim
        .iter()
        .filter(|(_, mark)| now >= mark.expiry)
        .map(|(&holder_id, _)| holder_id)
        .collect();

    for holder_id in expired_now {
        let Some(mark) = stg.grace_reclaim.remove(&holder_id) else { continue; };
        stg.ping_outstanding.remove(&holder_id);
        announce_loss_and_evict(&mut stg, holder_id, "Ghost: not answering reclaim ping");
        for (rid, _ref_now) in mark.pairings {
            crate::cmds::complete_pairing_if_ready(&mut stg, rid);
        }
        for (rid, target_now) in mark.renames {
            crate::cmds::finish_deferred_rename(&mut stg, rid, &target_now);
        }
    }
}

pub fn liveness_tick(state: &Arc<Mutex<ServerState>>) {
    let mut stg = state.lock().unwrap();

    // Expire unanswered pings first, then ping newly-silent connections.
    let now = Instant::now();
    let expired: Vec<usize> = stg
        .ping_outstanding
        .iter()
        .filter_map(|(&id, &at)| {
            (now.duration_since(at) > eviction_window()).then_some(id)
        })
        .collect();
    for id in expired {
        stg.ping_outstanding.remove(&id);
        announce_loss_and_evict(&mut stg, id, "No response to PING");
    }

    let silent: Vec<usize> = stg
        .each_user()
        .filter(|u| now.duration_since(u.last_rx) > ping_after_window())
        .map(|u| u.id)
        .collect();
    for id in silent {
        if !stg.ping_outstanding.contains_key(&id) {
            let token = format!("{}-{}", stg.name, id);
            let line = proto::line(&stg.prefix(), "PING", &format!(":{}", token));
            send_to(&stg, id, &line);
            stg.ping_outstanding.insert(id, now);
        }
    }
}

/// Send one pre-formed line to a connection's reply queue (best effort).
fn send_to(stg: &ServerState, id: usize, line: &str) {
    if let Some(u) = stg.find_by_id(id) {
        let _ = u.tx.send(line.to_string());
    }
}

/// Announce the departure of a connection (if still present in state) and remove it.
pub(crate) fn announce_loss_and_evict(stg: &mut ServerState, id: usize, reason: &str) {
    if let Some(pfx) = stg.find_by_id(id).map(|u| u.prefix()) {
        let line = proto::line(&pfx, "QUIT", &format!(":{}", reason));
        for other in stg.each_user() {
            if other.id == id {
                continue;
            }
            let _ = other.tx.send(line.clone());
        }
    }
    stg.eject_user(id);
    stg.drop_empty_channels();
    let _ = stg.evict(id);
}

