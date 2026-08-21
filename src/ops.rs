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

/// Per-connection reply queue depth. At ~200 bytes/line this bounds one
/// connection's queued output near 100 KiB, so the 512-client ceiling implies a
/// provable worst case rather than an open-ended one.
const REPLY_QUEUE: usize = 512;

/// Per-connection flood window (RFC 8.10): one message per two seconds is the
/// sustainable rate; bursts above six messages within two seconds have the
/// excess lines silently dropped.
const FLOOD_BURST: usize = 6;
/// Env-tunable (CHONKLINE_FLOOD_WINDOW_MS, default 2000ms) so the test suite can
/// shrink it; production keeps the 2-second default.
fn flood_window() -> Duration {
    let ms: u64 = std::env::var("CHONKLINE_FLOOD_WINDOW_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
    Duration::from_millis(ms.max(1))
}

/// Deterministic host cloak: users see `<8-hex>.<suffix>` derived from an
/// HMAC-SHA256 of their real address, never the raw IP. Deterministic per
/// address so channel bans on a cloak keep working across reconnects, while the
/// real address is disclosed only to operators. Tunable via IRC_CLOAK_SECRET
/// (set a real secret in production) and IRC_CLOAK_SUFFIX.
pub(crate) fn cloak_host(real: &str) -> String {
    let secret = std::env::var("IRC_CLOAK_SECRET")
        .unwrap_or_else(|_| "chonkline-default-cloak-secret".to_string());
    let suffix = std::env::var("IRC_CLOAK_SUFFIX").unwrap_or_else(|_| "chonkbase.net".to_string());
    let mac = crate::crypto::hmac_sha256(secret.as_bytes(), real.as_bytes());
    format!("{}.{}", crate::crypto::hex(&mac[..4]), suffix)
}

/// How a listener treats the PROXY protocol header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    /// Never look for a header; `peer_addr()` is the client.
    Off,
    /// Use a header when present, fall back to `peer_addr()` when absent.
    ///
    /// Only for cutover, and only briefly: while the proxy is not yet
    /// prepending its own header a client can send a forged one and choose its
    /// own apparent address. Once the proxy sends the header first, any forged
    /// line arrives after it and is parsed harmlessly as an IRC command.
    Optional,
    /// Require a header; refuse the connection without one.
    Required,
}

fn parse_mode(raw: &str) -> ProxyMode {
    match raw {
        "1" | "true" | "yes" | "on" | "required" => ProxyMode::Required,
        "optional" | "detect" => ProxyMode::Optional,
        _ => ProxyMode::Off,
    }
}

/// Mode for the plaintext listener (IRC_PROXY_PROTOCOL).
fn proxy_mode() -> ProxyMode {
    parse_mode(&std::env::var("IRC_PROXY_PROTOCOL").unwrap_or_default())
}

/// Mode for the TLS listener (IRC_TLS_PROXY_PROTOCOL), defaulting to the
/// plaintext setting. Separate because the two ports are configured
/// independently at the proxy and can be cut over one at a time.
fn tls_proxy_mode() -> ProxyMode {
    match std::env::var("IRC_TLS_PROXY_PROTOCOL") {
        Ok(v) => parse_mode(&v),
        Err(_) => proxy_mode(),
    }
}

/// Peers permitted to connect without a PROXY header while the feature is on.
///
/// Empty by default: TLS is terminated in-process, so nothing legitimately
/// reaches the daemon over loopback and every connection should carry a header.
/// An exemption list exists for deployments that still front the daemon with a
/// local terminator which cannot emit one — note that such peers necessarily
/// share a single cloak, since their real address never arrives.
fn proxy_exempt_peer(peer: &str) -> bool {
    match std::env::var("IRC_PROXY_PROTOCOL_EXEMPT") {
        Ok(list) => list.split(',').map(str::trim).any(|e| !e.is_empty() && e == peer),
        Err(_) => false,
    }
}

fn find_terminator(buf: &[u8]) -> Option<usize> {
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' || b == b'\r' {
            return Some(i);
        }
    }
    None
}

/// Apply the OS-level keepalive every accepted socket gets: dead peers behind a
/// load balancer surface as half-open connections that no application-layer
/// ping can reach; TCP detects them in ~30s instead of lingering forever.
fn arm_keepalive(sock: &TcpStream) {
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = SockRef::from(sock).set_tcp_keepalive(&ka); // best effort: capability-less platforms keep the connection
}

/// Accept one plaintext client connection, run its read/write tasks, return the id.
pub fn spawn_connection(
    state: &Arc<Mutex<ServerState>>,
    sock: TcpStream,
) -> usize {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    arm_keepalive(&sock);

    let st_owned = state.clone();
    tokio::spawn(async move {
        admit_and_run(st_owned, id, sock, None).await;
    });

    id
}

/// Accept one TLS client connection. The PROXY header and admission control are
/// handled on the raw stream first, so the real client address is known before
/// the handshake and feeds the same cloak, ban and limit paths as plaintext.
pub fn spawn_tls_connection(
    state: &Arc<Mutex<ServerState>>,
    sock: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
) -> usize {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    arm_keepalive(&sock);

    let st_owned = state.clone();
    tokio::spawn(async move {
        admit_and_run(st_owned, id, sock, Some(acceptor)).await;
    });

    id
}

/// Resolve the client's real address, apply admission control, then run the
/// session. Everything here is async because the PROXY header has to be read
/// off the socket before the address — and therefore the cloak, the ban check
/// and the per-source limits — can be known.
async fn admit_and_run(
    state: Arc<Mutex<ServerState>>,
    id: usize,
    mut sock: TcpStream,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
) {
    let is_tls = acceptor.is_some();
    let peer = sock
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".into());

    // Resolve the client's real address from the PROXY header the proxy
    // prepends. The stream is *peeked* first: a TLS ClientHello must not be
    // consumed by a header read, so bytes are only taken once they are known to
    // begin a header. That also makes Optional mode safe on the TLS port.
    let mode = if is_tls { tls_proxy_mode() } else { proxy_mode() };
    let real_host = if mode != ProxyMode::Off && !proxy_exempt_peer(&peer) {
        // Time-bounded: this runs BEFORE admission control, so a client that
        // sends "PROXY " and then stalls would otherwise hold a task and an fd
        // that no limit counts.
        let peeked = match tokio::time::timeout(
            Duration::from_secs(10),
            crate::proxyproto::peek_is_header(&sock),
        ).await {
            Ok(p) => p,
            Err(_) => { crate::log::counted("proxy.timeout", ""); return; }
        };
        match peeked {
            crate::proxyproto::Peek::Header => match tokio::time::timeout(
                Duration::from_secs(10),
                crate::proxyproto::read_v1(&mut sock),
            ).await.unwrap_or(crate::proxyproto::Header::Invalid) {
                crate::proxyproto::Header::Source(addr) => addr,
                crate::proxyproto::Header::Unknown => peer.clone(),
                crate::proxyproto::Header::Empty => return, // hung up mid-header
                crate::proxyproto::Header::Invalid => {
                    crate::log::proxy_rejected(&peer);
                    refuse(&mut sock, is_tls, "Malformed PROXY protocol header").await;
                    return;
                }
            },
            crate::proxyproto::Peek::Closed => return, // probe or hang-up: close quietly
            crate::proxyproto::Peek::Other => {
                if mode == ProxyMode::Required {
                    // Fail closed: falling back here would silently restore the
                    // shared-address behaviour this exists to prevent.
                    crate::log::proxy_rejected(&peer);
                    refuse(&mut sock, is_tls, "PROXY protocol header required").await;
                    return;
                }
                // Optional: proceed, but make the gap visible in the logs.
                crate::log::counted("proxy.absent", &peer);
                peer.clone()
            }
        }
    } else {
        peer.clone()
    };

    // Bans and admission control are both keyed on that resolved address.
    // Both decisions are taken under one short lock, and every socket write
    // happens after it is released.
    enum Deny {
        Banned(String),
        Limited(crate::limits::Refusal),
    }

    let deny = {
        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
        let stg = &mut *guard;
        match stg.bans.matching(&real_host) {
            Some(ban) => Some(Deny::Banned(ban.reason.clone())),
            None => stg
                .sources
                .try_admit(&stg.limits, &real_host, Instant::now())
                .err()
                .map(Deny::Limited),
        }
    };

    match deny {
        Some(Deny::Banned(reason)) => {
            crate::log::counted("conn.banned", &real_host);
            refuse(&mut sock, is_tls, &format!("Banned: {}", reason)).await;
            return;
        }
        Some(Deny::Limited(why)) => {
            crate::log::refused(why.as_str());
            refuse(&mut sock, is_tls, why.message()).await;
            return;
        }
        None => {}
    }

    let host = cloak_host(&real_host);
    // DEBUG, not INFO: health checks open and close a connection every few
    // seconds and would otherwise be ~95% of the log, rotating the real events
    // out of retention within hours. The security-relevant event is a session
    // reaching registration, logged from the registration path instead.
    crate::log::conn_open(id, &real_host, &host, if is_tls { "tls" } else { "plain" });

    // The handshake happens only after admission, so a refused connection never
    // costs a key exchange — which matters precisely when refusals are frequent.
    match acceptor {
        Some(acc) => match acc.accept(sock).await {
            Ok(stream) => run_session(&state, id, stream, &host, &real_host).await,
            Err(e) => {
                crate::log::counted("tls.handshake_failed", &real_host);
                let _ = e;
            }
        },
        None => run_session(&state, id, sock, &host, &real_host).await,
    }

    // Release the admission slot this connection reserved, and record the close
    // with whatever identity it had reached.
    let nick = {
        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
        let stg = &mut *guard;
        stg.sources.release(&stg.limits, &real_host, Instant::now());
        stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default()
    };
    crate::log::conn_close(id, &real_host, &nick, "closed");
}

/// Write a refusal and close. On the TLS port the stream is not encrypted yet,
/// so an IRC line would reach the client as protocol garbage; there the socket
/// is simply closed.
async fn refuse(sock: &mut TcpStream, is_tls: bool, reason: &str) {
    if !is_tls {
        let _ = sock.write_all(format!("ERROR :{}\r\n", reason).as_bytes()).await;
    }
    let _ = sock.shutdown().await;
}

/// Run one client session over an established stream, plaintext or TLS.
async fn run_session<S>(
    state: &Arc<Mutex<ServerState>>,
    id: usize,
    stream: S,
    host: &str,
    real_host: &str,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (rd, mut wr) = tokio::io::split(stream);

    // Writer task: drain queued replies into the socket. Exits when its queue
    // closes (reader gone) or a write fails; dropping `wr` half-closes then.
    // Bounded: caps per-connection queued output at REPLY_QUEUE lines, so a
    // slow or deliberately non-reading client costs a known, finite amount of
    // memory instead of an unbounded one.
    let (tx, mut rx) = mpsc::channel::<String>(REPLY_QUEUE);
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if wr.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            let _ = wr.flush().await; // best-effort per line batch
        }
    });

    let notify = Arc::new(Notify::new());
    park_unregistered(state, id, host.to_string(), real_host.to_string(), tx.clone(), notify.clone());

    run_reader(state.clone(), id, rd, notify, real_host.to_string()).await;
}

/// Read loop: frames lines out of the byte stream (CR-LF / LF / CR per current
/// implementation practice), enforces the message-size limit (RFC 2.3) and
/// flood control (RFC 8.10), routes parsed commands to the dispatcher under
/// the state lock, and performs EOF cleanup on exit.
async fn run_reader<R>(
    state: Arc<Mutex<ServerState>>,
    id: usize,
    mut rd: R,
    notify: Arc<Notify>,
    src: String,
) where
    R: tokio::io::AsyncRead + Unpin,
{
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

            if process_segment(&state, id, &mut flood, &content, &src) {
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
    src: &str,
) -> bool {
    if seg.is_empty() {
        return false; // empty messages are silently ignored (RFC 2.3.1)
    }
    let text = String::from_utf8_lossy(seg);
    match proto::parse(&text) {
        None => false, // grammar violations: dropped silently
        Some(cmd) => route(state, id, flood, &cmd, src),
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
    src: &str,
) -> bool {
    if cmd.name.len() == 3 && cmd.name.chars().all(|c| c.is_ascii_digit()) {
        return false; // numeric replies from clients are dropped (RFC 2.4)
    }

    let quit = {
        let mut stg = state.lock().unwrap_or_else(|e| e.into_inner());

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

        // Flood control (RFC 8.10), tier 1: the per-connection burst window.
        // Excess over the burst is dropped silently.
        let now = Instant::now();
        let fw = flood_window();
        flood.push_back(now);
        while let Some(front) = flood.front() {
            if now.duration_since(*front) > fw {
                flood.pop_front();
            } else {
                break;
            }
        }
        if flood.len() > FLOOD_BURST {
            crate::log::flood("dropped");
            return false;
        }

        // Tier 2: the per-source aggregate budget. Without this, spreading
        // traffic across N connections multiplies the tier-1 allowance by N —
        // the limiter weakens in exact proportion to the abuse.
        {
            let stg_ref = &mut *stg;
            match stg_ref.sources.charge_message(&stg_ref.limits, src, now) {
                Ok(()) => {}
                Err(false) => {
                    crate::log::flood("dropped");
                    return false;
                }
                Err(true) => {
                    // Persistent offenders are closed rather than throttled
                    // forever, which is what clients expect from an ircd.
                    crate::log::flood("disconnected");
                    let line = proto::line("", "ERROR", ":Excess flood");
                    if let Some(u) = stg_ref.find_by_id(id) {
                        if u.tx.try_send(line).is_err() { crate::log::counted("output.dropped", ""); }
                    }
                    return true;
                }
            }
        }

        // Registration gate: everything but the pairing commands requires a
        // completed NICK/USER registration.
        let open = match cmd.name.as_str() {
            "NICK" | "USER" | "PASS" | "CAP" | "AUTHENTICATE" | "PING" | "PONG" => true,
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
        if u.tx.try_send(line).is_err() { crate::log::counted("output.dropped", ""); }
    }
}

/// Natural-closure path (EOF or socket death): when the session still holds an
/// identity in state, announce a quit message reflecting the event (RFC 8.7),
/// then remove it from every channel and nick table. Idempotent for clean
/// exits that already purged via QUIT/kill.
fn cleanup_on_eof(state: &Arc<Mutex<ServerState>>, id: usize) {
    let mut stg = state.lock().unwrap_or_else(|e| e.into_inner());
    match stg.find_by_id(id).map(|u| (u.registered, u.prefix())) {
        Some((true, pfx)) => {
            let line = proto::line(&pfx, "QUIT", ":Client connection lost");
            for mid in stg.channel_peers(id) {
                send_to(&stg, mid, &line); // only channel peers witness the quit
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
    real_host: String,
    tx: mpsc::Sender<String>,
    notify: Arc<Notify>,
) {
    let mut stg = state.lock().unwrap_or_else(|e| e.into_inner());
    if stg.find_by_id(id).is_some() {
        return; // already parked (should not happen); be harmless
    }
    stg.park_new(id, host, real_host, tx, notify);
}

/// Liveness polling (RFC 8.4): connections silent for too long receive a PING;
/// those that never answer are dropped with a quit message reflecting the event.
/// Liveness windows in seconds. Shipped defaults run ~30s ping / ~30s eviction
/// so a dead client is gone within roughly a minute; tests may shrink both via
/// environment overrides so reaping stays verifiable at test scale.
/// How long a connection may stay unregistered. Real clients complete the
/// NICK/USER pairing in milliseconds; this only ever catches abandoned or
/// deliberately idle sockets. Tunable for tests via CHONKLINE_REG_TIMEOUT_SECS.
fn registration_window() -> Duration {
    let secs: u64 = std::env::var("CHONKLINE_REG_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    Duration::from_secs(secs.max(1))
}

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
    let mut stg = state.lock().unwrap_or_else(|e| e.into_inner());

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
    let mut stg = state.lock().unwrap_or_else(|e| e.into_inner());

    // Expire unanswered pings first, then ping newly-silent connections.
    let now = Instant::now();

    // Registration deadline. Without this a connection that completes admission
    // and then sends nothing is never reaped: the liveness sweep below only
    // covers registered users, and TCP keepalive catches dead peers, not
    // deliberately idle ones. Such sockets hold an admission slot against the
    // global ceiling -- the bound that exists to stop memory exhaustion.
    let reg_deadline = registration_window();
    let expired_reg: Vec<usize> = stg
        .each_unreg()
        .filter(|u| now.duration_since(u.connected_at) > reg_deadline)
        .map(|u| u.id)
        .collect();
    for id in expired_reg {
        crate::log::counted("reg.timeout", "");
        announce_loss_and_evict(&mut stg, id, "Registration timeout");
    }
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
        if u.tx.try_send(line.to_string()).is_err() { crate::log::counted("output.dropped", ""); }
    }
}

/// Announce the departure of a connection (if still present in state) and remove it.
pub(crate) fn announce_loss_and_evict(stg: &mut ServerState, id: usize, reason: &str) {
    if let Some(pfx) = stg.find_by_id(id).map(|u| u.prefix()) {
        let line = proto::line(&pfx, "QUIT", &format!(":{}", reason));
        for mid in stg.channel_peers(id) {
            send_to(stg, mid, &line); // only channel peers witness the quit
        }
    }
    stg.eject_user(id);
    stg.drop_empty_channels();
    let _ = stg.evict(id);
}

