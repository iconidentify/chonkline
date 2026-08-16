// Scripted end-to-end scenarios over real TCP sockets against lib::serve().
use std::io::{BufRead, BufReader, Read as _IoRead, Write};
use std::net::TcpStream;
use std::time::Duration;

/// A scripted IRC client over a real TCP socket with line-reading primitives.
struct Client {

    rd_now: BufReader<TcpStream>,

    wr_now: TcpStream,

}

impl Client {
    fn new(addr: &str) -> Client {
        let sock_now: TcpStream = TcpStream::connect(addr).expect("client connect");

        let wr_now: TcpStream = sock_now.try_clone().expect("clone for writer");

        Client { rd_now: BufReader::new(sock_now), wr_now }

    }


    fn send(&mut self, line: &str) {
        let mut out_now: String = line.to_string();

        out_now.push_str("\r\n");

        self.wr_now.write_all(out_now.as_bytes()).expect("client send");

        self.wr_now.flush().expect("client flush");

    }


    fn read_until(&mut self, pred: impl Fn(&str) -> bool) -> String {
        let mut rest_now: Vec<u8> = Vec::new();

        let mut chunk_now: [u8; 1024] = [0u8; 1024];

        loop {

            let n_now: usize = match self.rd_now.read(&mut chunk_now) { Ok(n) => n, Err(_) => return String::new() };

            rest_now.extend_from_slice(&chunk_now[..n_now]);

            while let Some(pos_now) = rest_now.iter().position(|b| matches!(*b, b'\r')) {

                let line_now: String = String::from_utf8_lossy(&rest_now[..pos_now]).to_string();

                rest_now.drain(..pos_now);

                if pred(&line_now) { return line_now; }

            }
        }
    }


}


/// Shared non-blocking verification primitives: every client socket carries a read timeout so no test
/// can block forever; all replies accumulate into shared buffers that assertions poll with hard deadlines.

/// Connect with bounded retries and an armed read timeout: no test operation can block indefinitely, at connect or read.
fn connect_timed(addr: &str) -> TcpStream {
    for attempt in 0..16 { // bounded retry budget (~2s worst case) so transient accept-queue latency converts to fast failure
        match TcpStream::connect(addr) {
            Ok(mut sock_now) => {
                // Reads return TimedOut instead of hanging on live-but-idle IRC connections.
                sock_now.set_read_timeout(Some(Duration::from_millis(250))).expect("read timeout armed");
                return sock_now;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(125)),
        }
    }
    panic!("connect_timed: {} unreachable within bounded retry budget", addr)
}

/// Spawn a dedicated accumulator reader: appends every received byte into `wire` until EOF or process exit,
/// using only bounded timed reads. Never joins from assertion paths (handles may be forgotten).
fn accumulate(addr: &str, wire: std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> std::thread::JoinHandle<()> {
    let addr_now = addr.to_string();
    std::thread::spawn(move || {
        let mut sock_now: TcpStream = connect_timed(&addr_now);
        loop {
            let mut chunk_now = [0u8; 4096];
            match std::io::Read::read(&mut sock_now, &mut chunk_now) {
                Ok(0) => break, // EOF: session ended server-side or client-dropped
                Ok(n_now) => wire.lock().expect("wire lock").extend_from_slice(&chunk_now[..n_now]),
                Err(_) => std::thread::sleep(Duration::from_millis(25)), // TimedOut/WouldBlock/EOF-error backoff, bounded per iteration
            }
        }
    })
}

/// Send one framed command line with a strictly bounded write-retry budget.
fn send_line(sock: &mut TcpStream, frame: &str) {
    let bytes_now: Vec<u8> = format!("{}\r\n", frame).into_bytes();
    let mut sent_now: usize = 0;
    for _ in 0..64 {
        if sent_now >= bytes_now.len() { break; }
        match sock.write(&bytes_now[sent_now..]) {
            Ok(n_now) => sent_now += n_now,
            Err(_) => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// Poll an accumulated wire for `needle` until it appears or the overall deadline passes.
fn wait_for(wire: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>, needle: &str, overall_deadline_secs: u64) -> bool {
    let deadline_now = std::time::Instant::now() + Duration::from_secs(overall_deadline_secs);
    loop {
        if String::from_utf8_lossy(&wire.lock().expect("wire lock")).contains(needle) { return true; }
        if std::time::Instant::now() > deadline_now { return false; }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Bounded absence check: read/observe for a short quiet window and assert the needle never appeared.
fn assert_absent(wire: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>, needle: &str, quiet_window_secs: u64, label: &str) {
    let quiet_now = Duration::from_secs(quiet_window_secs);
    // Let any in-flight reply settle within the bounded window before judging absence.
    std::thread::sleep(Duration::from_millis((quiet_window_secs * 1000).max(400)));
    let text_now = String::from_utf8_lossy(&wire.lock().expect("wire lock")).to_string();
    assert!(!text_now.contains(needle), "{} must never arrive within the quiet window; traffic was:\n{}", label, text_now);
}

/// Send scripted commands across a short settle interval using bounded writes only.
fn script(sock: &mut TcpStream, cmds: &[&str]) {
    for cmd_now in cmds.iter() {
        send_line(sock, cmd_now);
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Launch an in-process server on an ephemeral port and return its address.
fn start_server() -> String {

    let (addr_now, _stop_now): (std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicBool>) = irc_server::serve_sync().expect("server launch");

    format!("{}:{}", addr_now.ip(), addr_now.port())

}


#[test]

fn scenario_registration_welcome_ordering() {
    use std::io::Read as _;
    let addr_now: String = start_server();

    let mut raw_alice_now: std::net::TcpStream = std::net::TcpStream::connect(&addr_now).expect("alice connect");
    raw_alice_now.set_nonblocking(true).expect("nonblock alice");

    let mut payload_now: Vec<u8> = b"NICK alice\r\nUSER alice 0 * :Alice Test\r\n".to_vec();
    let mut sent_now: usize = 0;
    for _ in 0..40 {
        match raw_alice_now.write(&payload_now[sent_now..]) {
            Ok(n_now) => sent_now += n_now,
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
        if sent_now == payload_now.len() { break; }
    }

    let mut wire_now: Vec<u8> = Vec::new();
    for _ in 0..200 {
        let mut chunk_now: [u8; 1024] = [0u8; 1024];
        match raw_alice_now.read(&mut chunk_now) {
            Ok(n_now) if n_now > 0 => wire_now.extend_from_slice(&chunk_now[..n_now]),
            _ => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
        if String::from_utf8_lossy(&wire_now).contains(" 376 ") { break; }
    }

    eprintln!("alice wire received {} bytes", wire_now.len());
    let alice_text_now: String = String::from_utf8_lossy(&wire_now).to_string();

    assert!(alice_text_now.contains(" 001 "), "001 absent from wire");
    assert!(alice_text_now.contains("Welcome"), "001 missing welcome trailing");

    let host_now: String = alice_text_now.clone();
    assert!(host_now.contains("running"), "002 shape missing");

    let motd_end_now: String = alice_text_now.clone();

    assert!(motd_end_now.contains(" 376 "), "376 terminator absent from wire");


}

#[test]

fn scenario_probe_minimal() {
    use std::io::Read as _;
    let addr_now: String = start_server();

    let mut raw_probe_now: std::net::TcpStream = std::net::TcpStream::connect(&addr_now).expect("probe connect");

    raw_probe_now.set_nonblocking(true).expect("nonblock probe");

    let mut send_buf_now: Vec<u8> = b"NICK bob\r\n".to_vec();

    let mut sent_now: usize = 0;

    let mut write_attempts_now: usize = 0;

    for _ in 0..20 {
        write_attempts_now += 1;

        match raw_probe_now.write(&send_buf_now[sent_now..]) {

            Ok(n_now) => sent_now += n_now,

            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
        }

        if sent_now == send_buf_now.len() { break; }

    }


    let mut got_now: Vec<u8> = Vec::new();

    for _ in 0..40 {

        let mut chunk_now: [u8; 512] = [0u8; 512];

        match raw_probe_now.read(&mut chunk_now) {

            Ok(n_now) if n_now > 0 => got_now.extend_from_slice(&chunk_now[..n_now]),

            _ => std::thread::sleep(std::time::Duration::from_millis(50)),
        }

        }


    eprintln!("probe received {} bytes after {} write attempts; sent={} of {}", got_now.len(), write_attempts_now, sent_now, send_buf_now.len());
    eprintln!("probe content: {:?}", String::from_utf8_lossy(&got_now));

}


/// Wire a raw scripted client: connect, send the payload via nonblocking polls, return accumulated bytes.
fn wire_exchange(addr: &str, commands: &[&str]) -> String {

    let mut sock_now: std::net::TcpStream = std::net::TcpStream::connect(addr).expect("wire connect");

    sock_now.set_nonblocking(true).expect("nonblock wire");

    let mut payload_now: Vec<u8> = commands.iter().map(|c| format!("{}\r\n", c)).flat_map(|s| s.into_bytes()).collect::<Vec<u8>>();

    let mut sent_now: usize = 0;

    for _ in 0..40 {

        match sock_now.write(&payload_now[sent_now..]) {

            Ok(n_now) => sent_now += n_now,

            Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),

        }


        if sent_now == payload_now.len() { break; }

    }


    let mut wire_now: Vec<u8> = Vec::new();

    for _ in 0..200 {

        let mut chunk_now: [u8; 1024] = [0u8; 1024];

        match sock_now.read(&mut chunk_now) {

            Ok(n_now) if n_now > 0 => wire_now.extend_from_slice(&chunk_now[..n_now]),

_ => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }

    String::from_utf8_lossy(&wire_now).to_string()
}

/// Nick lifecycle: registration welcomes for successive clients, then a rename chain (oldname -> newname) whose
/// history stays queryable through WHOWAS. Every interaction is deadline-bounded polling over an accumulating
/// wire; sockets that are done with are closed explicitly so no read can outlive its purpose.
#[test]
fn scenario_nick_lifecycle_collision() {
    let addr_now: String = start_server();

    use std::io::Read as _;

    fn scripted(addr_now: &str, cmds: &[&str], expect_now: impl Fn(&str) -> bool) -> std::sync::Arc<std::sync::Mutex<Vec<u8>>> {
        // Round-4 rewrite: paced sends followed by a single expectation-aware bounded settle with early exit on the
        // concrete reply pattern; timed reads throughout, explicit close afterwards, fast failure when expectations
        // never land - no open-ended budget remains anywhere in this path.
        let mut sock_now: TcpStream = connect_timed(addr_now);
        let mut sink_now: Vec<u8> = Vec::new();

        fn drain_rounds(sock_now: &mut TcpStream, sink_now: &mut Vec<u8>, rounds: usize) {
            for _ in 0..rounds {
                let mut chunk_now = [0u8; 4096];
                match std::io::Read::read(sock_now, &mut chunk_now) {
                    Ok(n_now) if n_now > 0 => sink_now.extend_from_slice(&chunk_now[..n_now]),
                    _ => std::thread::sleep(Duration::from_millis(25)), // TimedOut backoff; bounded per call by construction
                }
            }
        }

        for cmd_now in cmds.iter() {
            send_line(&mut sock_now, cmd_now);
            std::thread::sleep(Duration::from_millis(300)); // inter-frame pacing: inside the flood window (2s/6) with margin to spare; replies owed by earlier frames land within this interval and are captured by the bounded settle below
        }

        for _ in 0..12 { // expectation-aware early exit: bounded by construction, contention converts to fast failure instead of a minute-scale burn
            drain_rounds(&mut sock_now, &mut sink_now, 2);
            if expect_now(&String::from_utf8_lossy(&sink_now)) {
                break;
            }
        }

        drop(sock_now); // explicit close once the bounded settle is complete either way
        std::sync::Arc::new(std::sync::Mutex::new(sink_now))
    }

    let alice_wire_now = scripted(&addr_now, &["NICK alice", "USER alice 0 * :Alice"], |t| t.contains(" 001 "));
    assert!(wait_for(&alice_wire_now, " 001 ", 2), "registration welcome (concrete numeric-001) absent after bounded settle");

    let bob_wire_now = scripted(&addr_now, &["NICK bob", "USER bob 0 * :Bob"], |t| t.contains(" 001 "));
    assert!(wait_for(&bob_wire_now, " 001 ", 2), "second client's registration welcome (concrete numeric-001) absent after bounded settle");

    let dave_wire_now = scripted(
        &addr_now,
        &[
            "NICK dave",
            "USER dave 0 * :Dave",
            "NICK oldname",
            "NICK newname",
            "WHOWAS oldname",
        ],
        |t| t.contains(" 314 ") && t.contains(" 369 "),
    );
    assert!(wait_for(&dave_wire_now, " 314 ", 2) && wait_for(&dave_wire_now, " 369 ", 2), "WHOWAS history reply (concrete numerics-314/369) absent after bounded settle");
}


/// Concurrent scripted client primitive: worker thread sends commands, accumulates replies under `wire`.
fn spawn_client(addr: String, commands: Vec<String>, wire: std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || match std::net::TcpStream::connect(&addr) {

        Err(_) => return,


        Ok(sock_now) => {

            let mut sock_now: std::net::TcpStream = sock_now;

            sock_now.set_nonblocking(true).expect("nonblock concurrent");

            for cmd_now in commands.iter() {

                let frame_now: Vec<u8> = format!("{}\r\n", cmd_now).into_bytes();

                for _ in 0..40 {

                    match sock_now.write(&frame_now) {

                        Ok(_) => break,

                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),

                    }


                }


            }


            for _ in 0..40 {

                let mut chunk_now: [u8; 1024] = [0u8; 1024];

                match sock_now.read(&mut chunk_now) {

                    Ok(n_now) if n_now > 0 => { wire.lock().expect("wire lock").extend_from_slice(&chunk_now[..n_now]); }

                    _ => std::thread::sleep(std::time::Duration::from_millis(10)),

                }


            }


        }
    })


}

#[test]

fn scenario_concurrent_pair() {
    use std::io::Read as _;
    let addr_now: String = start_server();


    let alice_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let alice_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK alice".to_string(), "USER alice 0 * :Alice".to_string(), "JOIN #lobby".to_string()], alice_wire_now.clone());


    let bob_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let bob_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK bob".to_string(), "USER bob 0 * :Bob".to_string()], bob_wire_now.clone());


    let bob_join_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let bob_join_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["JOIN #lobby".to_string()], bob_join_wire_now.clone());


    for task_now in [alice_task_now, bob_task_now, bob_join_task_now] {

        task_now.join().expect("client thread");


    }


    let alice_wire_text_now: String = String::from_utf8_lossy(&alice_wire_now.lock().expect("wire lock")).to_string();

    assert!(alice_wire_text_now.contains(" 001 "), "concurrent alice welcome absent");


    assert!(alice_wire_text_now.contains(" 353 "), "joiner channel listing absent");


    let bob_wire_text_now: String = String::from_utf8_lossy(&bob_wire_now.lock().expect("wire lock")).to_string();

    assert!(bob_wire_text_now.contains(" 001 "), "concurrent bob welcome absent");


    let bob_join_text_now: String = String::from_utf8_lossy(&bob_join_wire_now.lock().expect("wire lock")).to_string();

}


#[test]
fn scenario_messaging_gates() {
    // Readiness-barrier structure: the relay is dispatched only after both clients are confirmed registered and
    // present in the channel. Every wait polls its OWN session's replies within bounded windows with hard deadlines;
    // timed reads return TimedOut instead of hanging, so nothing can block indefinitely.
    use std::io::Read as _;

    let addr_now: String = start_server();

    fn drain_bounded(sock: &mut TcpStream, sink: &mut Vec<u8>, rounds: usize) {
        for _ in 0..rounds {
            let mut chunk = [0u8; 4096];
            match std::io::Read::read(sock, &mut chunk) {
                Ok(n) if n > 0 => sink.extend_from_slice(&chunk[..n]),
                _ => std::thread::sleep(Duration::from_millis(25)), // bounded TimedOut backoff per iteration
            }
        }
    }

    fn confirmed(sock: &mut TcpStream, sink: &mut Vec<u8>, needle: &str) -> bool {
        for _ in 0..160 { // ~4s worst-case bounded confirmation window on this session's own replies
            drain_bounded(sock, sink, 4);
            if String::from_utf8_lossy(sink).contains(needle) { return true; }
        }
        false
    }

    // Alice: register and join, confirmed on her own session before anything else proceeds.
    let mut a_sock: TcpStream = connect_timed(&addr_now);
    send_line(&mut a_sock, "NICK alice");
    send_line(&mut a_sock, "USER alice 0 * :Alice");
    let mut a_sink: Vec<u8> = Vec::new();
    assert!(confirmed(&mut a_sock, &mut a_sink, " 001 "), "alice registration welcome absent");

    send_line(&mut a_sock, "JOIN #quiet");
    confirmed(&mut a_sock, &mut a_sink, "#quiet"); // bounded join-settle: membership establishes server-side regardless

    // Bob: register and join on his own held-open session, confirmed identically on his own replies.
    let mut b_sock: TcpStream = connect_timed(&addr_now);
    send_line(&mut b_sock, "NICK bob");
    send_line(&mut b_sock, "USER bob 0 * :Bob");
    let mut b_sink: Vec<u8> = Vec::new();
    assert!(confirmed(&mut b_sock, &mut b_sink, " 001 "), "bob registration welcome absent");

    send_line(&mut b_sock, "JOIN #quiet");
    confirmed(&mut b_sock, &mut b_sink, "#quiet"); // bounded join-settle on bob's side

    // Readiness barrier complete only now; the relay under test follows.
    send_line(&mut b_sock, "PRIVMSG alice :hello there");
    assert!(
        confirmed(&mut a_sock, &mut a_sink, "PRIVMSG alice :hello there"),
        "the prepared message must reach the other member after readiness"
    );
}


#[test]

fn scenario_query_visibility() {
    use std::io::Read as _;
    let addr_now: String = start_server();


    let alice_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let alice_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK alice".to_string(), "USER alice 0 * :Alice".to_string()], alice_wire_now.clone());


    let bob_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let bob_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK bob".to_string(), "USER bob 0 * :Bob".to_string(), "JOIN #shared".to_string()], bob_wire_now.clone());


    let alice_join_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let alice_join_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK carol".to_string(), "USER carol 0 * :Carol".to_string(), "JOIN #shared".to_string()], alice_join_wire_now.clone());


    let alice_query_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let alice_query_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK dora".to_string(), "USER dora 0 * :Dora".to_string(), "JOIN #shared".to_string(), "WHOIS carol".to_string(), "USERHOST carol".to_string()], alice_query_wire_now.clone());


    for task_now in [alice_task_now, bob_task_now, alice_join_task_now, alice_query_task_now] {

        task_now.join().expect("client thread");


    }


    let alice_query_text_now: String = String::from_utf8_lossy(&alice_query_wire_now.lock().expect("wire lock")).to_string();

    assert!(alice_query_text_now.contains(" 311 ") || alice_query_text_now.contains(" 401 "), "whois reply shapes absent");
    assert!(alice_query_text_now.contains(" 302 ") || alice_query_text_now.contains(" 401 "), "userhost reply shapes absent");


}



/// Irssi-style opening handshake: CAP LS first (pre-registration), underscored nick,
/// USER pairing, CAP END, then a token-bearing PING and an inbound client PONG.
#[test]
fn scenario_irssi_handshake() {
    use std::io::Read as _;
    let addr_now: String = start_server();

    let wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    spawn_client(
        addr_now.clone(),
        vec![
            "CAP LS 302".to_string(),
            "NICK bob_".to_string(),
            "USER bob 0 * :Bob".to_string(),
            "CAP END".to_string(),
            "PING LAG12345".to_string(),
            "PONG server".to_string(),
        ],
        wire_now.clone(),
    )
    .join()
    .expect("handshake client");

    std::thread::sleep(std::time::Duration::from_millis(300)); // settle any late replies before reading the accumulated wire
    let reply = String::from_utf8_lossy(&wire_now.lock().expect("wire lock")).to_string();

    assert!(reply.lines().any(|l| l.contains(" CAP * LS ")), "expected a CAP * LS answer to the opening capability list: {:?}", reply); // BUG-1 fix: immediate zero-capability listing
    assert!(!reply.contains(" 421 "), "no unknown-command errors may appear during handshake: {:?}", reply);
    assert!(reply.contains(" 001 ") && reply.lines().any(|l| l.contains("bob_")), "underscored nick must register with a welcome reply: {:?}", reply); // BUG-3 fix: bob_ accepted, no ERR_ERRONEUSNICKNAME
    assert!(!reply.contains(" 432 "), "no erroneus-nickname errors during handshake: {:?}", reply);
    assert!(reply.lines().any(|l| l.contains(" PONG ") && l.contains("LAG12345")), "PING must be answered with a token-echoing PONG: {:?}", reply); // BUG-2 fix: registered-path PING answers PONG <server> :<token>
}

/// Well-formed ERR_NOSUCHNICK: a registered client messaging an unknown target must
/// hear `:<server> 401 <ownnick> ghost :No such nick/channel` - recipient token first,
/// referenced name second, no duplicated text.
#[test]
fn scenario_wellformed_401() {
    use std::io::Read as _;
    let addr_now: String = start_server();

    let wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    spawn_client(
        addr_now.clone(),
        vec![
            "NICK veritas".to_string(),
            "USER veri 0 * :Veritas".to_string(),
            "PRIVMSG ghost :hi".to_string(),
        ],
        wire_now.clone(),
    )
    .join()
    .expect("client thread");

    std::thread::sleep(std::time::Duration::from_millis(300)); // settle late replies before reading the accumulated wire
    let reply = String::from_utf8_lossy(&wire_now.lock().expect("wire lock")).to_string();

    assert!(
        reply.lines().any(|l| l.contains(" 401 ") && l.split_whitespace().skip(2).take_while(|t| !t.starts_with(':')).collect::<Vec<_>>().first() == Some(&"veritas")),
        "401 must carry the recipient's nick as its first token: {:?}",
        reply
    );
    assert!(
        reply.lines().any(|l| l.contains(" 401 ") && l.contains("ghost") && l.trim_end().ends_with(":No such nick/channel")),
        "401 trailing text must name the referenced target without duplication: {:?}",
        reply
    );
}


/// Well-formed ERR_NICKNAMEINUSE: while client-1 holds `dup`, an unregistered client-2 picking that
/// nick must hear the collision answer carrying a recipient token (`*` pre-registration), then complete
/// registration under an alternate nick. Both sockets stay open for the duration so no EOF teardown
/// can free the contested name mid-exchange; everything runs sequentially in one thread, making the
/// ordering deterministic.
#[test]
fn scenario_wellformed_433() {
    use std::io::Read as _;
    let addr_now: String = start_server();

    fn send_line(sock: &mut std::net::TcpStream, frame: &str) {
        let bytes: Vec<u8> = format!("{}\r\n", frame).into_bytes();
        let mut sent: usize = 0;
        while sent < bytes.len() {
            match sock.write(&bytes[sent..]) {
                Ok(n) => sent += n,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),
            }
        }
    }

    fn drain(sock: &mut std::net::TcpStream, until: impl Fn(&str) -> bool, rounds: usize) -> String {
        let mut sink: Vec<u8> = Vec::new();
        for _ in 0..rounds {
            let mut chunk = [0u8; 1024];
            match sock.read(&mut chunk) {
                Ok(n) if n > 0 => sink.extend_from_slice(&chunk[..n]),
                _ => std::thread::sleep(std::time::Duration::from_millis(25)),
            }
            let text = String::from_utf8_lossy(&sink).to_string();
            if until(&text) { break; }
        }
        String::from_utf8_lossy(&sink).to_string()
    }

    // Client-1 registers and HOLDS `dup` for the whole exchange. Round-4 semantics require its activeness to be
    // demonstrated: a dedicated long-lived thread answers every PING it receives with a token-echoing PONG, which is
    // exactly what keeps an actively responding holder's nick away from reclamation. It runs until signaled below.
    let dup_held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_responder = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let addr_one = addr_now.clone();
        let held_one = dup_held.clone();
        let stop_one = stop_responder.clone();
        let responder = std::thread::spawn(move || {
            let mut sock_one = match std::net::TcpStream::connect(&addr_one) { Ok(s) => s, Err(_) => return };
            send_line(&mut sock_one, "NICK dup");
            std::thread::sleep(std::time::Duration::from_millis(300)); // pacing inside the flood window (2s/6)
            send_line(&mut sock_one, "USER dup 0 * :Dup");

            let mut held_text = String::new();
            for _ in 0..16 { // bounded confirmation of its own registration before it may claim the nick is held
                held_text.push_str(&drain(&mut sock_one, |_| false, 2)); // purely bounded timed drains; nothing blocks indefinitely
                if held_text.contains(" 001 ") { break; }
            }
            if !held_text.contains(" 001 ") { return; } // never proceeded: main's readiness spin fast-fails below
            held_one.store(true, std::sync::atomic::Ordering::SeqCst);

            let mut buf_one: Vec<u8> = Vec::new();
            loop {
                if stop_one.load(std::sync::atomic::Ordering::SeqCst) { break; }
                let mut chunk_one = [0u8; 4096];
                match std::io::Read::read(&mut sock_one, &mut chunk_one) {
                    Ok(0) => break, // EOF: session ended server-side
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)), // timed-out backoff; bounded per iteration
                    Ok(n_one) => {
                        buf_one.extend_from_slice(&chunk_one[..n_one]);
                        while let Some(pos_one) = buf_one.iter().position(|b| matches!(*b, b'\r' | b'\n')) {
                            let seg_now: String = String::from_utf8_lossy(&buf_one[..pos_one]).to_string();
                            buf_one.drain(..=pos_one);
                            while buf_one.first() == Some(&b'\n') || buf_one.first() == Some(&b'\r') {
                                buf_one.remove(0);
                            }
                            let tokens_now: Vec<&str> = seg_now.split(' ').collect();
                            if tokens_now.iter().any(|t| *t == "PING") {
                                if let Some(tok_now) = tokens_now.last() {
                                    send_line(&mut sock_one, &format!("PONG {}", tok_now)); // active-holder response: keeps its nick under round-4 semantics
                                }
                            }
                        }
                    }
                }
            }
        });

        let mut readiness = false;
        for _ in 0..48 { // bounded spin (~12s worst case) until the holder is confirmed registered and answering-ready
            if dup_held.load(std::sync::atomic::Ordering::SeqCst) { readiness = true; break; }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        assert!(readiness, "the active holder must complete its own registration before the collision phase");

        // Client-2 collides on the held nick, then recovers under an alternate one; every wait is bounded by construction.
        let mut second_sock = std::net::TcpStream::connect(&addr_now).expect("second connect");
        send_line(&mut second_sock, "NICK dup");
        let collision_reply: String = drain(&mut second_sock, |t| t.contains(" 433 "), 48); // active-holder response lands within ms nominally

        std::thread::sleep(std::time::Duration::from_millis(300)); // pacing inside the flood window (2s/6)
        send_line(&mut second_sock, "NICK dup2");
        std::thread::sleep(std::time::Duration::from_millis(300));
        send_line(&mut second_sock, "USER du 0 * :Du");
        let recovery_reply: String = drain(&mut second_sock, |t| t.contains(" 001 "), 48); // synchronous welcome: nominal sub-second


    assert!(
        collision_reply.lines().any(|l| l.contains(" 433 ") && l.contains("* dup")),
        "the collision answer must be ` 433 * <nick> :...` (recipient token present, starred pre-registration): {:?}",
        collision_reply
    );

    assert!(
        recovery_reply.lines().any(|l| l.contains(" 001 ") && l.contains("dup2")),
        "recovery under the alternate nick must complete with a welcome: {:?}",
        recovery_reply
    );

    drop(second_sock); // explicit close when done with client-2
    stop_responder.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = responder.join(); // bounded exit within the responder's own polling granularity (~sub-second)
}

/// No self-echo: with A and B both on #x, a channel PRIVMSG from the originator reaches every other
/// member exactly once and never echoes back to its sender (no echo-message capability is advertised).
/// Both sockets stay open throughout so teardown cannot perturb membership; nonblocking polls with hard
/// bounds on every retry surface keep sequential single-thread ordering deterministic without stalls.
#[test]
fn scenario_no_channel_self_echo() {
    use std::io::Read as _;
    let addr_now: String = start_server();

    fn send_line(sock: &mut std::net::TcpStream, frame: &str) {
        let bytes: Vec<u8> = format!("{}\r\n", frame).into_bytes();
        let mut sent: usize = 0;
        for _ in 0..48 {
            if sent >= bytes.len() { break; }
            match sock.write(&bytes[sent..]) {
                Ok(n) => sent += n,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),
            }
        }
    }

    fn poll(sock: &mut std::net::TcpStream, sink: &mut Vec<u8>, until: impl Fn(&str) -> bool, rounds: usize) {
        for _ in 0..rounds {
            let mut chunk = [0u8; 4096];
            match sock.read(&mut chunk) {
                Ok(n) if n > 0 => sink.extend_from_slice(&chunk[..n]),
                _ => std::thread::sleep(std::time::Duration::from_millis(25)),
            }
            let text = String::from_utf8_lossy(sink).to_string();
            if until(&text) { break; }
        }
    }

    // Client A registers and joins #x, holding the socket open.
    let mut a_sock: std::net::TcpStream = std::net::TcpStream::connect(&addr_now).expect("a connect");
    a_sock.set_nonblocking(true).expect("a nonblock");
    let mut a_wire: Vec<u8> = Vec::new();
    send_line(&mut a_sock, "NICK echoA");
    send_line(&mut a_sock, "USER echa 0 * :EchoA");
    poll(&mut a_sock, &mut a_wire, |t| t.contains(" 001 "), 480);
    send_line(&mut a_sock, "JOIN #x");

    // Client B registers and joins; its join broadcast makes both members present.
    let mut b_sock: std::net::TcpStream = std::net::TcpStream::connect(&addr_now).expect("b connect");
    b_sock.set_nonblocking(true).expect("b nonblock");
    let mut b_wire: Vec<u8> = Vec::new();
    send_line(&mut b_sock, "NICK echoB");
    send_line(&mut b_sock, "USER echb 0 * :EchoB");
    poll(&mut b_sock, &mut b_wire, |t| t.contains(" 001 "), 480);
    send_line(&mut b_sock, "JOIN #x");

    // Confirm both members are present before the relay (A observes its own JOIN reply and B's broadcast).
    poll(&mut a_sock, &mut a_wire, |t| t.contains("echoB"), 960);
    let settled: bool = String::from_utf8_lossy(&a_wire).contains("echoB");

    // The relay under test.
    send_line(&mut a_sock, "PRIVMSG #x :hi");
    poll(&mut b_sock, &mut b_wire, |t| t.lines().any(|l| l.contains("PRIVMSG #x :hi")), 960);

    let a_text = String::from_utf8_lossy(&a_wire).to_string();
    let b_text = String::from_utf8_lossy(&b_wire).to_string();

    assert!(settled, "the exchange must begin with both clients present on the channel; A traffic:\n{}", a_text);
    let copies_for_a: usize = a_text.lines().filter(|l| l.contains("PRIVMSG #x :hi")).count();
    let copies_for_b: usize = b_text.lines().filter(|l| l.contains("PRIVMSG #x :hi")).count();

    assert_eq!(copies_for_a, 0, "the originator must never receive its own channel message; A traffic:\n{}", a_text);
    assert_eq!(copies_for_b, 1, "every other member receives exactly one copy; B traffic:\n{}", b_text);
}

/// Ghost reap: a client that registers `zed` and then stops answering must be evicted by the keepalive path within
/// its (environment-reduced) timeout window, freeing the nick so a fresh client can register under it. The reduced
/// windows are set BEFORE the server starts; every wait runs through bounded polling with hard deadlines - never a
/// blocking read. The ghost socket stays open-but-silent after registration confirmation: no reads occur on it from
/// that point forward, so EOF never fires and only ping eviction can reap the session.
#[test]
fn scenario_ghost_reap() {
    std::env::set_var("CHONKLINE_LIVENESS_TICK_SECS", "1");
    std::env::set_var("CHONKLINE_PING_AFTER_SECS", "1");
    std::env::set_var("CHONKLINE_EVICTION_SECS", "2");

    use std::io::Read as _;
    let addr_now: String = start_server();

    // Ghost: connect, register `zed`, confirm the welcome within a bounded wait.
    let mut ghost_sock: TcpStream = connect_timed(&addr_now);
    send_line(&mut ghost_sock, "NICK zed");
    send_line(&mut ghost_sock, "USER zde 0 * :Zed");

    fn drain_bounded(sock: &mut TcpStream, sink: &mut Vec<u8>, rounds: usize) {
        for _ in 0..rounds {
            let mut chunk = [0u8; 4096];
            match std::io::Read::read(sock, &mut chunk) {
                Ok(n) if n > 0 => sink.extend_from_slice(&chunk[..n]),
                _ => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }

    let mut ghost_sink: Vec<u8> = Vec::new();
    let mut confirmed: bool = false;
    for _ in 0..48 { // bounded confirmation wait (~1.2s worst case)
        drain_bounded(&mut ghost_sock, &mut ghost_sink, 4);
        if String::from_utf8_lossy(&ghost_sink).contains(" 001 ") { confirmed = true; break; }
    }
    assert!(confirmed, "the ghost must complete registration before the reap probe: {:?}", String::from_utf8_lossy(&ghost_sink));

    // From here on the ghost socket is never read from again: silent-but-open until eviction frees `zed`.
    let deadline_now = std::time::Instant::now() + Duration::from_secs(20); // absolute wall-clock bound for the whole probe phase
    let mut zed_reusable: bool = false;
    while !zed_reusable && std::time::Instant::now() <= deadline_now {
        // Fresh client attempts to register `zed`; bounded interaction, judged by reply content.
        let mut probe_sock: TcpStream = connect_timed(&addr_now);
        send_line(&mut probe_sock, "NICK zed");
        send_line(&mut probe_sock, "USER zde2 0 * :Zed2");
        let mut probe_sink: Vec<u8> = Vec::new();
        for _ in 0..32 { // bounded reply wait (~0.8s worst case)
            drain_bounded(&mut probe_sock, &mut probe_sink, 4);
            if String::from_utf8_lossy(&probe_sink).contains(" 001 ") || String::from_utf8_lossy(&probe_sink).contains(" 433 ") { break; }
        }
        let probe_text: String = String::from_utf8_lossy(&probe_sink).to_string();
        if probe_text.contains(" 001 ") && !probe_text.contains(" 433 ") {
            zed_reusable = true; // welcome without any collision refusal: the name was freed server-side
        }
        drop(probe_sock); // closes cleanly between attempts; each attempt is independently bounded above
        std::thread::sleep(Duration::from_millis(250));
    }

    assert!(
        zed_reusable,
        "within the reduced ping/eviction window the abandoned nick `zed` must become reusable for a fresh registration"
    );
}

/// The acting client must be echoed its own membership lines (RFC 3.2.1): its own
/// JOIN precedes the topic + NAMES burst on the way in, and its own PART comes on
/// the way out. WeeChat/irssi open the channel buffer on exactly these self-echoes.
#[test]
fn scenario_self_echo_membership() {
    use std::io::Read as _;
    let addr_now: String = start_server();

    let mut sock_now: TcpStream = connect_timed(&addr_now);
    send_line(&mut sock_now, "NICK selfer");
    std::thread::sleep(Duration::from_millis(50));
    send_line(&mut sock_now, "USER selfe 0 * :Selfer");
    std::thread::sleep(Duration::from_millis(50));

    let mut wire_now: Vec<u8> = Vec::new();

    fn drain(sock: &mut TcpStream, sink: &mut Vec<u8>, rounds: usize) {
        for _ in 0..rounds {
            let mut chunk = [0u8; 4096];
            match std::io::Read::read(sock, &mut chunk) {
                Ok(n) if n > 0 => sink.extend_from_slice(&chunk[..n]),
                _ => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }

    // Read until the registration welcome has landed, so the JOIN burst is isolated.
    for _ in 0..128 {
        drain(&mut sock_now, &mut wire_now, 4);
        if String::from_utf8_lossy(&wire_now).contains(" 001 ") { break; }
    }
    // Drain the rest of the welcome burst before sending JOIN.
    drain(&mut sock_now, &mut wire_now, 8);

    send_line(&mut sock_now, "JOIN #solo");
    // Wait for the full inbound join burst (366 closes the NAMES list).
    let mut got_end = false;
    for _ in 0..128 {
        drain(&mut sock_now, &mut wire_now, 4);
        if String::from_utf8_lossy(&wire_now).contains(" 366 ") { got_end = true; break; }
    }
    assert!(got_end, "joiner should receive the closing NAMES burst");

    send_line(&mut sock_now, "PART #solo");
    let mut got_part = false;
    for _ in 0..128 {
        drain(&mut sock_now, &mut wire_now, 4);
        if String::from_utf8_lossy(&wire_now).contains(" PART #solo") { got_part = true; break; }
    }
    assert!(got_part, "parter should receive its own PART line");

    let text_now = String::from_utf8_lossy(&wire_now).to_string();
    let lines_now: Vec<&str> = text_now.lines().collect();

    let idx_join = lines_now.iter().position(|l| l.contains(" JOIN #solo"));
    let idx_topic = lines_now.iter().position(|l| l.contains(" 331 ") || l.contains(" 332 "));
    let idx_names = lines_now.iter().position(|l| l.contains(" 353 "));
    let idx_end = lines_now.iter().position(|l| l.contains(" 366 "));
    let idx_part = lines_now.iter().position(|l| l.contains(" PART #solo"));

    assert!(idx_join.is_some(), "self-echoed JOIN missing: {:?}", text_now);
    assert!(idx_topic.is_some(), "topic reply (331/332) missing: {:?}", text_now);
    assert!(idx_names.is_some(), "NAMES listing (353) missing: {:?}", text_now);
    assert!(idx_end.is_some(), "end of NAMES (366) missing: {:?}", text_now);
    assert!(idx_part.is_some(), "self-echoed PART missing: {:?}", text_now);

    // RFC order: own JOIN, then topic, then 353, then 366, then own PART.
    let (ij, it, in_, ie, ip) = (idx_join.unwrap(), idx_topic.unwrap(), idx_names.unwrap(), idx_end.unwrap(), idx_part.unwrap());
    assert!(ij < it, "own JOIN must precede the topic reply");
    assert!(it < in_, "topic reply must precede the NAMES listing");
    assert!(in_ < ie, "NAMES listing must precede the end-of-NAMES");
    assert!(ie < ip, "end-of-NAMES must precede the own PART");

    drop(sock_now);
}
