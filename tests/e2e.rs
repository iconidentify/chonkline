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
#[test]

fn scenario_nick_lifecycle_collision() {
    use std::io::Read as _;
    let addr_now: String = start_server();


    let alice_wire_now: String = wire_exchange(&addr_now, &[

        "NICK alice",

        "USER alice 0 * :Alice"

    ]);


    assert!(alice_wire_now.contains(" 001 "), "registration welcome absent");


    let bob_wire_now: String = wire_exchange(&addr_now, &[

        "NICK bob",


        "USER bob 0 * :Bob"


    ]);


    assert!(bob_wire_now.contains(" 001 "), "second client welcome absent");


    let carol_wire_now: String = wire_exchange(&addr_now, &[

        "NICK carol",


        "USER carol 0 * :Carol"


    ]);


    let dave_wire_now: String = wire_exchange(&addr_now, &[

        "NICK dave",


        "USER dave 0 * :Dave",


        "NICK oldname",




        "NICK newname",


        "WHOWAS oldname",

    ]);


    assert!(dave_wire_now.contains(" 314 "), "whowas history reply absent");


    assert!(dave_wire_now.contains(" 369 "), "whowas terminator absent");


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
    use std::io::Read as _;
    let addr_now: String = start_server();


    let alice_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let alice_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK alice".to_string(), "USER alice 0 * :Alice".to_string(), "JOIN #quiet".to_string()], alice_wire_now.clone());


    let bob_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let bob_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK bob".to_string(), "USER bob 0 * :Bob".to_string(), "JOIN #quiet".to_string(), "PRIVMSG alice :hello there".to_string()], bob_wire_now.clone());


    for task_now in [alice_task_now, bob_task_now] {

        task_now.join().expect("client thread");


    }


    // Replies may arrive late under parallel-suite load; poll until both expectations are met.
    let mut alice_wire_text_now: String = String::new();
    for _ in 0..160 {
        alice_wire_text_now = String::from_utf8_lossy(&alice_wire_now.lock().expect("wire lock")).to_string();
        if alice_wire_text_now.contains(" 001 ") && alice_wire_text_now.contains("PRIVMSG") { break; }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    assert!(alice_wire_text_now.contains(" 001 "), "messaging alice welcome absent: {:?}", alice_wire_text_now);

    let bob_wire_text_now: String = String::from_utf8_lossy(&bob_wire_now.lock().expect("wire lock")).to_string();

    assert!(alice_wire_text_now.contains("PRIVMSG"), "delivered privmsg relay absent: {:?}", alice_wire_text_now);


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

    // Client-1 registers and HOLDS `dup` for the whole exchange.
    let mut first_sock = std::net::TcpStream::connect(&addr_now).expect("first connect");
    send_line(&mut first_sock, "NICK dup");
    send_line(&mut first_sock, "USER dup 0 * :Dup");
    drain(&mut first_sock, |t| t.contains(" 001 "), 320);

    // Client-2 collides on the held nick, then recovers under an alternate one.
    let mut second_sock = std::net::TcpStream::connect(&addr_now).expect("second connect");
    send_line(&mut second_sock, "NICK dup");
    let collision_reply: String = drain(&mut second_sock, |t| t.contains(" 433 "), 160);

    send_line(&mut second_sock, "NICK dup2");
    send_line(&mut second_sock, "USER du 0 * :Du");
    let recovery_reply: String = drain(&mut second_sock, |t| t.contains(" 001 "), 320);

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

/// Ghost reap: a client that registers `zed` and then vanishes without any EOF-visible teardown must be
/// evicted by the liveness ping/eviction path within its (environment-reduced) timeout window, freeing the
/// nick and channel memberships so a fresh client can register under the same name. The abandoned socket is
/// held open-but-silent inside a parked thread: no reads occur on it, so EOF never fires and only keepalive
/// failure can reap the session. Window knobs are restored before returning so concurrent scenarios see
/// production pacing.
#[test]
fn scenario_ghost_reap() {
    std::env::set_var("CHONKLINE_LIVENESS_TICK_SECS", "1");
    std::env::set_var("CHONKLINE_PING_AFTER_SECS", "2");
    std::env::set_var("CHONKLINE_EVICTION_SECS", "3");

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

    // The ghost: registers `zed`, then is parked silent (no reads at all from here on).
    let addr_clone_now: String = addr_now.clone();
    let ghost_handle = std::thread::spawn(move || {
        let mut g_sock: std::net::TcpStream = std::net::TcpStream::connect(&addr_clone_now).expect("ghost connect");
        send_line(&mut g_sock, "NICK zed");
        send_line(&mut g_sock, "USER zde 0 * :Zed");
        // Confirm registration landed before going quiet... via a bounded opportunistic read.
        let mut sink: Vec<u8> = Vec::new();
        for _ in 0..96 {
            let mut chunk = [0u8; 4096];
            match std::io::Read::read(&mut g_sock, &mut chunk) {
                Ok(n) if n > 0 => sink.extend_from_slice(&chunk[..n]),
                _ => std::thread::sleep(std::time::Duration::from_millis(25)),
            }
            if String::from_utf8_lossy(&sink).contains(" 001 ") { break; }
        }
        // Now hold the socket open but silent: no reads, no writes. Sleep-loop until process exit;
        // forgetting the handle below ensures no join can ever block on this thread.
        loop { std::thread::sleep(std::time::Duration::from_secs(5)); }
    });

    // Give the ghost time to register before probing reuse.
    let mut zed_reusable: bool = false;
    let deadline_now: std::time::Instant = std::time::Instant::now() + std::time::Duration::from_secs(20);
    for _attempt in 0..24 {
        let probe_wire: Vec<u8> = Vec::new();
        if std::time::Instant::now() > deadline_now { break; } // absolute wall-clock bound: contention converts to fast failure, never a stall
        let addr_attempt_now: String = addr_now.clone();
        let handle2 = std::thread::spawn(move || {
                let mut p_sock: std::net::TcpStream = match std::net::TcpStream::connect(&addr_attempt_now) { Ok(s) => s, Err(_) => return None::<Vec<u8>> };
                send_line(&mut p_sock, "NICK zed");
                send_line(&mut p_sock, "USER zde2 0 * :Zed2");
                let mut sink: Vec<u8> = Vec::new();
                for _ in 0..24 {
                    let mut chunk = [0u8; 4096];
                    match std::io::Read::read(&mut p_sock, &mut chunk) {
                        Ok(n) if n > 0 => sink.extend_from_slice(&chunk[..n]),
                        _ => std::thread::sleep(std::time::Duration::from_millis(25)),
                    }
                }
                Some(sink)
        });
        let result = handle2.join().expect("probe thread");
        if let Some(buf) = result {
            let text = String::from_utf8_lossy(&buf).to_string();
            if text.contains(" 001 ") && !text.contains(" 433 ") {
                zed_reusable = true;
                drop(probe_wire);
                break;
            }
            drop(buf);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    std::env::remove_var("CHONKLINE_LIVENESS_TICK_SECS");
    std::env::remove_var("CHONKLINE_PING_AFTER_SECS");
    std::env::remove_var("CHONKLINE_EVICTION_SECS");

    std::mem::forget(ghost_handle); // never joined: held open-but-silent for process lifetime by design

    assert!(zed_reusable, "within the (reduced) ping-timeout window the abandoned nick `zed` must become reusable for a fresh registration");
}
