// Scripted end-to-end scenarios over real TCP sockets against lib::serve().
use std::io::{BufRead, BufReader, Read as _IoRead, Write};
use std::net::TcpStream;
use std::time::Duration;

/// A scripted IRC client over a real TCP socket with line-reading primitives.
pub struct Client {

    pub rd_now: BufReader<TcpStream>,

    pub wr_now: TcpStream,

}

impl Client {
    pub fn new(addr: &str) -> Client {
        let sock_now: TcpStream = TcpStream::connect(addr).expect("client connect");

        let wr_now: TcpStream = sock_now.try_clone().expect("clone for writer");

        Client { rd_now: BufReader::new(sock_now), wr_now }

    }


    pub fn send(&mut self, line: &str) {
        let mut out_now: String = line.to_string();

        out_now.push_str("\r\n");

        self.wr_now.write_all(out_now.as_bytes()).expect("client send");

        self.wr_now.flush().expect("client flush");

    }


    pub fn read_until(&mut self, pred: impl Fn(&str) -> bool) -> String {
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
pub fn connect_timed(addr: &str) -> TcpStream {
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
pub fn accumulate(addr: &str, wire: std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> std::thread::JoinHandle<()> {
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
pub fn send_line(sock: &mut TcpStream, frame: &str) {
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
pub fn wait_for(wire: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>, needle: &str, overall_deadline_secs: u64) -> bool {
    let deadline_now = std::time::Instant::now() + Duration::from_secs(overall_deadline_secs);
    loop {
        if String::from_utf8_lossy(&wire.lock().expect("wire lock")).contains(needle) { return true; }
        if std::time::Instant::now() > deadline_now { return false; }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Bounded absence check: read/observe for a short quiet window and assert the needle never appeared.
pub fn assert_absent(wire: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>, needle: &str, quiet_window_secs: u64, label: &str) {
    let quiet_now = Duration::from_secs(quiet_window_secs);
    // Let any in-flight reply settle within the bounded window before judging absence.
    std::thread::sleep(Duration::from_millis((quiet_window_secs * 1000).max(400)));
    let text_now = String::from_utf8_lossy(&wire.lock().expect("wire lock")).to_string();
    assert!(!text_now.contains(needle), "{} must never arrive within the quiet window; traffic was:\n{}", label, text_now);
}

/// Send scripted commands across a short settle interval using bounded writes only.
pub fn script(sock: &mut TcpStream, cmds: &[&str]) {
    for cmd_now in cmds.iter() {
        send_line(sock, cmd_now);
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Launch an in-process server on an ephemeral port and return its address.
pub fn start_server() -> String {
    // Shrink the flood window (prod default 2s) so query-battery tests don't hold
    // multiple seconds per command. Safe under the serial harness (--test-threads=1);
    // every test sets the same value so there is no cross-test divergence.
    std::env::set_var("CHONKLINE_FLOOD_WINDOW_MS", "120");

    let (addr_now, _stop_now): (std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicBool>) = irc_server::serve_sync().expect("server launch");

    format!("{}:{}", addr_now.ip(), addr_now.port())

}


