mod common;
use common::*;
#[allow(unused_imports)]
use std::io::{Read, Write, BufRead};
#[allow(unused_imports)]
use std::net::TcpStream;
#[allow(unused_imports)]
use std::time::Duration;
#[allow(unused_imports)]
use std::sync::{Arc, Mutex};


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
