// The MOTD must carry the ASCII wordmark and describe the real services, so
// clients see accurate capability/registration guidance on connect.
mod common;
use common::start_server;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[test]
fn motd_describes_services_and_art() {
    let addr = start_server();
    let mut s = TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    s.write_all(b"NICK viewer\r\nUSER viewer 0 * :V\r\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = Vec::new();
    while Instant::now() < deadline {
        let mut c = [0u8; 4096];
        match s.read(&mut c) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&c[..n]),
            Err(_) => {}
        }
        if String::from_utf8_lossy(&buf).contains(" 376 ") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains(" 375 "), "RPL_MOTDSTART absent");
    assert!(text.contains(" 376 "), "RPL_ENDOFMOTD absent");
    // A fragment of the ASCII wordmark (art rendered with a clean left edge).
    assert!(text.contains("|___/") || text.contains("| (__|"), "MOTD art fragment absent");
    assert!(text.contains("NickServ REGISTER"), "MOTD missing NickServ guidance");
    assert!(text.contains("ChanServ REGISTER"), "MOTD missing ChanServ guidance");
    assert!(text.contains("SASL"), "MOTD missing capability summary");
}
