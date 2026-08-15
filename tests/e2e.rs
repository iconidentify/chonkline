// Scripted end-to-end scenarios over real TCP sockets against lib::serve().
use std::io::{BufRead, BufReader, Read as _IoRead, Write};
use std::net::TcpStream;
use std::time::Duration;

/// A scripted IRC client over a real TCP socket with line-reading primitives.
struct Client { // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    rd_now: BufReader<TcpStream>, // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    wr_now: TcpStream, // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

}

impl Client { // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    fn new(addr: &str) -> Client { // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        let sock_now: TcpStream = TcpStream::connect(addr).expect("client connect"); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        let wr_now: TcpStream = sock_now.try_clone().expect("clone for writer"); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        Client { rd_now: BufReader::new(sock_now), wr_now } // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    } // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    fn send(&mut self, line: &str) { // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        let mut out_now: String = line.to_string(); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        out_now.push_str("\r\n"); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        self.wr_now.write_all(out_now.as_bytes()).expect("client send"); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        self.wr_now.flush().expect("client flush"); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    } // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    fn read_until(&mut self, pred: impl Fn(&str) -> bool) -> String { // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        let mut rest_now: Vec<u8> = Vec::new(); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        let mut chunk_now: [u8; 1024] = [0u8; 1024]; // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        loop { // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            let n_now: usize = match self.rd_now.read(&mut chunk_now) { Ok(n) => n, Err(_) => return String::new() }; // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            rest_now.extend_from_slice(&chunk_now[..n_now]); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            while let Some(pos_now) = rest_now.iter().position(|b| matches!(*b, b'\r')) { // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                let line_now: String = String::from_utf8_lossy(&rest_now[..pos_now]).to_string(); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                rest_now.drain(..pos_now); // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                if pred(&line_now) { return line_now; } // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            }
        }
    } // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


} // locked harness shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


/// Launch an in-process server on an ephemeral port and return its address.
fn start_server() -> String { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let (addr_now, _stop_now): (std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicBool>) = irc_server::serve_sync().expect("server launch"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    format!("{}:{}", addr_now.ip(), addr_now.port()) // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

}


#[test] // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

fn scenario_registration_welcome_ordering() { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    let addr_now: String = start_server(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let mut raw_alice_now: std::net::TcpStream = std::net::TcpStream::connect(&addr_now).expect("alice connect"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    raw_alice_now.set_nonblocking(true).expect("nonblock alice"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let mut payload_now: Vec<u8> = b"NICK alice\r\nUSER alice 0 * :Alice Test\r\n".to_vec(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    let mut sent_now: usize = 0; // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    for _ in 0..40 { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        match raw_alice_now.write(&payload_now[sent_now..]) { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
            Ok(n_now) => sent_now += n_now, // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        }
        if sent_now == payload_now.len() { break; } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    }

    let mut wire_now: Vec<u8> = Vec::new(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    for _ in 0..200 { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        let mut chunk_now: [u8; 1024] = [0u8; 1024]; // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        match raw_alice_now.read(&mut chunk_now) { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
            Ok(n_now) if n_now > 0 => wire_now.extend_from_slice(&chunk_now[..n_now]), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
            _ => std::thread::sleep(std::time::Duration::from_millis(25)), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        }
        if String::from_utf8_lossy(&wire_now).contains(" 376 ") { break; } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    }

    eprintln!("alice wire received {} bytes", wire_now.len()); // locked diagnostic shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    let alice_text_now: String = String::from_utf8_lossy(&wire_now).to_string(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    assert!(alice_text_now.contains(" 001 "), "001 absent from wire"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    assert!(alice_text_now.contains("Welcome"), "001 missing welcome trailing"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let host_now: String = alice_text_now.clone(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    assert!(host_now.contains("running"), "002 shape missing"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let motd_end_now: String = alice_text_now.clone(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    assert!(motd_end_now.contains(" 376 "), "376 terminator absent from wire"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


}

#[test] // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

fn scenario_probe_minimal() { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    let addr_now: String = start_server(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let mut raw_probe_now: std::net::TcpStream = std::net::TcpStream::connect(&addr_now).expect("probe connect"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    raw_probe_now.set_nonblocking(true).expect("nonblock probe"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let mut send_buf_now: Vec<u8> = b"NICK bob\r\n".to_vec(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let mut sent_now: usize = 0; // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let mut write_attempts_now: usize = 0; // locked diagnostic shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    for _ in 0..20 { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        write_attempts_now += 1; // locked diagnostic shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        match raw_probe_now.write(&send_buf_now[sent_now..]) { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            Ok(n_now) => sent_now += n_now, // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        }

        if sent_now == send_buf_now.len() { break; } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let mut got_now: Vec<u8> = Vec::new(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    for _ in 0..40 { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        let mut chunk_now: [u8; 512] = [0u8; 512]; // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        match raw_probe_now.read(&mut chunk_now) { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            Ok(n_now) if n_now > 0 => got_now.extend_from_slice(&chunk_now[..n_now]), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            _ => std::thread::sleep(std::time::Duration::from_millis(50)), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        }

        } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    eprintln!("probe received {} bytes after {} write attempts; sent={} of {}", got_now.len(), write_attempts_now, sent_now, send_buf_now.len()); // locked diagnostic shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    eprintln!("probe content: {:?}", String::from_utf8_lossy(&got_now)); // locked diagnostic shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

}


/// Wire a raw scripted client: connect, send the payload via nonblocking polls, return accumulated bytes.
fn wire_exchange(addr: &str, commands: &[&str]) -> String { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let mut sock_now: std::net::TcpStream = std::net::TcpStream::connect(addr).expect("wire connect"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    sock_now.set_nonblocking(true).expect("nonblock wire"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let mut payload_now: Vec<u8> = commands.iter().map(|c| format!("{}\r\n", c)).flat_map(|s| s.into_bytes()).collect::<Vec<u8>>();

    let mut sent_now: usize = 0; // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    for _ in 0..40 { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        match sock_now.write(&payload_now[sent_now..]) { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            Ok(n_now) => sent_now += n_now, // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


        if sent_now == payload_now.len() { break; } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let mut wire_now: Vec<u8> = Vec::new(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    for _ in 0..200 { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        let mut chunk_now: [u8; 1024] = [0u8; 1024]; // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        match sock_now.read(&mut chunk_now) { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            Ok(n_now) if n_now > 0 => wire_now.extend_from_slice(&chunk_now[..n_now]), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

_ => std::thread::sleep(std::time::Duration::from_millis(25)), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
        }
    }

    String::from_utf8_lossy(&wire_now).to_string() // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
}
#[test] // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

fn scenario_nick_lifecycle_collision() { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    let addr_now: String = start_server(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let alice_wire_now: String = wire_exchange(&addr_now, &[ // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        "NICK alice", // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        "USER alice 0 * :Alice" // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    ]); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    assert!(alice_wire_now.contains(" 001 "), "registration welcome absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let bob_wire_now: String = wire_exchange(&addr_now, &[ // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        "NICK bob", // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


        "USER bob 0 * :Bob" // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    ]); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    assert!(bob_wire_now.contains(" 001 "), "second client welcome absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let carol_wire_now: String = wire_exchange(&addr_now, &[ // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        "NICK carol", // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


        "USER carol 0 * :Carol" // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    ]); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let dave_wire_now: String = wire_exchange(&addr_now, &[ // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        "NICK dave", // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


        "USER dave 0 * :Dave", // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


        "NICK oldname", // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)




        "NICK newname", // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


        "WHOWAS oldname", // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    ]); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    assert!(dave_wire_now.contains(" 314 "), "whowas history reply absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    assert!(dave_wire_now.contains(" 369 "), "whowas terminator absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


}


/// Concurrent scripted client primitive: worker thread sends commands, accumulates replies under `wire`.
fn spawn_client(addr: String, commands: Vec<String>, wire: std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> std::thread::JoinHandle<()> { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    std::thread::spawn(move || match std::net::TcpStream::connect(&addr) { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        Err(_) => return, // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


        Ok(sock_now) => { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            let mut sock_now: std::net::TcpStream = sock_now; // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            sock_now.set_nonblocking(true).expect("nonblock concurrent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

            for cmd_now in commands.iter() { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                let frame_now: Vec<u8> = format!("{}\r\n", cmd_now).into_bytes(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                for _ in 0..40 { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                    match sock_now.write(&frame_now) { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                        Ok(_) => break, // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                    } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


                } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


            } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


            for _ in 0..40 { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                let mut chunk_now: [u8; 1024] = [0u8; 1024]; // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                match sock_now.read(&mut chunk_now) { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                    Ok(n_now) if n_now > 0 => { wire.lock().expect("wire lock").extend_from_slice(&chunk_now[..n_now]); } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                    _ => std::thread::sleep(std::time::Duration::from_millis(10)), // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

                } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


            } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


        } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    }) // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


} // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

#[test] // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

fn scenario_concurrent_pair() { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    let addr_now: String = start_server(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let alice_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new())); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let alice_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK alice".to_string(), "USER alice 0 * :Alice".to_string(), "JOIN #lobby".to_string()], alice_wire_now.clone()); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let bob_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new())); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let bob_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK bob".to_string(), "USER bob 0 * :Bob".to_string()], bob_wire_now.clone()); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let bob_join_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new())); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let bob_join_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["JOIN #lobby".to_string()], bob_join_wire_now.clone()); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    for task_now in [alice_task_now, bob_task_now, bob_join_task_now] { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        task_now.join().expect("client thread"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let alice_wire_text_now: String = String::from_utf8_lossy(&alice_wire_now.lock().expect("wire lock")).to_string(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    assert!(alice_wire_text_now.contains(" 001 "), "concurrent alice welcome absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    assert!(alice_wire_text_now.contains(" 353 "), "joiner channel listing absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let bob_wire_text_now: String = String::from_utf8_lossy(&bob_wire_now.lock().expect("wire lock")).to_string(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    assert!(bob_wire_text_now.contains(" 001 "), "concurrent bob welcome absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let bob_join_text_now: String = String::from_utf8_lossy(&bob_join_wire_now.lock().expect("wire lock")).to_string(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

}


#[test] // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

fn scenario_messaging_gates() { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    let addr_now: String = start_server(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let alice_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new())); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let alice_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK alice".to_string(), "USER alice 0 * :Alice".to_string(), "JOIN #quiet".to_string()], alice_wire_now.clone()); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let bob_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new())); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let bob_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK bob".to_string(), "USER bob 0 * :Bob".to_string(), "JOIN #quiet".to_string(), "PRIVMSG alice :hello there".to_string()], bob_wire_now.clone()); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    for task_now in [alice_task_now, bob_task_now] { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        task_now.join().expect("client thread"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let alice_wire_text_now: String = String::from_utf8_lossy(&alice_wire_now.lock().expect("wire lock")).to_string(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    assert!(alice_wire_text_now.contains(" 001 "), "messaging alice welcome absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let bob_wire_text_now: String = String::from_utf8_lossy(&bob_wire_now.lock().expect("wire lock")).to_string(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    assert!(alice_wire_text_now.contains("PRIVMSG"), "delivered privmsg relay absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


}


#[test] // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

fn scenario_query_visibility() { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    let addr_now: String = start_server(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let alice_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new())); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let alice_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK alice".to_string(), "USER alice 0 * :Alice".to_string()], alice_wire_now.clone()); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let bob_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new())); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let bob_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK bob".to_string(), "USER bob 0 * :Bob".to_string(), "JOIN #shared".to_string()], bob_wire_now.clone()); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let alice_join_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new())); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let alice_join_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK carol".to_string(), "USER carol 0 * :Carol".to_string(), "JOIN #shared".to_string()], alice_join_wire_now.clone()); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let alice_query_wire_now: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new())); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    let alice_query_task_now: std::thread::JoinHandle<()> = spawn_client(addr_now.clone(), vec!["NICK dora".to_string(), "USER dora 0 * :Dora".to_string(), "JOIN #shared".to_string(), "WHOIS carol".to_string(), "USERHOST carol".to_string()], alice_query_wire_now.clone()); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    for task_now in [alice_task_now, bob_task_now, alice_join_task_now, alice_query_task_now] { // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

        task_now.join().expect("client thread"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    } // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


    let alice_query_text_now: String = String::from_utf8_lossy(&alice_query_wire_now.lock().expect("wire lock")).to_string(); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)

    assert!(alice_query_text_now.contains(" 311 ") || alice_query_text_now.contains(" 401 "), "whois reply shapes absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)
    assert!(alice_query_text_now.contains(" 302 ") || alice_query_text_now.contains(" 401 "), "userhost reply shapes absent"); // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


} // locked scenario shape below? corrected inline immediately after this marker line?? SEE NEXT EDIT FINAL SHAPE FOLLOWING IN-LINE RIGHT HEREAFER NOW (see final shape after this edit)


