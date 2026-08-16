// End-to-end coverage for the accounts / SASL / IRCv3 / host-cloaking features,
// driven over real TCP sockets against lib::serve().
mod common;
use common::start_server;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use irc_server::crypto::base64_encode;

fn client(addr: &str) -> TcpStream {
    let s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    s
}

/// Send one command, paced to stay under the test flood window (6 / 120ms).
fn send(s: &mut TcpStream, line: &str) {
    s.write_all(line.as_bytes()).unwrap();
    s.write_all(b"\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(35));
}

/// Accumulate everything received until `needle` appears or the deadline passes.
fn drain_until(s: &mut TcpStream, needle: &str, secs: u64) -> String {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut buf: Vec<u8> = Vec::new();
    while Instant::now() < deadline {
        let mut chunk = [0u8; 4096];
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if String::from_utf8_lossy(&buf).contains(needle) {
                    break;
                }
            }
            Err(_) => {} // read timeout: keep waiting until the deadline
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn register(s: &mut TcpStream, nick: &str) {
    send(s, &format!("NICK {}", nick));
    send(s, &format!("USER {} 0 * :{} test", nick, nick));
    let _ = drain_until(s, " 001 ", 3);
}

#[test]
fn cap_ls_advertises_supported_caps() {
    let addr = start_server();
    let mut c = client(&addr);
    send(&mut c, "CAP LS 302");
    let ls = drain_until(&mut c, "LS :", 3);
    for cap in ["sasl", "server-time", "away-notify", "extended-join", "account-notify", "multi-prefix"] {
        assert!(ls.contains(cap), "CAP LS missing {cap}: {ls:?}");
    }
    assert!(ls.contains("sasl=PLAIN"), "CAP LS 302 should carry sasl=PLAIN: {ls:?}");
}

#[test]
fn nickserv_register_then_sasl_login() {
    let addr = start_server();

    // First connection registers the account "alice".
    let mut a = client(&addr);
    register(&mut a, "alice");
    send(&mut a, "PRIVMSG NickServ :REGISTER hunter2");
    let reg = drain_until(&mut a, "registered", 3);
    assert!(reg.contains("NickServ") && reg.contains("registered"), "register NOTICE absent: {reg:?}");

    // Second connection logs in with SASL PLAIN before completing registration.
    let mut b = client(&addr);
    send(&mut b, "CAP LS 302");
    let _ = drain_until(&mut b, "LS :", 3);
    send(&mut b, "CAP REQ :sasl");
    let ack = drain_until(&mut b, "ACK", 3);
    assert!(ack.contains("ACK") && ack.contains("sasl"), "CAP REQ not ACKed: {ack:?}");
    send(&mut b, "AUTHENTICATE PLAIN");
    let plus = drain_until(&mut b, "AUTHENTICATE +", 3);
    assert!(plus.contains("AUTHENTICATE +"), "server did not prompt for PLAIN payload: {plus:?}");
    // PLAIN payload = authzid \0 authcid \0 passwd
    let payload = base64_encode(b"\0alice\0hunter2");
    send(&mut b, &format!("AUTHENTICATE {}", payload));
    let done = drain_until(&mut b, " 903 ", 3);
    assert!(done.contains(" 900 "), "RPL_LOGGEDIN (900) absent: {done:?}");
    assert!(done.contains(" 903 "), "RPL_SASLSUCCESS (903) absent: {done:?}");
    assert!(done.contains("alice"), "900 should name the account: {done:?}");

    // Registration completes after CAP END.
    send(&mut b, "CAP END");
    send(&mut b, "NICK bob");
    send(&mut b, "USER bob 0 * :Bob");
    let welcome = drain_until(&mut b, " 001 ", 3);
    assert!(welcome.contains(" 001 "), "welcome withheld after SASL+CAP END: {welcome:?}");
}

#[test]
fn sasl_wrong_password_fails() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "carol");
    send(&mut a, "PRIVMSG NickServ :REGISTER rightpass");
    let _ = drain_until(&mut a, "registered", 3);

    let mut b = client(&addr);
    send(&mut b, "CAP REQ :sasl");
    let _ = drain_until(&mut b, "ACK", 3);
    send(&mut b, "AUTHENTICATE PLAIN");
    let _ = drain_until(&mut b, "AUTHENTICATE +", 3);
    send(&mut b, &format!("AUTHENTICATE {}", base64_encode(b"\0carol\0wrongpass")));
    let fail = drain_until(&mut b, " 904 ", 3);
    assert!(fail.contains(" 904 "), "wrong password should yield 904: {fail:?}");
}

#[test]
fn host_is_cloaked_not_raw_ip() {
    let addr = start_server();
    let mut c = client(&addr);
    register(&mut c, "dave");
    send(&mut c, "USERHOST dave");
    let uh = drain_until(&mut c, " 302 ", 3);
    let line = uh.lines().find(|l| l.contains(" 302 ")).expect("no 302");
    let trailing = line.splitn(2, " :").nth(1).unwrap_or("");
    assert!(!trailing.contains("127.0.0.1"), "raw IP leaked in USERHOST: {trailing:?}");
    assert!(trailing.contains('@'), "USERHOST must carry user@host: {trailing:?}");
    // default cloak suffix
    assert!(trailing.contains("chonkbase.net"), "cloak suffix absent: {trailing:?}");
}

#[test]
fn server_time_tag_on_channel_message() {
    let addr = start_server();

    // amy negotiates server-time, then joins.
    let mut amy = client(&addr);
    send(&mut amy, "CAP REQ :server-time");
    let _ = drain_until(&mut amy, "ACK", 3);
    send(&mut amy, "CAP END");
    register(&mut amy, "amy");
    send(&mut amy, "JOIN #clock");
    let _ = drain_until(&mut amy, "JOIN", 3);

    // ben joins and speaks.
    let mut ben = client(&addr);
    register(&mut ben, "ben");
    send(&mut ben, "JOIN #clock");
    let _ = drain_until(&mut ben, "JOIN", 3);
    send(&mut ben, "PRIVMSG #clock :hello there");

    let got = drain_until(&mut amy, "hello there", 3);
    let msg = got.lines().find(|l| l.contains("PRIVMSG") && l.contains("hello there")).expect("no msg");
    assert!(msg.starts_with("@time="), "server-time tag missing on relayed message: {msg:?}");
    assert!(msg.contains("T") && msg.contains("Z"), "timestamp not ISO-8601: {msg:?}");
}

#[test]
fn notice_and_ctcp_relay_between_users() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "nota");
    let mut b = client(&addr);
    register(&mut b, "notb");

    // NOTICE user->user must be delivered (regression: NOTICE was dropped).
    send(&mut a, "NOTICE notb :heads up");
    let n = drain_until(&mut b, "heads up", 3);
    assert!(n.contains("NOTICE notb :heads up"), "user NOTICE not delivered: {n:?}");

    // CTCP request (PRIVMSG) and reply (NOTICE) must pass \x01 bytes through intact.
    send(&mut a, "PRIVMSG notb :\u{1}VERSION\u{1}");
    let req = drain_until(&mut b, "VERSION", 3);
    assert!(req.contains("\u{1}VERSION\u{1}"), "CTCP request not relayed intact: {req:?}");
    send(&mut b, "NOTICE nota :\u{1}VERSION chonkline\u{1}");
    let rep = drain_until(&mut a, "VERSION", 3);
    assert!(rep.contains("\u{1}VERSION chonkline\u{1}"), "CTCP reply (NOTICE) not relayed: {rep:?}");
}

#[test]
fn mode_op_broadcast_has_flag_and_target() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "opper");
    send(&mut a, "JOIN #ops");
    let _ = drain_until(&mut a, "JOIN", 3);

    let mut b = client(&addr);
    register(&mut b, "victim");
    send(&mut b, "JOIN #ops");
    let _ = drain_until(&mut b, "JOIN", 3);
    let _ = drain_until(&mut a, "victim", 2); // a observes b's join

    send(&mut a, "MODE #ops +o victim");
    let m = drain_until(&mut b, "MODE #ops", 3);
    let line = m.lines().find(|l| l.contains("MODE #ops")).expect("no MODE broadcast");
    // Correct shape: "<chan> +o <nick>" — flag joined to sign, target present.
    assert!(line.contains("MODE #ops +o victim"), "malformed op MODE: {line:?}");
    assert!(!line.contains("+ o"), "stray space between sign and flag: {line:?}");
}

#[test]
fn chanserv_register_and_founder_autoop() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "founder1");
    send(&mut a, "PRIVMSG NickServ :REGISTER founderpass");
    let _ = drain_until(&mut a, "registered", 3);

    // Create the channel (creator-op), then register it with ChanServ.
    send(&mut a, "JOIN #den");
    let _ = drain_until(&mut a, "JOIN", 3);
    send(&mut a, "PRIVMSG ChanServ :REGISTER #den");
    let reg = drain_until(&mut a, "registered", 3);
    assert!(reg.contains("ChanServ") && reg.contains("registered"), "ChanServ REGISTER failed: {reg:?}");

    // Leave (the channel empties), then rejoin: the founder must be re-opped by
    // ChanServ even though a fresh joiner would normally not be an operator.
    send(&mut a, "PART #den");
    let _ = drain_until(&mut a, "PART", 3);
    send(&mut a, "JOIN #den");
    let rejoin = drain_until(&mut a, "+o founder1", 3);
    assert!(
        rejoin.contains("ChanServ") && rejoin.contains("MODE #den +o founder1"),
        "founder not auto-opped on rejoin: {rejoin:?}"
    );
}

#[test]
fn extended_join_carries_account_and_realname() {
    let addr = start_server();

    // Watcher negotiates extended-join and sits in the channel.
    let mut watch = client(&addr);
    send(&mut watch, "CAP REQ :extended-join");
    let _ = drain_until(&mut watch, "ACK", 3);
    send(&mut watch, "CAP END");
    register(&mut watch, "watcher");
    send(&mut watch, "JOIN #xj");
    let _ = drain_until(&mut watch, "JOIN", 3);

    // A second user joins; the watcher must see the extended form.
    let mut joiner = client(&addr);
    register(&mut joiner, "joiner");
    send(&mut joiner, "JOIN #xj");

    let seen = drain_until(&mut watch, "joiner", 3);
    let jline = seen.lines().find(|l| l.contains("JOIN") && l.contains("joiner!")).expect("no join seen");
    // Format: :joiner!user@host JOIN #xj <account> :<realname>
    assert!(jline.contains("#xj *"), "extended-join should carry account field (* when logged out): {jline:?}");
    assert!(jline.contains(":joiner test"), "extended-join should carry realname: {jline:?}");
}
