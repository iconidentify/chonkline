// Coverage for the services, SASL-ordering, list, and labeled-response fixes.
mod common;
use common::start_server;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use irc_server::crypto::base64_encode;

fn client(addr: &str) -> TcpStream {
    let s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    s
}

fn send(s: &mut TcpStream, line: &str) {
    s.write_all(line.as_bytes()).unwrap();
    s.write_all(b"\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(35));
}

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
            Err(_) => {}
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn register(s: &mut TcpStream, nick: &str) {
    send(s, &format!("NICK {nick}"));
    send(s, &format!("USER {nick} 0 * :{nick} test"));
    let welcome = drain_until(s, " 001 ", 3);
    assert!(
        welcome.contains(" 001 "),
        "{nick} did not register: {welcome:?}"
    );
}

#[test]
fn service_nicks_and_accounts_are_reserved() {
    let addr = start_server();
    let mut c = client(&addr);
    send(&mut c, "NICK NickServ");
    send(&mut c, "USER NickServ 0 * :nope");
    let refused = drain_until(&mut c, " 432 ", 3);
    assert!(
        refused.contains(" 432 "),
        "NickServ was accepted: {refused:?}"
    );
    assert!(
        refused.to_ascii_lowercase().contains("reserved"),
        "432 should say the nick is reserved: {refused:?}"
    );

    register(&mut c, "ordinary");
    send(&mut c, "NICK ChanServ");
    let renamed = drain_until(&mut c, " 432 ", 3);
    assert!(
        renamed.contains(" 432 "),
        "rename onto ChanServ was accepted: {renamed:?}"
    );
    // The session keeps the nick it had.
    send(&mut c, "USERHOST ordinary");
    let uh = drain_until(&mut c, " 302 ", 3);
    assert!(
        uh.contains("ordinary"),
        "reserved rename kicked the real nick off: {uh:?}"
    );
}

#[test]
fn password_change_requires_the_current_password() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "pwuser");
    send(&mut a, "PRIVMSG NickServ :REGISTER oldpass");
    let reg = drain_until(&mut a, "registered", 3);
    assert!(reg.contains("registered"), "register failed: {reg:?}");

    send(&mut a, "PRIVMSG NickServ :SET PASSWORD oldpass newpass");
    let updated = drain_until(&mut a, "Password updated", 3);
    assert!(
        updated.contains("Password updated"),
        "set password failed: {updated:?}"
    );

    // A wrong current password does not rotate the credential.
    send(&mut a, "PRIVMSG NickServ :SET PASSWORD oldpass other");
    let wrong = drain_until(&mut a, "incorrect", 3);
    assert!(
        wrong.to_ascii_lowercase().contains("incorrect"),
        "wrong current password was accepted: {wrong:?}"
    );

    let mut fresh = client(&addr);
    register(&mut fresh, "checker");
    send(&mut fresh, "PRIVMSG NickServ :IDENTIFY pwuser oldpass");
    let old = drain_until(&mut fresh, "Invalid", 3);
    assert!(old.contains("Invalid"), "old password still works: {old:?}");
    send(&mut fresh, "PRIVMSG NickServ :IDENTIFY pwuser newpass");
    let now = drain_until(&mut fresh, "identified", 3);
    assert!(
        now.contains("identified"),
        "new password was not accepted: {now:?}"
    );

    let mut anon = client(&addr);
    register(&mut anon, "anon");
    send(&mut anon, "PRIVMSG NickServ :SET PASSWORD a b");
    let denied = drain_until(&mut anon, "identified", 3);
    assert!(
        denied.contains("must be identified"),
        "anonymous password change was accepted: {denied:?}"
    );

    send(&mut a, "PRIVMSG NickServ :HELP");
    let help = drain_until(&mut a, "SET PASSWORD", 3);
    assert!(
        help.contains("SET PASSWORD"),
        "HELP omits SET PASSWORD: {help:?}"
    );
}

#[test]
fn sasl_plain_accepts_nick_and_user_before_authenticate() {
    let addr = start_server();
    let mut owner = client(&addr);
    register(&mut owner, "sasluser");
    send(&mut owner, "PRIVMSG NickServ :REGISTER hunter2");
    let reg = drain_until(&mut owner, "registered", 3);
    assert!(reg.contains("registered"), "register failed: {reg:?}");

    let mut b = client(&addr);
    send(&mut b, "CAP LS 302");
    let _ = drain_until(&mut b, "LS :", 3);
    send(&mut b, "NICK saslclient");
    send(&mut b, "USER saslclient 0 * :saslclient");
    send(&mut b, "CAP REQ :sasl");
    let ack = drain_until(&mut b, "ACK", 3);
    assert!(ack.contains("sasl"), "sasl was not acked: {ack:?}");
    send(&mut b, "AUTHENTICATE PLAIN");
    let prompt = drain_until(&mut b, "AUTHENTICATE +", 3);
    assert!(
        prompt.contains("AUTHENTICATE +"),
        "normal order did not reach PLAIN: {prompt:?}"
    );
    assert!(
        !prompt.contains(" 907 "),
        "normal order was rejected as already authenticated: {prompt:?}"
    );

    let payload = base64_encode(b"\0sasluser\0hunter2");
    send(&mut b, &format!("AUTHENTICATE {payload}"));
    let done = drain_until(&mut b, " 903 ", 3);
    assert!(done.contains(" 903 "), "SASL did not succeed: {done:?}");
    assert!(
        !done.contains(" 907 "),
        "success was reported as 907: {done:?}"
    );

    send(&mut b, "CAP END");
    let welcome = drain_until(&mut b, " 001 ", 3);
    assert!(
        welcome.contains(" 001 "),
        "welcome never arrived after CAP END: {welcome:?}"
    );

    // Registration has finished; SASL is no longer in time.
    send(&mut b, "AUTHENTICATE PLAIN");
    let late = drain_until(&mut b, " 907 ", 3);
    assert!(
        late.contains(" 907 "),
        "SASL after welcome should be 907: {late:?}"
    );
}

#[test]
fn plaintext_does_not_offer_external() {
    let addr = start_server();
    let mut owner = client(&addr);
    register(&mut owner, "plainuser");
    send(&mut owner, "PRIVMSG NickServ :REGISTER hunter2");
    assert!(drain_until(&mut owner, "registered", 3).contains("registered"));

    let mut b = client(&addr);
    send(&mut b, "CAP LS 302");
    let ls = drain_until(&mut b, "sasl=PLAIN", 3);
    assert!(
        ls.contains("sasl=PLAIN") && !ls.contains("EXTERNAL"),
        "plaintext advertised EXTERNAL: {ls:?}"
    );
    send(&mut b, "NICK plainclient");
    send(&mut b, "USER plainclient 0 * :plainclient");
    send(&mut b, "CAP REQ :sasl");
    assert!(drain_until(&mut b, "ACK", 3).contains("sasl"));
    send(&mut b, "AUTHENTICATE EXTERNAL");
    let refused = drain_until(&mut b, " 904 ", 3);
    assert!(
        refused.contains(" 908 "),
        "missing mechanism list: {refused:?}"
    );
    assert!(
        refused.contains(" 904 "),
        "EXTERNAL was not refused: {refused:?}"
    );
    assert!(
        !refused.contains("EXTERNAL,PLAIN"),
        "plaintext offered EXTERNAL: {refused:?}"
    );

    // The failed attempt must not consume the one SASL try.
    send(&mut b, "AUTHENTICATE PLAIN");
    assert!(drain_until(&mut b, "AUTHENTICATE +", 3).contains("AUTHENTICATE +"));
    let payload = base64_encode(b"\0plainuser\0hunter2");
    send(&mut b, &format!("AUTHENTICATE {payload}"));
    let done = drain_until(&mut b, " 903 ", 3);
    assert!(
        done.contains(" 903 "),
        "PLAIN after a refused EXTERNAL failed: {done:?}"
    );
}

#[test]
fn founder_is_opped_on_identify_and_by_chanserv_op() {
    let addr = start_server();
    let mut founder = client(&addr);
    register(&mut founder, "founder");
    send(&mut founder, "PRIVMSG NickServ :REGISTER founderpass");
    assert!(drain_until(&mut founder, "registered", 3).contains("registered"));
    send(&mut founder, "JOIN #soup");
    assert!(drain_until(&mut founder, " 366 ", 3).contains(" 366 "));
    send(&mut founder, "PRIVMSG ChanServ :REGISTER #soup");
    let reg = drain_until(&mut founder, "registered", 3);
    assert!(
        reg.contains("registered"),
        "channel register failed: {reg:?}"
    );

    // Same account, different nick, not identified at join time.
    let mut late = client(&addr);
    register(&mut late, "founder2");
    send(&mut late, "JOIN #soup");
    let joined = drain_until(&mut late, " 366 ", 3);
    assert!(joined.contains(" 366 "), "join failed: {joined:?}");
    assert!(
        !joined.contains("MODE #soup +o founder2"),
        "unidentified joiner was opped: {joined:?}"
    );
    send(&mut late, "PRIVMSG NickServ :IDENTIFY founder founderpass");
    let opped = drain_until(&mut late, "MODE #soup +o founder2", 3);
    assert!(
        opped.contains("ChanServ") && opped.contains("MODE #soup +o founder2"),
        "identify did not grant founder ops: {opped:?}"
    );

    // Deliberate deop, then the explicit command restores it.
    send(&mut late, "MODE #soup -o founder2");
    let deop = drain_until(&mut late, "MODE #soup -o founder2", 3);
    assert!(
        deop.contains("-o founder2"),
        "deop was not applied: {deop:?}"
    );
    send(&mut late, "PRIVMSG ChanServ :OP #soup");
    let restored = drain_until(&mut late, "MODE #soup +o founder2", 3);
    assert!(
        restored.contains("MODE #soup +o founder2"),
        "ChanServ OP did not restore ops: {restored:?}"
    );

    // Already op: a notice, and no second mode change.
    send(&mut late, "PRIVMSG ChanServ :OP #soup");
    let again = drain_until(&mut late, "already an operator", 3);
    assert!(
        again.contains("already an operator"),
        "second OP did not notice: {again:?}"
    );
    assert!(
        !again.contains("MODE #soup +o"),
        "second OP sent another mode: {again:?}"
    );

    // Logout keeps the ops the founder already holds.
    send(&mut late, "PRIVMSG NickServ :LOGOUT");
    let logged_out = drain_until(&mut late, "logged out", 3);
    assert!(
        logged_out.contains("logged out"),
        "logout failed: {logged_out:?}"
    );
    assert!(
        !logged_out.contains("MODE #soup -o"),
        "logout removed founder ops: {logged_out:?}"
    );

    // A logged-in non-founder is refused and stays unopped.
    let mut stranger = client(&addr);
    register(&mut stranger, "stranger");
    send(&mut stranger, "PRIVMSG NickServ :REGISTER strangerpass");
    assert!(drain_until(&mut stranger, "registered", 3).contains("registered"));
    send(&mut stranger, "JOIN #soup");
    let _ = drain_until(&mut stranger, " 366 ", 3);
    send(&mut stranger, "PRIVMSG ChanServ :OP #soup");
    let denied = drain_until(&mut stranger, "founder", 3);
    assert!(
        denied.contains("founder"),
        "non-founder OP was not refused: {denied:?}"
    );
    assert!(
        !denied.contains("MODE #soup +o stranger"),
        "non-founder was opped: {denied:?}"
    );

    send(&mut founder, "PRIVMSG ChanServ :HELP");
    let help = drain_until(&mut founder, "OP #channel", 3);
    assert!(help.contains("OP #channel"), "HELP omits OP: {help:?}");
}

#[test]
fn list_header_and_mask_match_the_advertised_elist() {
    let addr = start_server();
    let mut c = client(&addr);
    register(&mut c, "lister");
    for chan in ["#alpha", "#beta", "#other"] {
        send(&mut c, &format!("JOIN {chan}"));
        let _ = drain_until(&mut c, " 366 ", 3);
    }
    send(&mut c, "LIST #a*");
    let listed = drain_until(&mut c, " 323 ", 3);
    let start = listed.lines().find(|l| l.contains(" 321 ")).unwrap_or("");
    assert!(
        start.contains("Channel"),
        "321 is missing the Channel header: {start:?}"
    );
    assert!(
        start.contains("Users Name"),
        "321 is missing the Users Name header: {start:?}"
    );
    assert!(
        listed.contains("#alpha"),
        "ELIST mask dropped #alpha: {listed:?}"
    );
    assert!(
        !listed.contains("#beta"),
        "ELIST mask kept #beta: {listed:?}"
    );
    assert!(
        !listed.contains("#other"),
        "ELIST mask kept #other: {listed:?}"
    );
    assert!(listed.contains(" 323 "), "LIST never closed: {listed:?}");
}

#[test]
fn labeled_response_batches_multiline_replies_and_acks_the_rest() {
    let addr = start_server();
    let mut a = client(&addr);
    // Either cap may be requested on its own. labeled-response is not applied
    // until batch is negotiated too, and the order is not significant.
    send(&mut a, "CAP REQ :labeled-response");
    let only = drain_until(&mut a, "ACK", 3);
    assert!(
        only.contains("labeled-response") && !only.contains("NAK"),
        "labeled-response alone was refused: {only:?}"
    );
    send(&mut a, "CAP REQ :batch");
    let both = drain_until(&mut a, "ACK", 3);
    assert!(
        both.contains("batch") && !both.contains("NAK"),
        "batch was refused: {both:?}"
    );
    send(&mut a, "CAP END");
    register(&mut a, "labeler");

    send(&mut a, "@label=ping1 PING hello");
    let pong = drain_until(&mut a, "PONG", 3);
    let pong_line = pong.lines().find(|l| l.contains("PONG")).unwrap_or("");
    assert!(
        pong_line.starts_with("@label=ping1 "),
        "single reply was not labeled: {pong_line:?}"
    );
    assert!(
        !pong.contains("BATCH"),
        "a one-line reply was wrapped in a batch: {pong:?}"
    );

    // Tag names are case-insensitive; the value is echoed as the client sent it.
    send(&mut a, "@LaBeL=Ping2 PING hello2");
    let pong2 = drain_until(&mut a, "hello2", 3);
    let pong2_line = pong2.lines().find(|l| l.contains("PONG")).unwrap_or("");
    assert!(
        pong2_line.starts_with("@label=Ping2 "),
        "label tag name was not folded: {pong2_line:?}"
    );

    send(&mut a, "@label=empty1 PONG :whatever");
    let ack = drain_until(&mut a, "ACK", 3);
    let ack_line = ack
        .lines()
        .find(|l| l.contains("ACK") && l.contains("label="))
        .unwrap_or("");
    assert!(
        ack_line.starts_with("@label=empty1 "),
        "empty command was not acked: {ack:?}"
    );
    assert!(ack_line.contains(" ACK"), "ACK verb missing: {ack_line:?}");

    send(&mut a, "JOIN #labeled");
    let _ = drain_until(&mut a, " 366 ", 3);
    send(&mut a, "@label=lst LIST");
    let list = drain_until(&mut a, "BATCH -", 3);
    let lines: Vec<&str> = list.lines().collect();
    let open = lines
        .iter()
        .find(|l| l.contains("BATCH +") && l.contains("labeled-response"))
        .copied()
        .unwrap_or("");
    assert!(
        open.starts_with("@label=lst "),
        "batch open is missing the label: {list:?}"
    );
    assert!(
        open.contains("labeled-response"),
        "batch type missing: {open:?}"
    );
    let reference = open
        .split_whitespace()
        .find(|t| t.starts_with('+'))
        .unwrap_or("")
        .trim_start_matches('+');
    assert!(!reference.is_empty(), "batch reference missing: {open:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains(" 321 ") && l.starts_with(&format!("@batch={reference}"))),
        "321 was not inside the batch: {list:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains(" 323 ") && l.starts_with(&format!("@batch={reference}"))),
        "323 was not inside the batch: {list:?}"
    );
    let close = lines
        .iter()
        .find(|l| l.contains("BATCH -"))
        .copied()
        .unwrap_or("");
    assert!(
        !close.contains("label="),
        "batch close must not repeat the label: {close:?}"
    );
    assert!(
        !lines
            .iter()
            .filter(|l| l.contains(" 321 ") || l.contains(" 322 ") || l.contains(" 323 "))
            .any(|l| l.contains("label=")),
        "inner numerics must not carry the label: {list:?}"
    );

    // A label the server refuses to echo does not break the command.
    let huge = "x".repeat(65);
    send(&mut a, &format!("@label={huge} PING big"));
    let big = drain_until(&mut a, "PONG", 3);
    let big_line = big.lines().find(|l| l.contains("PONG")).unwrap_or("");
    assert!(
        !big_line.contains("label="),
        "overlong label was echoed: {big_line:?}"
    );
    assert!(
        big_line.contains("PONG"),
        "overlong label dropped the command: {big:?}"
    );

    let mut b = client(&addr);
    register(&mut b, "hearer");
    send(&mut a, "@label=secret PRIVMSG hearer :hello leak");
    let heard = drain_until(&mut b, "hello leak", 3);
    assert!(
        heard.contains("hello leak"),
        "labeled PRIVMSG was not delivered: {heard:?}"
    );
    assert!(
        !heard.contains("label="),
        "client label leaked to the recipient: {heard:?}"
    );
    let acked = drain_until(&mut a, "@label=secret", 3);
    assert!(
        acked.contains("@label=secret") && acked.contains("ACK"),
        "successful PRIVMSG was not acked: {acked:?}"
    );
}
