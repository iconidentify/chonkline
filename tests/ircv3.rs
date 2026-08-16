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

/// Read for the full duration (no early stop) so duplicate lines are captured.
fn drain_for(s: &mut TcpStream, secs: u64) -> String {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut buf: Vec<u8> = Vec::new();
    while Instant::now() < deadline {
        let mut chunk = [0u8; 4096];
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => {}
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

#[test]
fn nick_change_is_broadcast_to_channel_and_self() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "alpha");
    send(&mut a, "JOIN #nickroom");
    let _ = drain_until(&mut a, "JOIN", 3);
    let mut b = client(&addr);
    register(&mut b, "beta");
    send(&mut b, "JOIN #nickroom");
    let _ = drain_until(&mut b, "JOIN", 3);
    let _ = drain_until(&mut a, "beta", 2);

    send(&mut a, "NICK alpha2");
    // The channel peer must see the rename.
    let seen = drain_until(&mut b, "NICK", 3);
    assert!(
        seen.contains(":alpha!") && seen.contains("NICK") && seen.contains("alpha2"),
        "channel peer did not see NICK change: {seen:?}"
    );
    // The renamer must get its own echo.
    let echo = drain_until(&mut a, "NICK alpha2", 3);
    assert!(echo.contains("NICK") && echo.contains("alpha2"), "no self NICK echo: {echo:?}");
}

#[test]
fn quit_reaches_peers_once_and_not_strangers() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "quita");
    send(&mut a, "JOIN #qroom");
    let _ = drain_until(&mut a, "JOIN", 3);
    let mut b = client(&addr);
    register(&mut b, "quitb");
    send(&mut b, "JOIN #qroom");
    let _ = drain_until(&mut b, "JOIN", 3);
    let mut stranger = client(&addr);
    register(&mut stranger, "quitc"); // shares no channel with quita
    let _ = drain_until(&mut a, "quitb", 2);

    send(&mut a, "QUIT :bye now");
    let bseen = drain_for(&mut b, 2);
    assert!(bseen.contains(":quita!") && bseen.contains("bye now"), "peer missed QUIT: {bseen:?}");
    assert_eq!(bseen.matches(" QUIT ").count(), 1, "duplicate QUIT broadcast: {bseen:?}");

    let cseen = drain_for(&mut stranger, 1);
    assert!(!cseen.contains(":quita!"), "stranger wrongly saw the QUIT: {cseen:?}");
}

#[test]
fn nickserv_ghost_disconnects_held_session() {
    let addr = start_server();
    // A registers and holds the nick "ghoster".
    let mut a = client(&addr);
    register(&mut a, "ghoster");
    send(&mut a, "PRIVMSG NickServ :REGISTER ghostpass");
    let _ = drain_until(&mut a, "registered", 3);

    // B connects under a different nick, identifies to the ghoster account,
    // then ghosts the lingering session.
    let mut b = client(&addr);
    register(&mut b, "ghostb");
    send(&mut b, "PRIVMSG NickServ :IDENTIFY ghoster ghostpass");
    let _ = drain_until(&mut b, "identified", 3);
    send(&mut b, "PRIVMSG NickServ :GHOST ghoster");
    let g = drain_until(&mut b, "disconnected", 3);
    assert!(g.contains("disconnected") && g.contains("free"), "ghost notice absent: {g:?}");

    // The server disconnects A (its socket is closed from the server side).
    let mut closed = false;
    let mut buf = [0u8; 256];
    for _ in 0..10 {
        match a.read(&mut buf) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    assert!(closed, "ghosted session A was not disconnected");

    // The nick is now free: a fresh registration for "ghoster" succeeds.
    let mut c = client(&addr);
    c.write_all(b"NICK ghoster\r\nUSER ghoster 0 * :C\r\n").unwrap();
    let welcome = drain_until(&mut c, " 001 ", 3);
    assert!(welcome.contains(" 001 "), "freed nick could not be reused: {welcome:?}");
}

#[test]
fn topic_reports_setter_and_time_333() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "topa");
    send(&mut a, "JOIN #topicwho");
    let _ = drain_until(&mut a, "JOIN", 3);
    send(&mut a, "TOPIC #topicwho :the new topic");
    let _ = drain_until(&mut a, "TOPIC", 2);

    // A fresh joiner must receive 332 (topic) and 333 (setter + time).
    let mut b = client(&addr);
    register(&mut b, "topb");
    send(&mut b, "JOIN #topicwho");
    let seen = drain_until(&mut b, " 333 ", 3);
    assert!(seen.contains(" 332 ") && seen.contains("the new topic"), "RPL_TOPIC missing: {seen:?}");
    let l333 = seen.lines().find(|l| l.contains(" 333 ")).expect("no RPL_TOPICWHOTIME");
    assert!(l333.contains("#topicwho") && l333.contains("topa"), "333 setter wrong: {l333:?}");
    // last token is a unix timestamp
    let ts = l333.split_whitespace().last().unwrap_or("");
    assert!(ts.parse::<u64>().map(|t| t > 1_600_000_000).unwrap_or(false), "333 timestamp invalid: {l333:?}");
}

#[test]
fn who_flags_carry_here_gone_and_status() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "whoa");
    send(&mut a, "JOIN #whoroom"); // creator -> op
    let _ = drain_until(&mut a, "JOIN", 3);
    let mut b = client(&addr);
    register(&mut b, "whob");
    send(&mut b, "JOIN #whoroom");
    let _ = drain_until(&mut b, "JOIN", 3);
    send(&mut b, "AWAY :brb");
    let _ = drain_until(&mut b, " 306 ", 2);
    let _ = drain_until(&mut a, "whob", 2);

    send(&mut a, "WHO #whoroom");
    let who = drain_until(&mut a, " 315 ", 3);
    // whoa is present + channel op -> "H@"; whob is away -> "G".
    assert!(who.contains(" H@ :0"), "here+op WHO flags (H@) absent: {who:?}");
    assert!(who.contains(" G :0"), "away user not flagged G in WHO: {who:?}");
    assert!(!who.contains(" O :0"), "obsolete 'O' oper flag still emitted: {who:?}");
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

// ---------------------------------------------------------------------------
// GitHub-issue conformance coverage (#8/#10/#12/#13/#14/#15/#16/#17)
// ---------------------------------------------------------------------------

#[test]
fn oper_and_admin_numerics() {
    // #12: OPER success -> 381 (not 379); non-oper admin cmd -> 481; ADMIN -> 256/257.
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "opercand");
    send(&mut a, "REHASH");
    let rehash = drain_until(&mut a, " 481 ", 2);
    assert!(rehash.contains(" 481 "), "non-oper REHASH should be 481: {rehash:?}");
    send(&mut a, "OPER oper secret");
    let oper = drain_until(&mut a, " 381 ", 3);
    assert!(oper.contains(" 381 "), "OPER should reply 381 RPL_YOUREOPER: {oper:?}");
    assert!(!oper.contains(" 379 "), "OPER must not use 379: {oper:?}");
    send(&mut a, "ADMIN");
    let admin = drain_until(&mut a, " 256 ", 2);
    assert!(admin.contains(" 256 "), "ADMIN should use RPL_ADMINME 256: {admin:?}");
}

#[test]
fn links_and_trace_numerics() {
    // #12: LINKS -> 364 + 365; TRACE -> 262.
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "linktrace");
    send(&mut a, "LINKS");
    let links = drain_until(&mut a, " 365 ", 3);
    assert!(links.contains(" 364 ") && links.contains(" 365 "), "LINKS should be 364+365: {links:?}");
    send(&mut a, "TRACE");
    let trace = drain_until(&mut a, " 262 ", 3);
    assert!(trace.contains(" 262 "), "TRACE should end with 262: {trace:?}");
}

#[test]
fn wallops_reaches_plus_w_users() {
    let addr = start_server();
    let mut oper = client(&addr);
    register(&mut oper, "woper");
    send(&mut oper, "OPER oper secret");
    let _ = drain_until(&mut oper, " 381 ", 3);
    let mut listener = client(&addr);
    register(&mut listener, "wlisten");
    send(&mut listener, "MODE wlisten +w");
    let _ = drain_until(&mut listener, "+w", 2);
    send(&mut oper, "WALLOPS :maintenance soon");
    let got = drain_until(&mut listener, "WALLOPS", 3);
    assert!(got.contains("WALLOPS") && got.contains("maintenance soon"), "+w user missed WALLOPS: {got:?}");
}

#[test]
fn channel_mode_query_324_and_329() {
    // #8: 324 includes key/limit values; 329 creation time follows.
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "moder");
    send(&mut a, "JOIN #modeq");
    let _ = drain_until(&mut a, "JOIN", 3);
    send(&mut a, "MODE #modeq +kl secret 25");
    let _ = drain_until(&mut a, "MODE #modeq", 2);
    send(&mut a, "MODE #modeq");
    let q = drain_until(&mut a, " 329 ", 3);
    let l324 = q.lines().find(|l| l.contains(" 324 ")).expect("no 324");
    assert!(l324.contains("secret") && l324.contains("25"), "324 missing key/limit values: {l324:?}");
    assert!(q.contains(" 329 "), "329 RPL_CREATIONTIME absent: {q:?}");
}

#[test]
fn lusers_reports_265_266() {
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "luser");
    send(&mut a, "LUSERS");
    let l = drain_until(&mut a, " 266 ", 3);
    assert!(l.contains(" 265 ") && l.contains(" 266 "), "LUSERS missing 265/266: {l:?}");
}

#[test]
fn cap_ls_includes_new_caps() {
    let addr = start_server();
    let mut c = client(&addr);
    send(&mut c, "CAP LS 302");
    let ls = drain_until(&mut c, "LS :", 3);
    for cap in ["userhost-in-names", "chghost", "cap-notify"] {
        assert!(ls.contains(cap), "CAP LS missing {cap}: {ls:?}");
    }
}

#[test]
fn userhost_in_names_expands_entries() {
    // #10: with the cap, 353 lists nick!user@host.
    let addr = start_server();
    let mut a = client(&addr);
    send(&mut a, "CAP REQ :userhost-in-names");
    let _ = drain_until(&mut a, "ACK", 3);
    send(&mut a, "CAP END");
    register(&mut a, "uhnick");
    send(&mut a, "JOIN #uhn");
    let names = drain_until(&mut a, " 353 ", 3);
    assert!(names.contains("uhnick!uhnick@"), "NAMES should carry user@host: {names:?}");
}

#[test]
fn chghost_on_account_login() {
    // #17: logging in changes the visible host and emits CHGHOST to the client.
    let addr = start_server();
    let mut a = client(&addr);
    send(&mut a, "CAP REQ :chghost");
    let _ = drain_until(&mut a, "ACK", 3);
    send(&mut a, "CAP END");
    register(&mut a, "chguser");
    send(&mut a, "JOIN #chg");
    let _ = drain_until(&mut a, "JOIN", 3);
    send(&mut a, "PRIVMSG NickServ :REGISTER chgpass");
    let seen = drain_until(&mut a, "CHGHOST", 3);
    assert!(seen.contains("CHGHOST") && seen.contains("chguser.user."), "no CHGHOST on login: {seen:?}");
}

#[test]
fn statusmsg_reaches_only_ops() {
    // #15: @#chan reaches operators, not regular members.
    let addr = start_server();
    let mut op = client(&addr);
    register(&mut op, "smop");
    send(&mut op, "JOIN #sm"); // creator -> op
    let _ = drain_until(&mut op, "JOIN", 3);
    let mut reg = client(&addr);
    register(&mut reg, "smreg");
    send(&mut reg, "JOIN #sm");
    let _ = drain_until(&mut reg, "JOIN", 3);
    let _ = drain_until(&mut op, "smreg", 2);
    // regular member sends to @#sm; only the op should receive it
    send(&mut reg, "PRIVMSG @#sm :ops only");
    let opgot = drain_until(&mut op, "ops only", 3);
    assert!(opgot.contains("PRIVMSG @#sm :ops only"), "op did not get STATUSMSG: {opgot:?}");
    let reggot = drain_for(&mut reg, 1);
    assert!(!reggot.contains("ops only"), "regular member wrongly echoed STATUSMSG: {reggot:?}");
}

#[test]
fn whox_returns_requested_fields() {
    // #14: WHO %cnf returns 354 with channel, nick, flags only.
    let addr = start_server();
    let mut a = client(&addr);
    register(&mut a, "whoxer");
    send(&mut a, "JOIN #whox");
    let _ = drain_until(&mut a, "JOIN", 3);
    send(&mut a, "WHO #whox %tcnf,99");
    let w = drain_until(&mut a, " 354 ", 3);
    let l = w.lines().find(|l| l.contains(" 354 ")).expect("no 354");
    assert!(l.contains(" 99 ") && l.contains("#whox") && l.contains("whoxer"), "354 fields wrong: {l:?}");
}

#[test]
fn ban_exception_lets_user_join() {
    // #16: +b then a matching +e lets the user in; 348/349 list the exceptions.
    let addr = start_server();
    let mut op = client(&addr);
    register(&mut op, "banop");
    send(&mut op, "JOIN #bex");
    let _ = drain_until(&mut op, "JOIN", 3);
    send(&mut op, "MODE #bex +b *!*@*");     // ban everyone
    send(&mut op, "MODE #bex +e *!*@*");     // but except everyone
    let _ = drain_until(&mut op, "MODE #bex +e", 2);
    send(&mut op, "MODE #bex e");
    let elist = drain_until(&mut op, " 349 ", 2);
    assert!(elist.contains(" 348 ") && elist.contains(" 349 "), "except list 348/349 absent: {elist:?}");
    // a second user (covered by the exception) can join despite the ban
    let mut u = client(&addr);
    register(&mut u, "banned");
    send(&mut u, "JOIN #bex");
    let uj = drain_until(&mut u, "#bex", 3);
    assert!(uj.contains("JOIN") && !uj.contains(" 474 "), "exception did not override ban: {uj:?}");
}

#[test]
fn invite_exception_bypasses_invite_only() {
    // #16: +I mask lets a matching user bypass +i; 346/347 list.
    let addr = start_server();
    let mut op = client(&addr);
    register(&mut op, "invop");
    send(&mut op, "JOIN #iex");
    let _ = drain_until(&mut op, "JOIN", 3);
    send(&mut op, "MODE #iex +i");
    send(&mut op, "MODE #iex +I *!*@*");
    let _ = drain_until(&mut op, "MODE #iex +I", 2);
    send(&mut op, "MODE #iex I");
    let ilist = drain_until(&mut op, " 347 ", 2);
    assert!(ilist.contains(" 346 ") && ilist.contains(" 347 "), "invex list 346/347 absent: {ilist:?}");
    let mut u = client(&addr);
    register(&mut u, "guest");
    send(&mut u, "JOIN #iex");
    let uj = drain_until(&mut u, "#iex", 3);
    assert!(uj.contains("JOIN") && !uj.contains(" 473 "), "invex did not bypass +i: {uj:?}");
}
