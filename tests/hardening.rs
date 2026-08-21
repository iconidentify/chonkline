//! End-to-end coverage for the post-incident hardening work.
//!
//! These run in their own test binary so the PROXY-protocol environment does
//! not leak into the other suites, which deliberately exercise the direct
//! (no-proxy) path.

mod common;
use common::*;

/// Every test here shares one environment, so the values are set identically
/// and the server is started only after they are in place.
fn start_proxied_server() -> String {
    std::env::set_var("IRC_PROXY_PROTOCOL", "1");
    // These clients arrive over loopback, which is exempt by default so the TLS
    // sidecar keeps working. Clear the exemption so the header is genuinely
    // required here; the sidecar path is covered in tests/tls_sidecar.rs.
    std::env::set_var("IRC_PROXY_PROTOCOL_EXEMPT", "");
    std::env::set_var("IRC_MAX_CLONES_PER_IP", "2");
    std::env::set_var("IRC_MAX_CONNECTS_PER_MIN", "0"); // isolate the clone cap
    std::env::set_var("IRC_MAX_MESSAGES_PER_10S", "0"); // not under test here
    std::env::set_var("IRC_CLOAK_SECRET", "hardening-test-secret");
    std::env::set_var("IRC_CLOAK_SUFFIX", "users.test");
    start_server()
}

/// Register a client that arrives through the proxy from `src`, join `chan`,
/// and return the host shown in its own JOIN echo — i.e. its cloak.
fn cloak_seen_by_joining(addr: &str, src: &str, nick: &str, chan: &str) -> String {
    let mut c = Client::new(addr);
    c.send(&format!("PROXY TCP4 {} 10.0.0.1 41234 6667", src));
    c.send(&format!("NICK {}", nick));
    c.send(&format!("USER {} 0 * :Hardening Test", nick));
    c.read_until(|l| l.contains(" 001 "));
    c.send(&format!("JOIN {}", chan));

    let echo = c.read_until(|l| l.contains("JOIN") && l.contains(nick));
    // ":nick!user@cloak JOIN #chan" -> cloak
    echo.split('@')
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn distinct_sources_receive_distinct_cloaks() {
    let addr = start_proxied_server();

    let a = cloak_seen_by_joining(&addr, "203.0.113.7", "alice", "#cloaktest");
    let b = cloak_seen_by_joining(&addr, "198.51.100.9", "bob", "#cloaktest");

    assert!(!a.is_empty() && !b.is_empty(), "both clients must report a cloak (a={a:?} b={b:?})");
    assert_ne!(
        a, b,
        "two clients from different addresses must not share a cloak — a shared cloak is the \
         defect this whole change exists to fix"
    );
    assert!(a.ends_with(".users.test"), "cloak should carry the configured suffix, got {a:?}");
}

#[test]
fn the_same_source_keeps_a_stable_cloak() {
    let addr = start_proxied_server();

    // Stability is what makes a cloak bannable across reconnects.
    let first = cloak_seen_by_joining(&addr, "203.0.113.50", "carol", "#stabletest");
    let second = cloak_seen_by_joining(&addr, "203.0.113.50", "dave", "#stabletest");

    assert_eq!(first, second, "one address must map to one stable cloak");
}

#[test]
fn a_malformed_proxy_header_fails_closed() {
    let addr = start_proxied_server();

    // Falling back to peer_addr() here would silently reintroduce the shared
    // cloak, so the connection must be refused instead.
    let mut c = Client::new(&addr);
    c.send("NICK eve"); // no PROXY header at all
    c.send("USER eve 0 * :No Header");

    let line = c.read_until(|l| l.contains("ERROR") || l.contains(" 001 "));
    assert!(
        line.contains("ERROR"),
        "a connection without a valid PROXY header must be refused, got {line:?}"
    );
}

#[test]
fn clone_cap_refuses_the_excess_and_isolates_other_sources() {
    let addr = start_proxied_server();
    let flood_src = "203.0.113.200";

    // Hold the cap open with live connections.
    let mut held = Vec::new();
    for i in 0..2 {
        let mut c = Client::new(&addr);
        c.send(&format!("PROXY TCP4 {} 10.0.0.1 4000{} 6667", flood_src, i));
        c.send(&format!("NICK flood{}", i));
        c.send(&format!("USER flood{} 0 * :Flood", i));
        c.read_until(|l| l.contains(" 001 "));
        held.push(c);
    }

    // The third from that address is refused...
    let mut over = Client::new(&addr);
    over.send(&format!("PROXY TCP4 {} 10.0.0.1 40099 6667", flood_src));
    over.send("NICK flood9");
    over.send("USER flood9 0 * :Flood");
    let refused = over.read_until(|l| l.contains("ERROR") || l.contains(" 001 "));
    assert!(
        refused.contains("ERROR"),
        "the connection past the clone cap must be refused, got {refused:?}"
    );

    // ...while an unrelated address is entirely unaffected.
    let mut other = Client::new(&addr);
    other.send("PROXY TCP4 198.51.100.77 10.0.0.1 40100 6667");
    other.send("NICK innocent");
    other.send("USER innocent 0 * :Bystander");
    let welcome = other.read_until(|l| l.contains(" 001 ") || l.contains("ERROR"));
    assert!(
        welcome.contains(" 001 "),
        "one source exhausting its cap must not affect another, got {welcome:?}"
    );
}

#[test]
fn regonly_channel_refuses_unauthenticated_joins() {
    let addr = start_proxied_server();

    // Founder opens the channel and sets +R.
    let mut owner = Client::new(&addr);
    owner.send("PROXY TCP4 203.0.113.10 10.0.0.1 42000 6667");
    owner.send("NICK owner");
    owner.send("USER owner 0 * :Owner");
    owner.read_until(|l| l.contains(" 001 "));
    owner.send("JOIN #regonly");
    owner.read_until(|l| l.contains("JOIN"));
    owner.send("MODE #regonly +R");
    owner.read_until(|l| l.contains("MODE") || l.contains("482"));

    // An unauthenticated client is refused with ERR_NEEDREGGEDNICK (477).
    let mut guest = Client::new(&addr);
    guest.send("PROXY TCP4 198.51.100.20 10.0.0.1 42001 6667");
    guest.send("NICK guest");
    guest.send("USER guest 0 * :Guest");
    guest.read_until(|l| l.contains(" 001 "));
    guest.send("JOIN #regonly");

    let reply = guest.read_until(|l| l.contains(" 477 ") || l.contains("JOIN"));
    assert!(
        reply.contains(" 477 "),
        "+R must refuse an unauthenticated join with 477, got {reply:?}"
    );
}

#[test]
fn kill_requires_operator_privilege() {
    let addr = start_proxied_server();

    let mut victim = Client::new(&addr);
    victim.send("PROXY TCP4 203.0.113.30 10.0.0.1 43000 6667");
    victim.send("NICK victim");
    victim.send("USER victim 0 * :Victim");
    victim.read_until(|l| l.contains(" 001 "));

    let mut rando = Client::new(&addr);
    rando.send("PROXY TCP4 198.51.100.30 10.0.0.1 43001 6667");
    rando.send("NICK rando");
    rando.send("USER rando 0 * :Rando");
    rando.read_until(|l| l.contains(" 001 "));

    rando.send("KILL victim :not allowed");
    // Specific: the 005 burst now advertises TARGMAX=PRIVMSG:4,NOTICE:4, so a
    // bare "NOTICE" predicate matches the wrong line.
    let reply = rando.read_until(|l| l.contains(" 481 "));
    assert!(
        reply.contains(" 481 "),
        "a non-operator KILL must be refused with 481, got {reply:?}"
    );
}


#[test]
fn a_client_that_is_not_a_header_is_refused_without_its_bytes_being_eaten() {
    // Detection peeks before reading. A stream that is not a header must be
    // recognised as such rather than having its first line consumed as one --
    // that distinction is what makes this safe to enable on the TLS port, where
    // the first bytes are a ClientHello.
    let addr = start_proxied_server();

    let mut c = Client::new(&addr);
    c.send("NICK notaheader");
    c.send("USER notaheader 0 * :Plain");

    let line = c.read_until(|l| l.contains("ERROR") || l.contains(" 001 "));
    assert!(
        line.contains("ERROR"),
        "required mode must refuse a stream with no header, got {line:?}"
    );
}

#[test]
fn an_overlong_username_is_truncated_rather_than_refused() {
    // Clients send the local system username without asking. Refusing an
    // 11-character one made the server unreachable for those users, who saw
    // only a bare 461 with nothing to act on.
    let addr = start_proxied_server();

    let mut c = Client::new(&addr);
    c.send("PROXY TCP4 203.0.113.60 10.0.0.1 44000 6667");
    c.send("NICK longuser");
    c.send("USER christopherlong 0 * :Long Username");

    let line = c.read_until(|l| l.contains(" 001 ") || l.contains(" 461 "));
    assert!(
        line.contains(" 001 "),
        "an overlong username must register, not be refused: {line:?}"
    );
}

#[test]
fn an_empty_username_is_still_refused() {
    let addr = start_proxied_server();

    let mut c = Client::new(&addr);
    c.send("PROXY TCP4 203.0.113.61 10.0.0.1 44001 6667");
    c.send("NICK emptyuser");
    c.send("USER  0 * :No Username");

    let line = c.read_until(|l| l.contains(" 461 ") || l.contains(" 001 "));
    assert!(line.contains(" 461 "), "an empty username must still be refused: {line:?}");
}

#[test]
fn a_bare_wildcard_mask_cannot_wedge_the_server() {
    // `WHO :` sends an empty mask. That used to panic wildcard_match inside
    // dispatch, under the state lock -- poisoning it, so every later lock
    // panicked too. The server kept accepting TCP while being permanently
    // unable to serve anyone, which a tcpSocket liveness probe cannot detect.
    let addr = start_proxied_server();

    let mut attacker = Client::new(&addr);
    attacker.send("PROXY TCP4 203.0.113.70 10.0.0.1 45000 6667");
    attacker.send("NICK wedger");
    attacker.send("USER wedger 0 * :Wedge");
    attacker.read_until(|l| l.contains(" 001 "));
    attacker.send("WHO :");
    attacker.send("LIST :");

    // The real assertion: a brand-new client must still be able to register.
    let mut after = Client::new(&addr);
    after.send("PROXY TCP4 203.0.113.71 10.0.0.1 45001 6667");
    after.send("NICK survivor");
    after.send("USER survivor 0 * :Survivor");
    let line = after.read_until(|l| l.contains(" 001 ") || l.contains("ERROR"));
    assert!(
        line.contains(" 001 "),
        "server must still serve new clients after an empty mask: {line:?}"
    );
}

#[test]
fn an_empty_ban_mask_cannot_wedge_the_server() {
    // Same matcher, reached through a stored channel ban -- worse, because the
    // empty mask persists and re-fires on every subsequent join.
    let addr = start_proxied_server();

    let mut c = Client::new(&addr);
    c.send("PROXY TCP4 203.0.113.72 10.0.0.1 45002 6667");
    c.send("NICK banner");
    c.send("USER banner 0 * :Banner");
    c.read_until(|l| l.contains(" 001 "));
    c.send("JOIN #wedge");
    c.read_until(|l| l.contains("JOIN"));
    c.send("MODE #wedge +b :");
    c.send("PART #wedge");
    c.send("JOIN #wedge");

    let mut after = Client::new(&addr);
    after.send("PROXY TCP4 203.0.113.73 10.0.0.1 45003 6667");
    after.send("NICK survivor2");
    after.send("USER survivor2 0 * :Survivor");
    let line = after.read_until(|l| l.contains(" 001 ") || l.contains("ERROR"));
    assert!(line.contains(" 001 "), "server must survive an empty ban mask: {line:?}");
}

#[test]
fn an_idle_unregistered_connection_is_reaped() {
    // A socket that completes admission and then sends nothing used to hold an
    // admission slot forever: the liveness sweep covers only registered users,
    // and TCP keepalive catches dead peers, not deliberately idle ones.
    std::env::set_var("CHONKLINE_REG_TIMEOUT_SECS", "1");
    std::env::set_var("CHONKLINE_LIVENESS_TICK_SECS", "1");
    let addr = start_proxied_server();

    let mut idler = Client::new(&addr);
    idler.send("PROXY TCP4 203.0.113.80 10.0.0.1 46000 6667");
    // Deliberately never sends NICK/USER.

    // The reaper should close it rather than leave it parked indefinitely.
    let line = idler.read_until(|l| l.contains("ERROR") || l.contains("QUIT") || l.contains(" 001 "));
    assert!(
        !line.contains(" 001 "),
        "an idle connection must never register on its own: {line:?}"
    );

    std::env::remove_var("CHONKLINE_REG_TIMEOUT_SECS");
    std::env::remove_var("CHONKLINE_LIVENESS_TICK_SECS");
}

#[test]
fn a_server_mask_broadcast_requires_operator() {
    // PRIVMSG $<mask> fans one command out to every user on the server. Any
    // registered client could do this: a broadcast and memory amplifier.
    let addr = start_proxied_server();

    let mut c = Client::new(&addr);
    c.send("PROXY TCP4 203.0.113.81 10.0.0.1 46001 6667");
    c.send("NICK masker");
    c.send("USER masker 0 * :Masker");
    c.read_until(|l| l.contains(" 001 "));
    c.send("PRIVMSG $** :broadcast attempt");

    // Predicate must not match the 005 burst, which now advertises TARGMAX=PRIVMSG:4.
    let line = c.read_until(|l| l.contains(" 481 ") || l.contains(" 401 "));
    assert!(line.contains(" 481 "), "non-oper server-mask broadcast must be refused: {line:?}");
}

#[test]
fn a_quiet_user_cannot_be_evicted_by_a_stranger() {
    // The reclaim silence window defaulted to zero, so anyone quiet for a
    // second looked "stale" and any socket -- including an unregistered one --
    // could force a ping and evict them 3s later. A 12-byte line every three
    // seconds was a targeted disconnect loop against any named user.
    let addr = start_proxied_server();

    let mut victim = Client::new(&addr);
    victim.send("PROXY TCP4 203.0.113.90 10.0.0.1 47000 6667");
    victim.send("NICK quietuser");
    victim.send("USER quietuser 0 * :Quiet");
    victim.read_until(|l| l.contains(" 001 "));

    std::thread::sleep(std::time::Duration::from_millis(1500));

    // An unregistered stranger contests the nick.
    let mut attacker = Client::new(&addr);
    attacker.send("PROXY TCP4 203.0.113.91 10.0.0.1 47001 6667");
    attacker.send("NICK quietuser");
    attacker.send("USER thief 0 * :Thief");

    // The nick is in use and must stay that way.
    let line = attacker.read_until(|l| l.contains(" 433 ") || l.contains(" 001 "));
    assert!(
        !line.contains(" 001 "),
        "a stranger must not take a live user's nick: {line:?}"
    );
}

#[test]
fn a_single_line_cannot_name_the_same_target_many_times() {
    // One 512-byte line naming a victim 161 times produced 161 deliveries, and
    // both flood tiers charged it as a single message. That multiplier is what
    // made the CTCP reflection flood effective.
    let addr = start_proxied_server();

    let mut victim = Client::new(&addr);
    victim.send("PROXY TCP4 203.0.113.92 10.0.0.1 47002 6667");
    victim.send("NICK target");
    victim.send("USER target 0 * :Target");
    victim.read_until(|l| l.contains(" 001 "));

    let mut sender = Client::new(&addr);
    sender.send("PROXY TCP4 203.0.113.93 10.0.0.1 47003 6667");
    sender.send("NICK sender");
    sender.send("USER sender 0 * :Sender");
    sender.read_until(|l| l.contains(" 001 "));

    // Distinct targets: identical ones de-duplicate to a single delivery, which
    // is the other half of the fix and correctly never reaches the cap.
    let many: String = (0..40).map(|i| format!("nick{}", i)).collect::<Vec<_>>().join(",");
    sender.send(&format!("PRIVMSG {} :amplified", many));

    // The first MAX_TARGETS entries are delivered (each 401, they do not exist)
    // and the 407 follows, so skip past the 401s.
    let reply = sender.read_until(|l| l.contains(" 407 "));
    assert!(reply.contains(" 407 "), "an oversized target list must be refused: {reply:?}");
}

#[test]
fn identical_targets_collapse_to_one_delivery() {
    // The other half of the amplification fix: naming the same victim many
    // times in one line must cost one delivery, not many.
    let addr = start_proxied_server();

    let mut victim = Client::new(&addr);
    victim.send("PROXY TCP4 203.0.113.94 10.0.0.1 47004 6667");
    victim.send("NICK dupetarget");
    victim.send("USER dupetarget 0 * :Target");
    victim.read_until(|l| l.contains(" 001 "));

    let mut sender = Client::new(&addr);
    sender.send("PROXY TCP4 203.0.113.95 10.0.0.1 47005 6667");
    sender.send("NICK dupesender");
    sender.send("USER dupesender 0 * :Sender");
    sender.read_until(|l| l.contains(" 001 "));

    let many = vec!["dupetarget"; 40].join(",");
    sender.send(&format!("PRIVMSG {} :once please", many));
    sender.send("PRIVMSG dupetarget :marker");

    // The victim should see the amplified line once, then the marker -- not 40
    // copies before it.
    let first = victim.read_until(|l| l.contains("once please") || l.contains("marker"));
    assert!(first.contains("once please"), "expected the message: {first:?}");
    let second = victim.read_until(|l| l.contains("once please") || l.contains("marker"));
    assert!(
        second.contains("marker"),
        "duplicate targets must collapse; saw another copy instead: {second:?}"
    );
}

#[test]
fn operators_on_plus_s_receive_server_notices() {
    // +s parsed, stored and rendered in RPL_UMODEIS, but nothing ever sent a
    // notice -- so an operator had no in-band signal during an incident.
    let addr = start_proxied_server();

    let mut op = Client::new(&addr);
    op.send("PROXY TCP4 203.0.113.96 10.0.0.1 48000 6667");
    op.send("NICK watcher");
    op.send("USER watcher 0 * :Watcher");
    op.read_until(|l| l.contains(" 001 "));
    op.send("OPER oper secret");
    op.read_until(|l| l.contains(" 381 "));
    op.send("MODE watcher +s");

    // A second operator logging in is exactly the kind of event worth seeing.
    let mut other = Client::new(&addr);
    other.send("PROXY TCP4 203.0.113.97 10.0.0.1 48001 6667");
    other.send("NICK secondop");
    other.send("USER secondop 0 * :Second");
    other.read_until(|l| l.contains(" 001 "));
    other.send("OPER oper secret");

    let notice = op.read_until(|l| l.contains("*** Notice"));
    assert!(
        notice.contains("secondop") && notice.contains("operator"),
        "expected a server notice about the new operator: {notice:?}"
    );
}

#[test]
fn a_failed_oper_attempt_is_announced() {
    let addr = start_proxied_server();

    let mut op = Client::new(&addr);
    op.send("PROXY TCP4 203.0.113.98 10.0.0.1 48002 6667");
    op.send("NICK sentry");
    op.send("USER sentry 0 * :Sentry");
    op.read_until(|l| l.contains(" 001 "));
    op.send("OPER oper secret");
    op.read_until(|l| l.contains(" 381 "));
    op.send("MODE sentry +s");

    let mut attacker = Client::new(&addr);
    attacker.send("PROXY TCP4 203.0.113.99 10.0.0.1 48003 6667");
    attacker.send("NICK guesser");
    attacker.send("USER guesser 0 * :Guesser");
    attacker.read_until(|l| l.contains(" 001 "));
    attacker.send("OPER oper wrongpassword");

    let notice = op.read_until(|l| l.contains("*** Notice"));
    assert!(
        notice.contains("Failed OPER"),
        "a failed OPER attempt must be announced: {notice:?}"
    );
}

#[test]
fn a_burst_of_commands_is_paced_not_discarded() {
    // Flood control used to drop the seventh message in a two-second window
    // silently, so a client joining several channels quickly simply lost some
    // of them with no feedback. Delaying throttles just as well and keeps the
    // work, which is what fakelag means.
    let addr = start_proxied_server();

    let mut c = Client::new(&addr);
    c.send("PROXY TCP4 203.0.113.120 10.0.0.1 49000 6667");
    c.send("NICK burster");
    c.send("USER burster 0 * :Burster");
    c.read_until(|l| l.contains(" 001 "));

    // Well past the six-per-two-seconds burst allowance, sent back to back.
    for i in 0..10 {
        c.send(&format!("JOIN #burst{}", i));
    }

    // Every join must eventually land. The last one is the one that used to be
    // thrown away.
    let last = c.read_until(|l| l.contains("#burst9"));
    assert!(
        last.contains("#burst9"),
        "the tenth join must arrive rather than be dropped: {last:?}"
    );
}
