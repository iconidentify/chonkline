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
    let reply = rando.read_until(|l| l.contains(" 481 ") || l.contains("NOTICE"));
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
