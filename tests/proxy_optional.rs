//! Optional (cutover) PROXY mode.
//!
//! While a proxy is not yet prepending its own header, requiring one would
//! refuse every connection. Optional mode bridges that gap: a header is used
//! when present and `peer_addr()` is used when absent.
//!
//! This is deliberately temporary. Until the proxy sends the header first, a
//! client can forge one and choose its own apparent address; once the proxy
//! prepends, a forged line lands after it and parses harmlessly as an IRC
//! command.

mod common;
use common::*;

fn start_optional_server() -> String {
    std::env::set_var("IRC_PROXY_PROTOCOL", "optional");
    std::env::remove_var("IRC_PROXY_PROTOCOL_EXEMPT");
    std::env::set_var("IRC_CLOAK_SUFFIX", "users.test");
    start_server()
}

#[test]
fn a_client_without_a_header_is_admitted() {
    let addr = start_optional_server();

    let mut c = Client::new(&addr);
    c.send("NICK plainuser");
    c.send("USER plainuser 0 * :No Header");

    let line = c.read_until(|l| l.contains(" 001 ") || l.contains("ERROR"));
    assert!(line.contains(" 001 "), "optional mode must admit a headerless client, got {line:?}");
}

#[test]
fn a_client_with_a_header_still_gets_that_address() {
    let addr = start_optional_server();

    let mut c = Client::new(&addr);
    c.send("PROXY TCP4 203.0.113.42 10.0.0.1 40000 6667");
    c.send("NICK hdruser");
    c.send("USER hdruser 0 * :With Header");
    c.read_until(|l| l.contains(" 001 "));
    c.send("JOIN #optional");

    let echo = c.read_until(|l| l.contains("JOIN") && l.contains("hdruser"));
    let cloak = echo.split('@').nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or_default();

    // The header is honoured, so this client's cloak is derived from
    // 203.0.113.42 rather than from the loopback peer address.
    let mut plain = Client::new(&addr);
    plain.send("NICK plainuser2");
    plain.send("USER plainuser2 0 * :No Header");
    plain.read_until(|l| l.contains(" 001 "));
    plain.send("JOIN #optional");
    let plain_echo = plain.read_until(|l| l.contains("JOIN") && l.contains("plainuser2"));
    let plain_cloak = plain_echo.split('@').nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or_default();

    assert!(!cloak.is_empty() && !plain_cloak.is_empty(), "both should report a cloak");
    assert_ne!(
        cloak, plain_cloak,
        "a header-supplied address must produce a different cloak from the raw peer address"
    );
}
