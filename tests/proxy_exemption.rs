//! The PROXY-header exemption list.
//!
//! TLS is terminated in-process, so nothing legitimately reaches the daemon
//! over loopback and the header is required from every peer by default. The
//! exemption exists only for deployments that still front the daemon with a
//! local terminator unable to emit one — and those peers necessarily share a
//! single cloak, because their real address never arrives.
//!
//! Its own test binary: this suite needs a different exemption environment from
//! the other suites.

mod common;
use common::*;

#[test]
fn loopback_is_not_exempt_by_default() {
    std::env::set_var("IRC_PROXY_PROTOCOL", "1");
    std::env::remove_var("IRC_PROXY_PROTOCOL_EXEMPT");
    let addr = start_server();

    // Fails closed: without this, anything able to reach the pod's loopback
    // would bypass the header and be cloaked from the wrong address.
    let mut c = Client::new(&addr);
    c.send("NICK loopuser");
    c.send("USER loopuser 0 * :No Header");

    let line = c.read_until(|l| l.contains("ERROR") || l.contains(" 001 "));
    assert!(
        line.contains("ERROR"),
        "a loopback peer must still need a PROXY header by default, got {line:?}"
    );
}

#[test]
fn an_explicitly_exempted_peer_is_admitted() {
    std::env::set_var("IRC_PROXY_PROTOCOL", "1");
    std::env::set_var("IRC_PROXY_PROTOCOL_EXEMPT", "127.0.0.1,::1");
    let addr = start_server();

    let mut c = Client::new(&addr);
    c.send("NICK exemptuser");
    c.send("USER exemptuser 0 * :Exempted");

    let line = c.read_until(|l| l.contains(" 001 ") || l.contains("ERROR"));
    assert!(
        line.contains(" 001 "),
        "an explicitly exempted peer must be admitted without a header, got {line:?}"
    );
}
