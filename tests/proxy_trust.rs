//! PROXY headers are only trusted from configured peers.
//!
//! A header is only as trustworthy as the path it arrived on. On Kubernetes a
//! `type: LoadBalancer` Service also opens a NodePort on every node's public
//! address, so the balancer can be bypassed by anyone who scans for it -- and a
//! bypasser writes their own header, naming any source they like.

mod common;
use common::*;

fn start_trusting(trusted: &str) -> String {
    std::env::set_var("IRC_PROXY_PROTOCOL", "1");
    std::env::set_var("IRC_PROXY_PROTOCOL_EXEMPT", "");
    std::env::set_var("IRC_PROXY_TRUSTED", trusted);
    std::env::set_var("IRC_CLOAK_SUFFIX", "users.test");
    start_server()
}

#[test]
fn a_header_from_an_untrusted_peer_is_refused() {
    // Our test client connects from loopback; trust only something else.
    let addr = start_trusting("10.9.9.9");

    let mut c = Client::new(&addr);
    c.send("PROXY TCP4 203.0.113.77 10.0.0.1 1 6667");
    c.send("NICK forger");
    c.send("USER forger 0 * :Forger");

    let line = c.read_until(|l| l.contains("ERROR") || l.contains(" 001 "));
    assert!(
        line.contains("ERROR"),
        "a header from an untrusted peer must be refused, got {line:?}"
    );
    std::env::remove_var("IRC_PROXY_TRUSTED");
}

#[test]
fn a_header_from_a_trusted_peer_is_accepted() {
    let addr = start_trusting("127.0.0.1,::1");

    let mut c = Client::new(&addr);
    c.send("PROXY TCP4 203.0.113.78 10.0.0.1 1 6667");
    c.send("NICK legit");
    c.send("USER legit 0 * :Legit");

    let line = c.read_until(|l| l.contains(" 001 ") || l.contains("ERROR"));
    assert!(line.contains(" 001 "), "a trusted peer must be accepted, got {line:?}");
    std::env::remove_var("IRC_PROXY_TRUSTED");
}

#[test]
fn an_unset_allowlist_trusts_any_peer() {
    // Backwards compatible: an existing deployment that has not set this keeps
    // working, and is told to set it in the manifest and at the firewall.
    std::env::remove_var("IRC_PROXY_TRUSTED");
    std::env::set_var("IRC_PROXY_PROTOCOL", "1");
    std::env::set_var("IRC_PROXY_PROTOCOL_EXEMPT", "");
    let addr = start_server();

    let mut c = Client::new(&addr);
    c.send("PROXY TCP4 203.0.113.79 10.0.0.1 1 6667");
    c.send("NICK anypeer");
    c.send("USER anypeer 0 * :Any");
    let line = c.read_until(|l| l.contains(" 001 ") || l.contains("ERROR"));
    assert!(line.contains(" 001 "));
}

#[test]
fn an_untrusted_peer_is_refused_with_or_without_a_header() {
    // The production shape: IRC_PROXY_PROTOCOL=1 is Required mode, and the
    // Service uses externalTrafficPolicy: Local so a bypasser arrives as
    // themselves rather than as the node. Both doors must be shut -- no header
    // is refused by the mode, a header is refused by the allowlist. Together
    // they leave a NodePort bypasser with nothing to say.
    let addr = start_trusting("192.168.*");

    let mut with_header = Client::new(&addr);
    with_header.send("PROXY TCP4 203.0.113.80 10.0.0.1 1 6667");
    with_header.send("NICK a");
    with_header.send("USER a 0 * :A");
    let l = with_header.read_until(|l| l.contains("ERROR") || l.contains(" 001 "));
    assert!(l.contains("ERROR"), "header from untrusted peer must be refused, got {l:?}");

    let mut no_header = Client::new(&addr);
    no_header.send("NICK b");
    no_header.send("USER b 0 * :B");
    let l = no_header.read_until(|l| l.contains("ERROR") || l.contains(" 001 "));
    assert!(l.contains("ERROR"), "required mode must refuse a missing header, got {l:?}");

    std::env::remove_var("IRC_PROXY_TRUSTED");
}
