//! The TLS sidecar path: ghostunnel terminates TLS in the same pod and forwards
//! to the daemon over loopback *without* emitting a PROXY header (its
//! `--proxy-protocol` flag emits v2 to a backend, it does not accept one
//! inbound). Requiring a header unconditionally would therefore fail every TLS
//! user closed the moment PROXY support was enabled.
//!
//! Its own test binary: this suite needs the default loopback exemption, while
//! tests/hardening.rs deliberately clears it.

mod common;
use common::*;

fn start_sidecar_server() -> String {
    std::env::set_var("IRC_PROXY_PROTOCOL", "1");
    std::env::remove_var("IRC_PROXY_PROTOCOL_EXEMPT"); // default: loopback exempt
    start_server()
}

#[test]
fn loopback_is_admitted_without_a_proxy_header() {
    let addr = start_sidecar_server();

    let mut c = Client::new(&addr);
    c.send("NICK tlsuser"); // arrives over loopback, exactly as the sidecar does
    c.send("USER tlsuser 0 * :Via Sidecar");

    let line = c.read_until(|l| l.contains(" 001 ") || l.contains("ERROR"));
    assert!(
        line.contains(" 001 "),
        "a loopback peer must be admitted without a PROXY header, got {line:?}"
    );
}

#[test]
fn a_loopback_client_may_still_present_a_header() {
    // Should a future sidecar learn to forward the original address, the
    // exemption must not stop the daemon from honouring it.
    let addr = start_sidecar_server();

    let mut c = Client::new(&addr);
    c.send("NICK hdruser");
    c.send("USER hdruser 0 * :With Header");
    let line = c.read_until(|l| l.contains(" 001 ") || l.contains("ERROR"));
    assert!(line.contains(" 001 "), "expected registration, got {line:?}");
}
