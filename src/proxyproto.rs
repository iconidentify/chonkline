//! PROXY protocol v1 (HAProxy) support for the client listener.
//!
//! The ingress terminates the client's TCP connection and opens a new one to
//! this server, so `peer_addr()` reports the ingress rather than the client.
//! Behind a single ingress that address is identical for every client, which
//! collapses every derived identity — cloaks, bans, per-source limits — onto one
//! value. The ingress forwards the original address in a PROXY protocol header;
//! this module reads it back off the wire.
//!
//! Only v1 (the human-readable form) is implemented, because that is what
//! ingress-nginx emits. A v2 (binary) header is detected and rejected rather
//! than misparsed.

use tokio::io::AsyncReadExt;

/// RFC-equivalent maximum for a v1 header line including CR-LF: an unknown-
/// protocol line with two IPv6 addresses and two ports cannot exceed this.
pub const MAX_V1_HEADER: usize = 107;

/// The v2 binary signature. Present only so it can be rejected explicitly.
const V2_SIGNATURE: &[u8] = b"\r\n\r\n\x00\r\nQUIT\n";

/// Outcome of inspecting a connection's first bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum Header {
    /// A well-formed v1 header carrying the original source address.
    Source(String),
    /// `PROXY UNKNOWN` — the sender declined to identify the peer. The
    /// connection is valid but carries no address.
    Unknown,
    /// Not a PROXY header, or one that cannot be trusted.
    Invalid,
    /// The peer closed without sending anything. A TCP health probe does
    /// exactly this, so it is a silent close rather than a rejection worth
    /// logging thousands of times a day.
    Empty,
}

/// Parse a complete v1 header line (without its CR-LF).
///
/// Grammar: `PROXY TCP4|TCP6|UNKNOWN <src> <dst> <sport> <dport>`.
pub fn parse_v1(line: &[u8]) -> Header {
    if line.starts_with(V2_SIGNATURE) {
        return Header::Invalid; // v2 is not supported; never guess at it
    }
    let text = match std::str::from_utf8(line) {
        Ok(t) => t,
        Err(_) => return Header::Invalid,
    };
    let rest = match text.strip_prefix("PROXY ") {
        Some(r) => r,
        None => return Header::Invalid,
    };

    let mut parts = rest.split(' ');
    let proto = match parts.next() {
        Some(p) => p,
        None => return Header::Invalid,
    };
    if proto == "UNKNOWN" {
        return Header::Unknown;
    }
    if proto != "TCP4" && proto != "TCP6" {
        return Header::Invalid;
    }

    let src = match parts.next() {
        Some(s) if !s.is_empty() => s,
        _ => return Header::Invalid,
    };
    // Remaining fields must be present and well-formed even though only the
    // source address is retained: a truncated header is a malformed one.
    let dst = parts.next();
    let sport = parts.next();
    let dport = parts.next();
    if dst.is_none() || sport.is_none() || dport.is_none() || parts.next().is_some() {
        return Header::Invalid;
    }
    for port in [sport, dport].into_iter().flatten() {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Header::Invalid;
        }
    }

    // The address must parse as the family the header claims, so a spoofed or
    // corrupt line cannot inject arbitrary text into cloaks or ban masks.
    let ok = match proto {
        "TCP4" => src.parse::<std::net::Ipv4Addr>().is_ok(),
        _ => src.parse::<std::net::Ipv6Addr>().is_ok(),
    };
    if !ok {
        return Header::Invalid;
    }
    Header::Source(src.to_string())
}

/// What the head of a connection looks like, without consuming it.
#[derive(Debug, PartialEq, Eq)]
pub enum Peek {
    /// Begins with the v1 signature: safe to read a header.
    Header,
    /// Something else — a TLS ClientHello, or an IRC command.
    Other,
    /// The peer closed without sending anything. A TCP health probe does
    /// exactly this, so it is a silent close rather than a rejection.
    Closed,
}

/// Inspect the first bytes of `sock` without consuming them.
///
/// This is what makes header handling safe on a TLS listener: reading a header
/// from a stream that turns out to carry a ClientHello would eat the handshake.
/// Peeking first means bytes are only taken when they really are a header.
pub async fn peek_is_header(sock: &tokio::net::TcpStream) -> Peek {
    const SIG: &[u8] = b"PROXY ";
    let mut buf = [0u8; 6];
    let mut seen = 0usize;

    // A short read is normal: loop until enough bytes to decide, or the peer
    // diverges from the signature, or it closes.
    for _ in 0..64 {
        match sock.peek(&mut buf[..]).await {
            Ok(0) => return if seen == 0 { Peek::Closed } else { Peek::Other },
            Ok(n) => {
                seen = n;
                let checked = n.min(SIG.len());
                if buf[..checked] != SIG[..checked] {
                    return Peek::Other; // diverged: definitely not a header
                }
                if n >= SIG.len() {
                    return Peek::Header;
                }
                // Matching so far but short; yield and look again.
                tokio::task::yield_now().await;
            }
            Err(_) => return if seen == 0 { Peek::Closed } else { Peek::Other },
        }
    }
    Peek::Other
}

/// Read and consume a v1 header from the head of `sock`.
///
/// Reads one byte at a time up to the CR-LF: the header must not be
/// over-consumed, because everything after it belongs to the IRC stream. This
/// costs at most `MAX_V1_HEADER` syscalls once per connection.
pub async fn read_v1<R>(sock: &mut R) -> Header
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line: Vec<u8> = Vec::with_capacity(MAX_V1_HEADER);
    let mut byte = [0u8; 1];
    loop {
        match sock.read(&mut byte).await {
            // EOF before the header completed. With nothing received at all this
            // is a health probe opening and closing, not a bad client.
            Ok(0) => return if line.is_empty() { Header::Empty } else { Header::Invalid },
            Ok(_) => {}
            Err(_) => return if line.is_empty() { Header::Empty } else { Header::Invalid },
        }
        line.push(byte[0]);

        if line.len() >= 2 && line[line.len() - 2] == b'\r' && line[line.len() - 1] == b'\n' {
            line.truncate(line.len() - 2);
            return parse_v1(&line);
        }
        if line.len() >= MAX_V1_HEADER {
            return Header::Invalid; // no terminator within the legal maximum
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_source() {
        let h = parse_v1(b"PROXY TCP4 203.0.113.7 10.2.1.11 54321 6667");
        assert_eq!(h, Header::Source("203.0.113.7".to_string()));
    }

    #[test]
    fn parses_ipv6_source() {
        let h = parse_v1(b"PROXY TCP6 2001:db8::1 2001:db8::2 54321 6667");
        assert_eq!(h, Header::Source("2001:db8::1".to_string()));
    }

    #[test]
    fn distinct_sources_stay_distinct() {
        let a = parse_v1(b"PROXY TCP4 203.0.113.7 10.2.1.11 1 6667");
        let b = parse_v1(b"PROXY TCP4 198.51.100.9 10.2.1.11 2 6667");
        assert_ne!(a, b, "two clients must not collapse to one address");
    }

    #[test]
    fn unknown_is_distinct_from_invalid() {
        assert_eq!(parse_v1(b"PROXY UNKNOWN"), Header::Unknown);
    }

    #[test]
    fn rejects_malformed() {
        // Family/address mismatch, truncation, junk, wrong family, and v2 all
        // fail closed rather than yielding an address.
        assert_eq!(parse_v1(b"PROXY TCP4 not-an-ip 10.2.1.11 1 2"), Header::Invalid);
        assert_eq!(parse_v1(b"PROXY TCP4 2001:db8::1 10.2.1.11 1 2"), Header::Invalid);
        assert_eq!(parse_v1(b"PROXY TCP4 203.0.113.7 10.2.1.11"), Header::Invalid);
        assert_eq!(parse_v1(b"NICK bob"), Header::Invalid);
        assert_eq!(parse_v1(b"PROXY TCP9 203.0.113.7 10.2.1.11 1 2"), Header::Invalid);
        assert_eq!(parse_v1(b"PROXY TCP4 203.0.113.7 10.2.1.11 1 x"), Header::Invalid);
        assert_eq!(parse_v1(V2_SIGNATURE), Header::Invalid);
    }

    #[tokio::test]
    async fn reads_header_without_consuming_the_stream() {
        let mut src: &[u8] = b"PROXY TCP4 203.0.113.7 10.2.1.11 54321 6667\r\nNICK bob\r\n";
        let h = read_v1(&mut src).await;
        assert_eq!(h, Header::Source("203.0.113.7".to_string()));
        // Everything after the header must remain for the IRC parser.
        assert_eq!(src, b"NICK bob\r\n");
    }

    #[tokio::test]
    async fn a_probe_that_sends_nothing_is_not_an_error() {
        // kubelet tcpSocket probes connect and close immediately; treating that
        // as a rejection would emit thousands of log events a day.
        let mut src: &[u8] = b"";
        assert_eq!(read_v1(&mut src).await, Header::Empty);
    }

    #[tokio::test]
    async fn a_truncated_header_is_still_invalid() {
        let mut src: &[u8] = b"PROXY TCP4 203.0.113.7";
        assert_eq!(read_v1(&mut src).await, Header::Invalid);
    }

    #[tokio::test]
    async fn overlong_header_is_rejected() {
        let mut long = b"PROXY TCP4 ".to_vec();
        long.extend(std::iter::repeat(b'9').take(MAX_V1_HEADER * 2));
        let mut src: &[u8] = &long;
        assert_eq!(read_v1(&mut src).await, Header::Invalid);
    }
}
