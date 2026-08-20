//! In-process TLS termination for the client listener.
//!
//! Previously TLS was terminated by a ghostunnel sidecar which forwarded
//! plaintext over loopback. That sidecar cannot forward the original client
//! address — its `--proxy-protocol` flag *emits* a v2 header to a backend
//! rather than accepting one inbound — so every TLS user reached the daemon as
//! `127.0.0.1` and shared a single cloak, with no attribution and no per-user
//! bans.
//!
//! Terminating here fixes that: the PROXY header arrives ahead of the TLS
//! handshake on the raw TCP stream (see `crate::proxyproto`), so the real
//! address is known before any decryption and feeds the same cloak, ban and
//! limit paths as the plaintext port.
//!
//! PEM parsing is done in-tree against the existing base64 decoder rather than
//! pulling in another dependency.

use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Extract every base64 body carrying `label` from a PEM document.
///
/// A cert file routinely holds a chain, so all matching blocks are returned in
/// order (leaf first, as issuers write them).
fn pem_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {}-----", label);
    let end = format!("-----END {}-----", label);
    let mut out = Vec::new();
    let mut rest = pem;

    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let Some(stop) = after.find(&end) else { break };
        if let Some(der) = crate::crypto::base64_decode(&after[..stop]) {
            if !der.is_empty() {
                out.push(der);
            }
        }
        rest = &after[stop + end.len()..];
    }
    out
}

/// Parse a private key in any of the three encodings issuers emit.
fn parse_key(pem: &str) -> Option<PrivateKeyDer<'static>> {
    if let Some(der) = pem_blocks(pem, "PRIVATE KEY").into_iter().next() {
        return Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)));
    }
    if let Some(der) = pem_blocks(pem, "RSA PRIVATE KEY").into_iter().next() {
        return Some(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)));
    }
    if let Some(der) = pem_blocks(pem, "EC PRIVATE KEY").into_iter().next() {
        return Some(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)));
    }
    None
}

/// Build an acceptor from PEM files on disk (`IRC_TLS_CERT` / `IRC_TLS_KEY`),
/// which in the cluster are the projected `tls.crt` / `tls.key` of the
/// cert-manager secret.
pub fn acceptor_from_files(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, String> {
    // Only the ring provider is compiled in; installing it explicitly keeps the
    // failure legible if that ever changes.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|e| format!("cannot read certificate {}: {}", cert_path, e))?;
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|e| format!("cannot read private key {}: {}", key_path, e))?;

    let chain: Vec<CertificateDer<'static>> = pem_blocks(&cert_pem, "CERTIFICATE")
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if chain.is_empty() {
        return Err(format!("no CERTIFICATE block in {}", cert_path));
    }
    let key = parse_key(&key_pem).ok_or_else(|| format!("no usable private key in {}", key_path))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("certificate and key do not form a valid pair: {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Resolve the TLS listener configuration from the environment. Returns `None`
/// when TLS is not configured, which is not an error: the plaintext port runs
/// on its own.
pub fn configured() -> Option<(u16, String, String)> {
    let port: u16 = std::env::var("IRC_TLS_PORT").ok().and_then(|v| v.parse().ok())?;
    if port == 0 {
        return None;
    }
    let cert = std::env::var("IRC_TLS_CERT").unwrap_or_else(|_| "/certs/tls.crt".to_string());
    let key = std::env::var("IRC_TLS_KEY").unwrap_or_else(|_| "/certs/tls.key".to_string());
    Some((port, cert, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_a_single_block() {
        let pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_blocks(pem, "CERTIFICATE"), vec![b"ABC".to_vec()]);
    }

    #[test]
    fn extracts_a_full_chain_in_order() {
        // Issuers ship leaf + intermediate in one file; both must survive.
        let pem = concat!(
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nWFla\n-----END CERTIFICATE-----\n"
        );
        assert_eq!(pem_blocks(pem, "CERTIFICATE"), vec![b"ABC".to_vec(), b"XYZ".to_vec()]);
    }

    #[test]
    fn tolerates_surrounding_noise_and_wrapped_lines() {
        let pem = concat!(
            "issued by Test CA\n",
            "-----BEGIN CERTIFICATE-----\nQU\nJD\n-----END CERTIFICATE-----\n",
            "trailing commentary\n"
        );
        assert_eq!(pem_blocks(pem, "CERTIFICATE"), vec![b"ABC".to_vec()]);
    }

    #[test]
    fn ignores_blocks_of_another_label() {
        let pem = "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n";
        assert!(pem_blocks(pem, "CERTIFICATE").is_empty());
    }

    #[test]
    fn unterminated_block_is_not_returned() {
        // A truncated file must fail cleanly rather than yield a partial key.
        let pem = "-----BEGIN CERTIFICATE-----\nQUJD\n";
        assert!(pem_blocks(pem, "CERTIFICATE").is_empty());
    }

    #[test]
    fn recognises_all_three_key_encodings() {
        assert!(matches!(
            parse_key("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----"),
            Some(PrivateKeyDer::Pkcs8(_))
        ));
        assert!(matches!(
            parse_key("-----BEGIN RSA PRIVATE KEY-----\nQUJD\n-----END RSA PRIVATE KEY-----"),
            Some(PrivateKeyDer::Pkcs1(_))
        ));
        assert!(matches!(
            parse_key("-----BEGIN EC PRIVATE KEY-----\nQUJD\n-----END EC PRIVATE KEY-----"),
            Some(PrivateKeyDer::Sec1(_))
        ));
        assert!(parse_key("no key here").is_none());
    }

    #[test]
    fn missing_files_report_which_path_failed() {
        // TlsAcceptor has no Debug impl, so match rather than unwrap_err.
        match acceptor_from_files("/nonexistent/tls.crt", "/nonexistent/tls.key") {
            Ok(_) => panic!("missing files must not yield an acceptor"),
            Err(err) => assert!(err.contains("/nonexistent/tls.crt"), "error should name the path: {err}"),
        }
    }

    #[test]
    fn tls_is_off_unless_a_port_is_set() {
        std::env::remove_var("IRC_TLS_PORT");
        assert!(configured().is_none());
    }
}
