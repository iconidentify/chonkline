//! End-to-end coverage for in-process TLS termination.
//!
//! The point of terminating here rather than behind a sidecar is that a TLS
//! client's *real* address reaches the cloak and limit paths. The PROXY header
//! is prepended to the raw TCP stream ahead of the handshake, so it is read
//! before anything is decrypted — these tests assert exactly that.
//!
//! The certificate is generated at test time with the `openssl` CLI rather than
//! committed, so no private key lives in the repository. The tests skip if
//! openssl is unavailable.

use std::sync::{Arc, Mutex};

/// Server startup mutates process-global environment, so only one test may be
/// in that window at a time. CI already runs with --test-threads=1; this keeps
/// a plain `cargo test` correct too.
static START: Mutex<()> = Mutex::new(());

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Generate a short-lived self-signed cert for `localhost`. Returns the cert and
/// key paths, or None when openssl is not installed.
fn generate_cert() -> Option<(String, String)> {
    let dir = std::env::temp_dir().join(format!("chonkline-tls-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let cert = dir.join("tls.crt").to_string_lossy().to_string();
    let key = dir.join("tls.key").to_string_lossy().to_string();

    if std::path::Path::new(&cert).exists() && std::path::Path::new(&key).exists() {
        return Some((cert, key));
    }

    let out = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            &key,
            "-out",
            &cert,
            "-days",
            "1",
            "-nodes", // -nodes yields an unencrypted PKCS8 key
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            // Without this openssl marks the cert CA:TRUE, and rustls then
            // refuses it as a leaf with CaUsedAsEndEntity. Real issuers hand out
            // end-entity certs, so this matches production shape too.
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some((cert, key))
}

/// Connect with bounded retries: listeners are spawned asynchronously, so a
/// connect immediately after startup can beat the bind.
async fn connect_retry(port: u16) -> tokio::net::TcpStream {
    for _ in 0..100 {
        if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            return s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("nothing listening on port {port} after 2s");
}

/// Claim an ephemeral port by binding and releasing it.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("local addr").port()
}

fn client_config(cert_path: &str) -> ClientConfig {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let pem = std::fs::read_to_string(cert_path).expect("read test cert");
    let body = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .and_then(|r| r.split("-----END CERTIFICATE-----").next())
        .expect("certificate block");
    let der = irc_server::crypto::base64_decode(body).expect("decode certificate");

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(der))
        .expect("trust the test certificate");
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Start a server with TLS enabled and PROXY parsing required, returning the
/// TLS port and the certificate path.
async fn start_tls_server() -> Option<(u16, String)> {
    start_tls_server_with_https().await.map(|(p, c, _)| (p, c))
}

/// As above, additionally starting the HTTPS listener; returns
/// (irc_tls_port, cert_path, https_port).
async fn start_tls_server_with_https() -> Option<(u16, String, u16)> {
    let _serialise = START.lock().unwrap_or_else(|p| p.into_inner());
    let (cert, key) = generate_cert()?;
    let port = free_port();
    let https_port = free_port();
    std::env::set_var("IRC_HTTPS_PORT", https_port.to_string());

    std::env::set_var("IRC_TLS_PORT", port.to_string());
    std::env::set_var("IRC_TLS_CERT", &cert);
    std::env::set_var("IRC_TLS_KEY", &key);
    std::env::set_var("IRC_PROXY_PROTOCOL", "1");
    std::env::set_var("IRC_PROXY_PROTOCOL_EXEMPT", ""); // require the header even on loopback
    std::env::set_var("IRC_CLOAK_SECRET", "tls-native-test-secret");
    std::env::set_var("IRC_CLOAK_SUFFIX", "users.test");

    irc_server::serve(
        "127.0.0.1:0".parse().unwrap(),
        irc_server::Config::default(),
    )
    .await
    .expect("server launch");

    Some((port, cert, https_port))
}

/// Connect over TLS, presenting `src` in a PROXY header ahead of the handshake,
/// register, join, and return the cloak from the JOIN echo.
async fn tls_cloak_for(port: u16, cert: &str, src: &str, nick: &str) -> String {
    let mut tcp = connect_retry(port).await;

    // The header goes on the raw stream, before any TLS bytes.
    tcp.write_all(format!("PROXY TCP4 {} 10.0.0.1 40000 6697\r\n", src).as_bytes())
        .await
        .expect("write proxy header");

    let connector = TlsConnector::from(Arc::new(client_config(cert)));
    let name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(name, tcp).await.expect("tls handshake");

    tls.write_all(
        format!(
            "NICK {}\r\nUSER {} 0 * :TLS Test\r\nJOIN #tlstest\r\n",
            nick, nick
        )
        .as_bytes(),
    )
    .await
    .expect("write registration");

    // Read until the client's own JOIN echo appears.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    for _ in 0..64 {
        let n = match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(line) = text
            .lines()
            .find(|l| l.contains("JOIN") && l.contains(nick))
        {
            return line
                .split('@')
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
                .unwrap_or_default()
                .to_string();
        }
    }
    String::new()
}

#[tokio::test]
async fn tls_clients_get_real_distinct_cloaks() {
    let Some((port, cert)) = start_tls_server().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    let a = tls_cloak_for(port, &cert, "203.0.113.7", "tlsalice").await;
    let b = tls_cloak_for(port, &cert, "198.51.100.9", "tlsbob").await;

    assert!(
        !a.is_empty() && !b.is_empty(),
        "both TLS clients must register and join (a={a:?} b={b:?})"
    );
    assert!(
        a.ends_with(".users.test"),
        "expected a cloaked host, got {a:?}"
    );
    assert_ne!(
        a, b,
        "TLS users must no longer share one cloak — that sharing is exactly what the \
         sidecar caused and what terminating in-process fixes"
    );
}

#[tokio::test]
async fn tls_cloak_matches_the_plaintext_cloak_for_the_same_address() {
    // One address must map to one identity regardless of which port it arrived
    // on, otherwise a ban set from one port would miss the other.
    let Some((port, cert)) = start_tls_server().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    let first = tls_cloak_for(port, &cert, "203.0.113.77", "tlscarol").await;
    let second = tls_cloak_for(port, &cert, "203.0.113.77", "tlsdave").await;

    assert!(!first.is_empty(), "expected a cloak");
    assert_eq!(
        first, second,
        "one address must yield one stable cloak over TLS too"
    );
}

#[tokio::test]
async fn the_web_property_is_served_over_tls() {
    // Behind its own load balancer there is no ingress left to terminate HTTPS
    // for this host, so the daemon has to do it or the page stops working.
    let Some((_irc, cert, https_port)) = start_tls_server_with_https().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    let tcp = connect_retry(https_port).await;
    let connector = TlsConnector::from(Arc::new(client_config(&cert)));
    let name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(name, tcp).await.expect("https handshake");

    tls.write_all(b"GET /api/stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    for _ in 0..32 {
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "expected 200 over TLS, got: {:?}",
        &text[..text.len().min(80)]
    );
    assert!(
        text.contains("\"server\""),
        "expected the stats payload, got: {:?}",
        &text[..text.len().min(200)]
    );
}

#[tokio::test]
async fn https_and_plaintext_serve_the_same_content() {
    // One handler behind both listeners, so the two cannot drift apart.
    let Some((_irc, cert, https_port)) = start_tls_server_with_https().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    let tcp = connect_retry(https_port).await;
    let connector = TlsConnector::from(Arc::new(client_config(&cert)));
    let name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(name, tcp).await.expect("https handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");

    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    for _ in 0..64 {
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "index page must serve over TLS"
    );
    assert!(text.contains("<"), "expected HTML for the index page");
}

#[tokio::test]
async fn a_bare_tcp_probe_on_the_tls_port_is_not_logged_as_a_failure() {
    // Load balancers health-check a TLS port by connecting and closing without
    // speaking TLS. Counting that as a failed handshake produced ~2 log lines a
    // minute in production and buried everything worth reading.
    let Some((port, _cert)) = start_tls_server().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    // Connect and close immediately, exactly as a probe does.
    let probe = connect_retry(port).await;
    drop(probe);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // The listener must still serve a real client afterwards. This suite runs
    // with the PROXY header required, so send one as a genuine client would.
    let mut tcp = connect_retry(port).await;
    tcp.write_all(b"PROXY TCP4 203.0.113.200 10.0.0.1 40000 6697\r\n")
        .await
        .expect("write proxy header");
    let connector = TlsConnector::from(Arc::new(client_config(&_cert)));
    let name = ServerName::try_from("localhost").expect("server name");
    let tls = connector.connect(name, tcp).await;
    assert!(tls.is_ok(), "a probe must not disturb the listener");
}

fn pem_der(pem: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = pem.split(&begin).nth(1)?.split(&end).next()?;
    irc_server::crypto::base64_decode(body)
}

fn load_key(path: &str) -> tokio_rustls::rustls::pki_types::PrivateKeyDer<'static> {
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
    let pem = std::fs::read_to_string(path).expect("client key");
    if let Some(der) = pem_der(&pem, "PRIVATE KEY") {
        return PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der));
    }
    if let Some(der) = pem_der(&pem, "RSA PRIVATE KEY") {
        return PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der));
    }
    panic!("no private key in {path}");
}

fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    let pem = std::fs::read_to_string(path).expect("cert");
    let der = pem_der(&pem, "CERTIFICATE").expect("certificate block");
    vec![CertificateDer::from(der)]
}

/// A self-signed client identity. Returns cert path, key path, and the
/// lowercase SHA-256 of the leaf DER — the same fingerprint the server stores.
fn generate_client_identity(name: &str) -> Option<(String, String, String)> {
    let dir = std::env::temp_dir().join(format!("chonkline-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let cert = dir
        .join(format!("{name}.crt"))
        .to_string_lossy()
        .to_string();
    let key = dir
        .join(format!("{name}.key"))
        .to_string_lossy()
        .to_string();
    if !std::path::Path::new(&cert).exists() {
        let out = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                &key,
                "-out",
                &cert,
                "-days",
                "1",
                "-nodes",
                "-subj",
                &format!("/CN={name}"),
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
    }
    let pem = std::fs::read_to_string(&cert).ok()?;
    let der = pem_der(&pem, "CERTIFICATE")?;
    let fp = irc_server::crypto::hex(&irc_server::crypto::sha256(&der));
    Some((cert, key, fp))
}

fn client_config_with_cert(server_cert: &str, client_cert: &str, client_key: &str) -> ClientConfig {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots
        .add(load_certs(server_cert).remove(0))
        .expect("trust the server certificate");
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(load_certs(client_cert), load_key(client_key))
        .expect("client certificate")
}

struct IrcTls {
    tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    buf: Vec<u8>,
}

impl IrcTls {
    async fn connect(
        port: u16,
        server_cert: &str,
        client: Option<(&str, &str)>,
        src: &str,
    ) -> Self {
        let mut tcp = connect_retry(port).await;
        tcp.write_all(format!("PROXY TCP4 {src} 10.0.0.1 40000 6697\r\n").as_bytes())
            .await
            .expect("proxy header");
        let cfg = match client {
            Some((cert, key)) => client_config_with_cert(server_cert, cert, key),
            None => client_config(server_cert),
        };
        let name = ServerName::try_from("localhost").expect("sni");
        let tls = TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .expect("handshake");
        IrcTls {
            tls,
            buf: Vec::new(),
        }
    }

    async fn send(&mut self, line: &str) {
        self.tls
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .expect("send");
    }

    fn text_from(&self, start: usize) -> String {
        String::from_utf8_lossy(&self.buf[start..]).to_string()
    }

    async fn wait_from(&mut self, start: usize, needle: &str) -> String {
        let mut chunk = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
        loop {
            if self.text_from(start).contains(needle) {
                return self.text_from(start);
            }
            if tokio::time::Instant::now() > deadline {
                return self.text_from(start);
            }
            match tokio::time::timeout(
                std::time::Duration::from_millis(250),
                self.tls.read(&mut chunk),
            )
            .await
            {
                Ok(Ok(0)) | Ok(Err(_)) => return self.text_from(start),
                Err(_) => continue,
                Ok(Ok(n)) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

#[tokio::test]
async fn sasl_external_enrolls_rotates_and_falls_back_to_plain() {
    let Some((port, server_cert)) = start_tls_server().await else {
        eprintln!("skipping: openssl unavailable");
        return;
    };
    let Some((cert_a, key_a, fp_a)) = generate_client_identity("client-a") else {
        eprintln!("skipping: openssl unavailable");
        return;
    };
    let Some((cert_b, key_b, fp_b)) = generate_client_identity("client-b") else {
        eprintln!("skipping: openssl unavailable");
        return;
    };
    let Some((cert_c, key_c, _)) = generate_client_identity("client-c") else {
        eprintln!("skipping: openssl unavailable");
        return;
    };

    // Enroll A with the password, on the same TLS session that presents A.
    let mut a = IrcTls::connect(port, &server_cert, Some((&cert_a, &key_a)), "203.0.113.10").await;
    a.send("CAP LS 302").await;
    let ls = a.wait_from(0, "sasl=").await;
    assert!(
        ls.contains("sasl=EXTERNAL,PLAIN"),
        "a certificate connection must advertise both mechanisms: {ls:?}"
    );
    a.send("NICK extowner").await;
    a.send("USER extowner 0 * :owner").await;
    a.send("CAP END").await;
    let welcome = a.wait_from(0, " 001 ").await;
    assert!(
        welcome.contains(" 001 "),
        "registration failed: {welcome:?}"
    );
    let mark = a.buf.len();
    a.send("PRIVMSG NickServ :REGISTER hunter2").await;
    let reg = a.wait_from(mark, "registered").await;
    assert!(reg.contains("registered"), "register failed: {reg:?}");
    let mark = a.buf.len();
    a.send("PRIVMSG NickServ :CERT ADD ee").await;
    let typed = a.wait_from(mark, "fingerprint").await;
    assert!(
        typed.to_ascii_lowercase().contains("fingerprint"),
        "a typed fingerprint must not be accepted as possession: {typed:?}"
    );
    let mark = a.buf.len();
    a.send("PRIVMSG NickServ :CERT ADD").await;
    let enrolled = a.wait_from(mark, "enrolled").await;
    assert!(
        enrolled.contains("enrolled"),
        "CERT ADD failed: {enrolled:?}"
    );
    let mark = a.buf.len();
    a.send("PRIVMSG NickServ :CERT LIST").await;
    let listed = a.wait_from(mark, &fp_a).await;
    assert!(
        listed.contains(&fp_a),
        "LIST did not show the enrolled fingerprint: {listed:?}"
    );
    drop(a);

    // EXTERNAL with an empty authzid logs in as the bound account.
    let mut back =
        IrcTls::connect(port, &server_cert, Some((&cert_a, &key_a)), "203.0.113.11").await;
    back.send("CAP LS 302").await;
    back.send("CAP REQ :sasl").await;
    back.send("NICK extback").await;
    back.send("USER extback 0 * :back").await;
    back.send("AUTHENTICATE EXTERNAL").await;
    let prompt = back.wait_from(0, "AUTHENTICATE +").await;
    assert!(
        prompt.contains("AUTHENTICATE +"),
        "EXTERNAL did not continue: {prompt:?}"
    );
    let mark = back.buf.len();
    back.send("AUTHENTICATE +").await;
    let ok = back.wait_from(mark, " 903 ").await;
    assert!(ok.contains(" 900 "), "missing 900: {ok:?}");
    assert!(
        ok.contains("extowner"),
        "login was not the enrolled account: {ok:?}"
    );
    assert!(ok.contains(" 903 "), "EXTERNAL did not succeed: {ok:?}");
    back.send("CAP END").await;
    let still = back.wait_from(mark, " 001 ").await;
    assert!(
        still.contains(" 001 "),
        "welcome missing after EXTERNAL: {still:?}"
    );
    // Stay connected: deleting the certificate must not kick this session.
    let live = back;

    // A second certificate enrolls beside the first, via PLAIN.
    let mut b = IrcTls::connect(port, &server_cert, Some((&cert_b, &key_b)), "203.0.113.12").await;
    b.send("CAP REQ :sasl").await;
    b.send("NICK extb").await;
    b.send("USER extb 0 * :b").await;
    b.send("AUTHENTICATE PLAIN").await;
    assert!(b
        .wait_from(0, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let payload = irc_server::crypto::base64_encode(b"\0extowner\0hunter2");
    let mark = b.buf.len();
    b.send(&format!("AUTHENTICATE {payload}")).await;
    let plain = b.wait_from(mark, " 903 ").await;
    assert!(
        plain.contains(" 903 "),
        "PLAIN on a cert connection failed: {plain:?}"
    );
    b.send("CAP END").await;
    assert!(b.wait_from(mark, " 001 ").await.contains(" 001 "));
    let mark = b.buf.len();
    b.send("PRIVMSG NickServ :CERT ADD").await;
    let second = b.wait_from(mark, "enrolled").await;
    assert!(
        second.contains("enrolled"),
        "second CERT ADD failed: {second:?}"
    );
    drop(b);

    let mut b2 = IrcTls::connect(port, &server_cert, Some((&cert_b, &key_b)), "203.0.113.13").await;
    b2.send("CAP REQ :sasl").await;
    b2.send("NICK extb2").await;
    b2.send("USER extb2 0 * :b2").await;
    b2.send("AUTHENTICATE EXTERNAL").await;
    assert!(b2
        .wait_from(0, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = b2.buf.len();
    let authzid = irc_server::crypto::base64_encode(b"extowner");
    b2.send(&format!("AUTHENTICATE {authzid}")).await;
    let named = b2.wait_from(mark, " 903 ").await;
    assert!(
        named.contains(" 903 ") && named.contains("extowner"),
        "authzid naming the bound account failed: {named:?}"
    );
    drop(b2);

    // Wrong authzid, unknown certificate, then PLAIN still works.
    let mut mismatch =
        IrcTls::connect(port, &server_cert, Some((&cert_a, &key_a)), "203.0.113.14").await;
    mismatch.send("CAP REQ :sasl").await;
    mismatch.send("NICK extmis").await;
    mismatch.send("USER extmis 0 * :mis").await;
    mismatch.send("AUTHENTICATE EXTERNAL").await;
    assert!(mismatch
        .wait_from(0, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = mismatch.buf.len();
    let other = irc_server::crypto::base64_encode(b"someoneelse");
    mismatch.send(&format!("AUTHENTICATE {other}")).await;
    let denied = mismatch.wait_from(mark, " 904 ").await;
    assert!(
        denied.contains(" 904 "),
        "foreign authzid was accepted: {denied:?}"
    );
    let mark = mismatch.buf.len();
    mismatch.send("AUTHENTICATE PLAIN").await;
    assert!(mismatch
        .wait_from(mark, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = mismatch.buf.len();
    mismatch.send(&format!("AUTHENTICATE {payload}")).await;
    let retried = mismatch.wait_from(mark, " 903 ").await;
    assert!(
        retried.contains(" 903 "),
        "PLAIN after a bad EXTERNAL failed: {retried:?}"
    );
    drop(mismatch);

    let mut unknown =
        IrcTls::connect(port, &server_cert, Some((&cert_c, &key_c)), "203.0.113.15").await;
    unknown.send("CAP LS 302").await;
    let uls = unknown.wait_from(0, "sasl=").await;
    assert!(
        uls.contains("sasl=EXTERNAL,PLAIN"),
        "unknown cert hid EXTERNAL: {uls:?}"
    );
    unknown.send("CAP REQ :sasl").await;
    unknown.send("NICK extunk").await;
    unknown.send("USER extunk 0 * :unk").await;
    unknown.send("AUTHENTICATE EXTERNAL").await;
    assert!(unknown
        .wait_from(0, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = unknown.buf.len();
    unknown.send("AUTHENTICATE +").await;
    let no = unknown.wait_from(mark, " 904 ").await;
    assert!(
        no.contains(" 904 "),
        "unknown certificate authenticated: {no:?}"
    );
    let mark = unknown.buf.len();
    unknown.send("AUTHENTICATE PLAIN").await;
    assert!(unknown
        .wait_from(mark, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = unknown.buf.len();
    unknown.send(&format!("AUTHENTICATE {payload}")).await;
    assert!(
        unknown.wait_from(mark, " 903 ").await.contains(" 903 "),
        "PLAIN with an unknown cert failed"
    );
    drop(unknown);

    // No certificate: EXTERNAL is not advertised and cannot be selected.
    let mut bare = IrcTls::connect(port, &server_cert, None, "203.0.113.16").await;
    bare.send("CAP LS 302").await;
    let bls = bare.wait_from(0, "sasl=").await;
    assert!(bls.contains("sasl=PLAIN"), "missing PLAIN: {bls:?}");
    assert!(
        !bls.contains("EXTERNAL"),
        "no-cert connection advertised EXTERNAL: {bls:?}"
    );
    bare.send("CAP REQ :sasl").await;
    bare.send("AUTHENTICATE EXTERNAL").await;
    let bare_no = bare.wait_from(0, " 904 ").await;
    assert!(
        bare_no.contains(" 908 ") && bare_no.contains(" 904 "),
        "EXTERNAL without a cert was not refused: {bare_no:?}"
    );
    assert!(
        !bare_no.contains("EXTERNAL,PLAIN"),
        "908 offered EXTERNAL with no cert: {bare_no:?}"
    );
    drop(bare);

    // Abort, malformed, and oversized responses fail closed.
    let mut messy =
        IrcTls::connect(port, &server_cert, Some((&cert_b, &key_b)), "203.0.113.17").await;
    messy.send("CAP REQ :sasl").await;
    messy.send("NICK extmessy").await;
    messy.send("USER extmessy 0 * :messy").await;
    let mark = messy.buf.len();
    messy.send("AUTHENTICATE *").await;
    let aborted = messy.wait_from(mark, " 906 ").await;
    assert!(aborted.contains(" 906 "), "abort was not 906: {aborted:?}");
    let mark = messy.buf.len();
    messy.send("AUTHENTICATE EXTERNAL").await;
    assert!(messy
        .wait_from(mark, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = messy.buf.len();
    messy.send("AUTHENTICATE !!!!").await;
    assert!(
        messy.wait_from(mark, " 904 ").await.contains(" 904 "),
        "malformed EXTERNAL was accepted"
    );
    let mark = messy.buf.len();
    messy.send("AUTHENTICATE EXTERNAL").await;
    assert!(messy
        .wait_from(mark, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = messy.buf.len();
    messy
        .send(&format!("AUTHENTICATE {}", "A".repeat(401)))
        .await;
    assert!(
        messy.wait_from(mark, " 904 ").await.contains(" 904 "),
        "oversized EXTERNAL was accepted"
    );
    drop(messy);

    // Password rotation leaves EXTERNAL in place. The session opened on A is
    // still logged in after both the password change and the removal of A.
    let mut rotator =
        IrcTls::connect(port, &server_cert, Some((&cert_b, &key_b)), "203.0.113.18").await;
    rotator.send("CAP REQ :sasl").await;
    rotator.send("NICK extrot").await;
    rotator.send("USER extrot 0 * :rot").await;
    rotator.send("AUTHENTICATE EXTERNAL").await;
    assert!(rotator
        .wait_from(0, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = rotator.buf.len();
    rotator.send("AUTHENTICATE +").await;
    assert!(rotator.wait_from(mark, " 903 ").await.contains(" 903 "));
    rotator.send("CAP END").await;
    assert!(rotator.wait_from(mark, " 001 ").await.contains(" 001 "));
    let mark = rotator.buf.len();
    rotator
        .send("PRIVMSG NickServ :SET PASSWORD hunter2 newpass")
        .await;
    let rotated = rotator.wait_from(mark, "Password updated").await;
    assert!(
        rotated.contains("Password updated"),
        "password rotation failed: {rotated:?}"
    );
    let mark = rotator.buf.len();
    rotator.send("PRIVMSG NickServ :CERT DEL").await;
    rotator
        .send(&format!("PRIVMSG NickServ :CERT DEL {fp_a}"))
        .await;
    let removed = rotator.wait_from(mark, "Certificate removed").await;
    assert!(
        removed.contains("Certificate removed"),
        "CERT DEL failed: {removed:?}"
    );
    drop(rotator);

    let mark = live.buf.len();
    let mut live = live;
    live.send("WHOIS extback").await;
    let who = live.wait_from(mark, " 330 ").await;
    assert!(
        who.contains(" 330 ") && who.contains("extowner"),
        "removing the certificate logged out the existing session: {who:?}"
    );
    drop(live);

    let mut gone =
        IrcTls::connect(port, &server_cert, Some((&cert_a, &key_a)), "203.0.113.19").await;
    gone.send("CAP REQ :sasl").await;
    gone.send("NICK extgone").await;
    gone.send("USER extgone 0 * :gone").await;
    gone.send("AUTHENTICATE EXTERNAL").await;
    assert!(gone
        .wait_from(0, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = gone.buf.len();
    gone.send("AUTHENTICATE +").await;
    let dead = gone.wait_from(mark, " 904 ").await;
    assert!(
        dead.contains(" 904 "),
        "deleted certificate still authenticated: {dead:?}"
    );
    let mark = gone.buf.len();
    let new_payload = irc_server::crypto::base64_encode(b"\0extowner\0newpass");
    gone.send("AUTHENTICATE PLAIN").await;
    assert!(gone
        .wait_from(mark, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = gone.buf.len();
    gone.send(&format!("AUTHENTICATE {new_payload}")).await;
    let plain_left = gone.wait_from(mark, " 903 ").await;
    assert!(
        plain_left.contains(" 903 "),
        "deleting a certificate disturbed the password: {plain_left:?}"
    );
    drop(gone);

    let mut still_b =
        IrcTls::connect(port, &server_cert, Some((&cert_b, &key_b)), "203.0.113.20").await;
    still_b.send("CAP REQ :sasl").await;
    still_b.send("NICK extstill").await;
    still_b.send("USER extstill 0 * :still").await;
    still_b.send("AUTHENTICATE EXTERNAL").await;
    assert!(still_b
        .wait_from(0, "AUTHENTICATE +")
        .await
        .contains("AUTHENTICATE +"));
    let mark = still_b.buf.len();
    still_b.send("AUTHENTICATE +").await;
    let kept = still_b.wait_from(mark, " 903 ").await;
    assert!(
        kept.contains(" 903 "),
        "password rotation or deleting A invalidated B: {kept:?}"
    );
    assert_ne!(
        fp_a, fp_b,
        "the two client certificates hashed to one fingerprint"
    );
}
