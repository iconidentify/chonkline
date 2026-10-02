//! Services account store: registered accounts with PBKDF2-hashed passwords,
//! persisted to a simple line-based file so identities survive restarts.
//!
//! Format (one account per line, tab-separated):
//!   <name>\t<iters>\t<base64 salt>\t<base64 hash>[\t<fp>[,<fp>...]]
//!
//! The fifth field is optional and holds SHA-256 certificate fingerprints
//! (lowercase hex, comma-separated). Lines written before certificates
//! existed have four fields and still load. Passwords are never stored; only
//! a PBKDF2-HMAC-SHA256 derivation with a per-account random salt. Account
//! names are keyed case-insensitively via the same folding used for nicknames.
//! A fingerprint maps to at most one account.

use std::collections::HashMap;
use std::io::{Read, Write};

use crate::crypto::{base64_decode, base64_encode, constant_time_eq, pbkdf2_sha256};
use crate::state::norm_nick;

const ITERS: u32 = 100_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
/// Overlap room for a rotation: the old fingerprint stays valid while the new
/// one is enrolled and checked. Eight is enough for that plus spares.
pub const MAX_CERTS_PER_ACCOUNT: usize = 8;

struct Account {
    name: String, // display form
    salt: Vec<u8>,
    hash: Vec<u8>,
    iters: u32,
    /// Lowercase hex SHA-256 fingerprints, unique within the account.
    certs: Vec<String>,
}

/// Result of enrolling a fingerprint that was not already on the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertAdd {
    Enrolled,
    Already,
}

pub struct AccountStore {
    path: Option<String>,
    map: HashMap<String, Account>, // key = norm_nick(name)
    /// Fingerprint -> account key. One fingerprint, one account.
    by_cert: HashMap<String, String>,
}

/// Normalize a certificate fingerprint to lowercase hex.
///
/// Accepts the stored form and the colon-separated form people paste. Anything
/// that is not 32 bytes of hex is rejected, so a nickname or a free-text claim
/// cannot be stored as a credential.
pub fn normalize_cert_fingerprint(raw: &str) -> Option<String> {
    let hex: String = raw
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

/// 16 bytes of OS entropy for a fresh salt; falls back to a time/address-seeded
/// digest if /dev/urandom is somehow unavailable.
fn random_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_LEN];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut salt).is_ok() {
            return salt;
        }
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!("{}-{}-{:p}", t, std::process::id(), &salt as *const _);
    crate::crypto::sha256(seed.as_bytes())[..SALT_LEN].to_vec()
}

impl AccountStore {
    /// Load the store from `path` (from IRC_ACCOUNTS_PATH). A missing file is an
    /// empty store; a missing path means in-memory only (no persistence).
    pub fn load(path: Option<String>) -> Self {
        let mut map = HashMap::new();
        let mut by_cert = HashMap::new();
        if let Some(p) = &path {
            if let Ok(contents) = std::fs::read_to_string(p) {
                for line in contents.lines() {
                    if let Some(mut acct) = parse_line(line) {
                        let key = norm_nick(&acct.name);
                        // First binding wins. A later line that repeats a
                        // fingerprint keeps its password and loses that print.
                        acct.certs.retain(|fp| {
                            if by_cert.contains_key(fp) {
                                return false;
                            }
                            by_cert.insert(fp.clone(), key.clone());
                            true
                        });
                        map.insert(key, acct);
                    }
                }
            }
        }
        AccountStore { path, map, by_cert }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.map.contains_key(&norm_nick(name))
    }

    pub fn count(&self) -> usize {
        self.map.len()
    }

    /// Register a new account. Fails if the name is already taken. Persists on
    /// success (best effort: an unwritable path keeps the account in memory).
    pub fn register(&mut self, name: &str, pass: &str) -> Result<(), &'static str> {
        let key = norm_nick(name);
        if key.is_empty() {
            return Err("invalid account name");
        }
        if crate::state::is_service_name(&key) {
            return Err("that name is reserved");
        }
        if self.map.contains_key(&key) {
            return Err("account already registered");
        }
        if pass.is_empty() {
            return Err("password required");
        }
        let salt = random_salt();
        let hash = pbkdf2_sha256(pass.as_bytes(), &salt, ITERS, HASH_LEN);
        self.map.insert(
            key,
            Account {
                name: name.to_string(),
                salt,
                hash,
                iters: ITERS,
                certs: Vec::new(),
            },
        );
        let _ = self.save();
        Ok(())
    }

    /// Replace the password of an existing account. A fresh salt is used, so a
    /// captured old hash cannot be replayed against the new password. The
    /// caller has to decide who is allowed to ask (an identified session, and
    /// usually the current password).
    pub fn set_password(&mut self, name: &str, new_pass: &str) -> Result<(), &'static str> {
        let key = norm_nick(name);
        if new_pass.is_empty() {
            return Err("password required");
        }
        let salt = random_salt();
        let hash = pbkdf2_sha256(new_pass.as_bytes(), &salt, ITERS, HASH_LEN);
        {
            let Some(acct) = self.map.get_mut(&key) else {
                return Err("account not registered");
            };
            acct.salt = salt;
            acct.hash = hash;
            acct.iters = ITERS;
            // Certificate bindings are a separate credential. Rotating the
            // password must not drop or rewrite them.
        }
        let _ = self.save();
        Ok(())
    }

    /// Fingerprints enrolled on this account, in enrollment order.
    pub fn certs_of(&self, name: &str) -> Option<Vec<String>> {
        self.map.get(&norm_nick(name)).map(|a| a.certs.clone())
    }

    /// Display name of the single account bound to this fingerprint.
    pub fn account_for_cert(&self, fp: &str) -> Option<String> {
        let fp = normalize_cert_fingerprint(fp)?;
        let key = self.by_cert.get(&fp)?;
        self.map.get(key).map(|a| a.name.clone())
    }

    /// Bind a fingerprint to an existing account.
    ///
    /// The caller has already proved possession (the fingerprint came from the
    /// TLS handshake, not from text the client typed). Fails without changing
    /// memory when the binding cannot be saved.
    pub fn add_cert(&mut self, name: &str, fp: &str) -> Result<CertAdd, &'static str> {
        let key = norm_nick(name);
        let fp = normalize_cert_fingerprint(fp).ok_or("invalid fingerprint")?;
        if !self.map.contains_key(&key) {
            return Err("account not registered");
        }
        if let Some(owner) = self.by_cert.get(&fp) {
            if owner == &key {
                return Ok(CertAdd::Already);
            }
            return Err("certificate belongs to another account");
        }
        {
            let acct = self.map.get_mut(&key).expect("account checked above");
            if acct.certs.len() >= MAX_CERTS_PER_ACCOUNT {
                return Err("certificate limit reached");
            }
            acct.certs.push(fp.clone());
        }
        self.by_cert.insert(fp.clone(), key.clone());
        if self.save().is_err() {
            if let Some(acct) = self.map.get_mut(&key) {
                acct.certs.retain(|c| c != &fp);
            }
            self.by_cert.remove(&fp);
            return Err("could not save account store");
        }
        Ok(CertAdd::Enrolled)
    }

    /// Remove one fingerprint from an account. The password and every other
    /// fingerprint stay. Does not touch live sessions; the caller decides that.
    pub fn remove_cert(&mut self, name: &str, fp: &str) -> Result<(), &'static str> {
        let key = norm_nick(name);
        let fp = normalize_cert_fingerprint(fp).ok_or("invalid fingerprint")?;
        let Some(acct) = self.map.get_mut(&key) else {
            return Err("account not registered");
        };
        let Some(pos) = acct.certs.iter().position(|c| c == &fp) else {
            return Err("no such certificate");
        };
        acct.certs.remove(pos);
        self.by_cert.remove(&fp);
        if self.save().is_err() {
            if let Some(acct) = self.map.get_mut(&key) {
                acct.certs.insert(pos, fp.clone());
            }
            self.by_cert.insert(fp, key);
            return Err("could not save account store");
        }
        Ok(())
    }

    /// Verify a password against a registered account (constant-time compare).
    pub fn verify(&self, name: &str, pass: &str) -> bool {
        match self.map.get(&norm_nick(name)) {
            None => false,
            Some(acct) => {
                let candidate =
                    pbkdf2_sha256(pass.as_bytes(), &acct.salt, acct.iters, acct.hash.len());
                constant_time_eq(&candidate, &acct.hash)
            }
        }
    }

    /// Canonical display name for a registered account, if present.
    pub fn display_name(&self, name: &str) -> Option<String> {
        self.map.get(&norm_nick(name)).map(|a| a.name.clone())
    }

    /// Atomic replace. `Ok` with no path means the store is intentionally
    /// in-memory. A write failure leaves the previous file in place.
    fn save(&self) -> Result<(), ()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut body = String::new();
        for acct in self.map.values() {
            body.push_str(&acct.name);
            body.push('\t');
            body.push_str(&acct.iters.to_string());
            body.push('\t');
            body.push_str(&base64_encode(&acct.salt));
            body.push('\t');
            body.push_str(&base64_encode(&acct.hash));
            if !acct.certs.is_empty() {
                body.push('\t');
                body.push_str(&acct.certs.join(","));
            }
            body.push('\n');
        }
        let tmp = format!("{}.tmp", path);
        let mut f = std::fs::File::create(&tmp).map_err(|_| ())?;
        if f.write_all(body.as_bytes()).is_err() || f.flush().is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(());
        }
        std::fs::rename(&tmp, path).map_err(|_| ())
    }
}

fn parse_line(line: &str) -> Option<Account> {
    let mut it = line.split('\t');
    let name = it.next()?.to_string();
    let iters: u32 = it.next()?.parse().ok()?;
    let salt = base64_decode(it.next()?)?;
    let hash = base64_decode(it.next()?)?;
    if name.is_empty() || salt.is_empty() || hash.is_empty() {
        return None;
    }
    let mut certs = Vec::new();
    if let Some(field) = it.next() {
        for part in field.split(',') {
            if let Some(fp) = normalize_cert_fingerprint(part) {
                if !certs.contains(&fp) {
                    certs.push(fp);
                }
            }
        }
    }
    Some(Account {
        name,
        salt,
        hash,
        iters,
        certs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_verify() {
        let mut s = AccountStore::load(None);
        assert!(s.register("Alice", "hunter2").is_ok());
        assert!(s.verify("alice", "hunter2")); // case-insensitive lookup
        assert!(!s.verify("alice", "wrong"));
        assert!(!s.verify("bob", "hunter2"));
        // duplicate registration refused
        assert!(s.register("ALICE", "other").is_err());
        // services names are not accounts
        assert!(s.register("NickServ", "x").is_err());
        assert!(s.register("ChanServ", "x").is_err());
    }

    #[test]
    fn password_can_be_replaced() {
        let mut s = AccountStore::load(None);
        s.register("Alice", "old").unwrap();
        assert!(s.set_password("alice", "new").is_ok());
        assert!(!s.verify("alice", "old"));
        assert!(s.verify("ALICE", "new"));
        assert!(s.set_password("alice", "").is_err());
        assert!(s.verify("alice", "new"));
        assert!(s.set_password("missing", "x").is_err());
    }

    #[test]
    fn persists_across_reload() {
        let path = format!("/tmp/chonkline-acct-test-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);
        {
            let mut s = AccountStore::load(Some(path.clone()));
            s.register("Zed", "s3cr3t").unwrap();
        }
        let s2 = AccountStore::load(Some(path.clone()));
        assert!(s2.exists("zed"));
        assert!(s2.verify("zed", "s3cr3t"));
        assert!(!s2.verify("zed", "nope"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn password_only_lines_load_and_round_trip_without_a_cert_field() {
        let path = format!("/tmp/chonkline-acct-old-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "Zed\t100000\tAQID\tBAUG\n").unwrap();
        // AQID and BAUG are valid base64 ("\x01\x02\x03", "\x04\x05\x06") but
        // not a real password hash. The line must still load.
        let s = AccountStore::load(Some(path.clone()));
        assert!(s.exists("zed"));
        assert_eq!(s.certs_of("zed").unwrap().len(), 0);
        let _ = std::fs::remove_file(&path);

        let path = format!("/tmp/chonkline-acct-plain-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);
        {
            let mut s = AccountStore::load(Some(path.clone()));
            s.register("Zed", "s3cr3t").unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let fields = text.lines().next().unwrap().split('\t').count();
        assert_eq!(
            fields, 4,
            "a password-only account stays a 4-field line: {text}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn certificates_persist_and_do_not_follow_the_password() {
        let path = format!("/tmp/chonkline-acct-cert-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);
        let fp_a = "ab".repeat(32);
        let fp_b = "cd".repeat(32);
        {
            let mut s = AccountStore::load(Some(path.clone()));
            s.register("Alice", "old").unwrap();
            assert_eq!(s.add_cert("alice", &fp_a).unwrap(), CertAdd::Enrolled);
            assert_eq!(
                s.add_cert("ALICE", &format!("{}:", fp_b)).unwrap(),
                CertAdd::Enrolled
            );
            // Colon form of the same print is the binding we already have.
            assert_eq!(
                s.add_cert(
                    "alice",
                    &fp_a
                        .chars()
                        .enumerate()
                        .flat_map(|(i, c)| {
                            if i > 0 && i % 2 == 0 {
                                vec![':', c]
                            } else {
                                vec![c]
                            }
                        })
                        .collect::<String>()
                )
                .unwrap(),
                CertAdd::Already
            );
            s.set_password("alice", "new").unwrap();
        }
        let s2 = AccountStore::load(Some(path.clone()));
        assert!(s2.verify("alice", "new"));
        assert!(!s2.verify("alice", "old"));
        assert_eq!(s2.account_for_cert(&fp_a).as_deref(), Some("Alice"));
        assert_eq!(s2.certs_of("alice").unwrap().len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_fingerprint_belongs_to_one_account_and_removal_keeps_the_password() {
        let mut s = AccountStore::load(None);
        s.register("Alice", "pw").unwrap();
        s.register("Bob", "pw").unwrap();
        let fp = "11".repeat(32);
        let other = "22".repeat(32);
        s.add_cert("alice", &fp).unwrap();
        assert!(s.add_cert("bob", &fp).is_err());
        s.add_cert("alice", &other).unwrap();
        s.remove_cert("alice", &fp).unwrap();
        assert!(s.account_for_cert(&fp).is_none());
        assert_eq!(s.account_for_cert(&other).as_deref(), Some("Alice"));
        assert!(s.verify("alice", "pw"));
        assert!(s.remove_cert("bob", &other).is_err());
    }

    #[test]
    fn certificate_limit_and_unsaved_binding_are_not_reported_as_enrolled() {
        let mut s = AccountStore::load(None);
        s.register("Alice", "pw").unwrap();
        for i in 0..MAX_CERTS_PER_ACCOUNT {
            let fp = format!("{:064x}", i as u128);
            assert!(s.add_cert("alice", &fp).is_ok(), "{fp}");
        }
        let overflow = format!("{:064x}", 99u128);
        assert_eq!(
            s.add_cert("alice", &overflow),
            Err("certificate limit reached")
        );
        assert!(s.account_for_cert(&overflow).is_none());

        let dir = format!("/tmp/chonkline-acct-dir-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut broken = AccountStore::load(Some(dir.clone()));
        broken.register("Alice", "pw").unwrap();
        let fp = "ee".repeat(32);
        assert_eq!(
            broken.add_cert("alice", &fp),
            Err("could not save account store")
        );
        assert!(broken.certs_of("alice").unwrap().is_empty());
        assert!(broken.account_for_cert(&fp).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
