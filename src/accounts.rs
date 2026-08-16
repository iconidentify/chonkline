//! Services account store: registered accounts with PBKDF2-hashed passwords,
//! persisted to a simple line-based file so identities survive restarts.
//!
//! Format (one account per line, tab-separated):
//!   <name>\t<iters>\t<base64 salt>\t<base64 hash>
//!
//! Passwords are never stored; only a PBKDF2-HMAC-SHA256 derivation with a
//! per-account random salt. Account names are keyed case-insensitively via the
//! same folding used for nicknames.

use std::collections::HashMap;
use std::io::{Read, Write};

use crate::crypto::{base64_decode, base64_encode, constant_time_eq, pbkdf2_sha256};
use crate::state::norm_nick;

const ITERS: u32 = 100_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

struct Account {
    name: String, // display form
    salt: Vec<u8>,
    hash: Vec<u8>,
    iters: u32,
}

pub struct AccountStore {
    path: Option<String>,
    map: HashMap<String, Account>, // key = norm_nick(name)
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
        if let Some(p) = &path {
            if let Ok(contents) = std::fs::read_to_string(p) {
                for line in contents.lines() {
                    if let Some(acct) = parse_line(line) {
                        map.insert(norm_nick(&acct.name), acct);
                    }
                }
            }
        }
        AccountStore { path, map }
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
            Account { name: name.to_string(), salt, hash, iters: ITERS },
        );
        self.save();
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

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let mut body = String::new();
        for acct in self.map.values() {
            body.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                acct.name,
                acct.iters,
                base64_encode(&acct.salt),
                base64_encode(&acct.hash),
            ));
        }
        // Atomic replace: write a sibling temp file then rename over the target.
        let tmp = format!("{}.tmp", path);
        if let Ok(mut f) = std::fs::File::create(&tmp) {
            if f.write_all(body.as_bytes()).is_ok() && f.flush().is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
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
    Some(Account { name, salt, hash, iters })
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
}
