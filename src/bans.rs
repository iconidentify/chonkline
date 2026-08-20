//! Server-wide address bans (K-lines), persisted so they survive a restart.
//!
//! Format (one ban per line, tab-separated):
//!   <mask>\t<expiry unix secs, 0 = permanent>\t<setter>\t<reason>
//!
//! Masks match against the client's *real* address, so a ban is only meaningful
//! once the PROXY header is parsed (see `crate::proxyproto`). Behind an ingress
//! that does not forward it every client shares one address and any ban would
//! match the entire network — which is exactly the failure this store exists to
//! avoid, so `Ban::matches` is deliberately never applied to a cloak.

use std::io::Write;

pub struct Ban {
    pub mask: String,
    pub expiry: u64, // unix seconds; 0 = permanent
    pub setter: String,
    pub reason: String,
}

pub struct BanStore {
    path: Option<String>,
    bans: Vec<Ban>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Glob match supporting `*` and `?`, iterative so a hostile mask cannot drive
/// unbounded recursion.
pub fn glob_match(mask: &str, text: &str) -> bool {
    let (m, t): (Vec<char>, Vec<char>) = (mask.chars().collect(), text.chars().collect());
    let (mut mi, mut ti) = (0usize, 0usize);
    let (mut star, mut backtrack) = (usize::MAX, 0usize);

    while ti < t.len() {
        if mi < m.len() && (m[mi] == '?' || m[mi] == t[ti]) {
            mi += 1;
            ti += 1;
        } else if mi < m.len() && m[mi] == '*' {
            star = mi;
            backtrack = ti;
            mi += 1;
        } else if star != usize::MAX {
            mi = star + 1;
            backtrack += 1;
            ti = backtrack;
        } else {
            return false;
        }
    }
    while mi < m.len() && m[mi] == '*' {
        mi += 1;
    }
    mi == m.len()
}

impl BanStore {
    /// Load from `path` (IRC_BANS_PATH). A missing file is an empty store; a
    /// missing path means in-memory only.
    pub fn load(path: Option<String>) -> Self {
        let mut bans = Vec::new();
        if let Some(p) = &path {
            if let Ok(contents) = std::fs::read_to_string(p) {
                for line in contents.lines() {
                    let mut f = line.split('\t');
                    match (f.next(), f.next(), f.next(), f.next()) {
                        (Some(mask), Some(exp), Some(setter), Some(reason)) if !mask.is_empty() => {
                            bans.push(Ban {
                                mask: mask.to_string(),
                                expiry: exp.parse().unwrap_or(0),
                                setter: setter.to_string(),
                                reason: reason.to_string(),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        BanStore { path, bans }
    }

    fn persist(&self) {
        let Some(p) = &self.path else { return };
        let mut out = String::new();
        for b in &self.bans {
            out.push_str(&format!("{}\t{}\t{}\t{}\n", b.mask, b.expiry, b.setter, b.reason));
        }
        // Best effort: an unwritable path keeps bans in memory for this run.
        if let Ok(mut f) = std::fs::File::create(p) {
            let _ = f.write_all(out.as_bytes());
        }
    }

    /// Drop expired entries. Called before every match so a lapsed ban never
    /// blocks a connection.
    fn expire(&mut self) {
        let now = now_secs();
        self.bans.retain(|b| b.expiry == 0 || b.expiry > now);
    }

    /// The ban matching `addr`, if any.
    pub fn matching(&mut self, addr: &str) -> Option<&Ban> {
        self.expire();
        self.bans.iter().find(|b| glob_match(&b.mask, addr))
    }

    /// Add a ban. `duration_secs` of 0 makes it permanent. Replaces any existing
    /// entry with the same mask so re-banning updates rather than duplicates.
    pub fn add(&mut self, mask: &str, duration_secs: u64, setter: &str, reason: &str) {
        if mask.is_empty() {
            return;
        }
        self.bans.retain(|b| b.mask != mask);
        self.bans.push(Ban {
            mask: mask.to_string(),
            expiry: if duration_secs == 0 { 0 } else { now_secs() + duration_secs },
            setter: setter.to_string(),
            reason: reason.to_string(),
        });
        self.persist();
    }

    /// Remove a ban by exact mask. Returns whether one was removed.
    pub fn remove(&mut self, mask: &str) -> bool {
        let before = self.bans.len();
        self.bans.retain(|b| b.mask != mask);
        let removed = self.bans.len() != before;
        if removed {
            self.persist();
        }
        removed
    }

    pub fn list(&self) -> &[Ban] {
        &self.bans
    }

    pub fn count(&self) -> usize {
        self.bans.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_wildcards() {
        assert!(glob_match("203.0.113.*", "203.0.113.7"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("203.0.113.?", "203.0.113.7"));
        assert!(!glob_match("203.0.113.*", "198.51.100.9"));
        assert!(!glob_match("203.0.113.?", "203.0.113.77"));
        assert!(glob_match("*.113.7", "203.0.113.7"));
    }

    #[test]
    fn pathological_mask_terminates() {
        // Iterative matching: a mask of many stars must not blow the stack or hang.
        let mask = "*".repeat(64) + "b";
        assert!(!glob_match(&mask, &"a".repeat(256)));
    }

    #[test]
    fn add_match_and_remove() {
        let mut s = BanStore::load(None);
        s.add("203.0.113.*", 0, "oper", "flooding");
        assert!(s.matching("203.0.113.7").is_some());
        assert!(s.matching("198.51.100.9").is_none());
        assert!(s.remove("203.0.113.*"));
        assert!(s.matching("203.0.113.7").is_none());
    }

    #[test]
    fn rebanning_updates_rather_than_duplicates() {
        let mut s = BanStore::load(None);
        s.add("203.0.113.*", 0, "oper", "first");
        s.add("203.0.113.*", 0, "oper", "second");
        assert_eq!(s.count(), 1);
        assert_eq!(s.matching("203.0.113.7").map(|b| b.reason.clone()), Some("second".to_string()));
    }

    #[test]
    fn expired_bans_stop_matching() {
        let mut s = BanStore::load(None);
        s.bans.push(Ban {
            mask: "203.0.113.*".to_string(),
            expiry: now_secs().saturating_sub(1), // already lapsed
            setter: "oper".to_string(),
            reason: "temporary".to_string(),
        });
        assert!(s.matching("203.0.113.7").is_none());
        assert_eq!(s.count(), 0, "expired entries are dropped, not merely skipped");
    }

    #[test]
    fn survives_a_round_trip_through_disk() {
        let path = std::env::temp_dir().join(format!("chonkline-bans-{}.db", std::process::id()));
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&p);

        let mut s = BanStore::load(Some(p.clone()));
        s.add("203.0.113.*", 0, "oper", "flooding hard");

        // A fresh store reading the same file sees the ban, as it would after a
        // pod restart.
        let mut reloaded = BanStore::load(Some(p.clone()));
        let hit = reloaded.matching("203.0.113.7").expect("ban must survive restart");
        assert_eq!(hit.reason, "flooding hard");
        assert_eq!(hit.setter, "oper");

        let _ = std::fs::remove_file(&p);
    }
}
