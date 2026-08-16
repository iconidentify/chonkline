//! Channel registration store (ChanServ): records a founder account and the
//! persisted topic for registered channels, so a channel and its ownership
//! survive the channel emptying out or the server restarting.
//!
//! Format (one channel per line, tab-separated):
//!   <key>\t<display>\t<founder>\t<base64 topic>
//!
//! `key` is the lowercased channel name; `founder` is the founder's account
//! display name (compared case-insensitively via nick folding).

use std::collections::HashMap;
use std::io::Write;

use crate::crypto::{base64_decode, base64_encode};
use crate::state::norm_nick;

pub struct ChanReg {
    pub display: String,
    pub founder_display: String,
    pub topic: String,
}

pub struct ChannelRegistry {
    path: Option<String>,
    map: HashMap<String, ChanReg>, // key = channel.to_lowercase()
}

impl ChannelRegistry {
    pub fn load(path: Option<String>) -> Self {
        let mut map = HashMap::new();
        if let Some(p) = &path {
            if let Ok(contents) = std::fs::read_to_string(p) {
                for line in contents.lines() {
                    if let Some((k, reg)) = parse_line(line) {
                        map.insert(k, reg);
                    }
                }
            }
        }
        ChannelRegistry { path, map }
    }

    pub fn is_registered(&self, chan_key: &str) -> bool {
        self.map.contains_key(&chan_key.to_lowercase())
    }

    pub fn get(&self, chan_key: &str) -> Option<&ChanReg> {
        self.map.get(&chan_key.to_lowercase())
    }

    pub fn count(&self) -> usize {
        self.map.len()
    }

    /// True when `account` (any case) is the registered founder of the channel.
    pub fn is_founder(&self, chan_key: &str, account: &str) -> bool {
        self.map
            .get(&chan_key.to_lowercase())
            .map(|r| norm_nick(&r.founder_display) == norm_nick(account))
            .unwrap_or(false)
    }

    pub fn register(&mut self, chan_key: &str, display: &str, founder_display: &str) -> Result<(), &'static str> {
        let key = chan_key.to_lowercase();
        if self.map.contains_key(&key) {
            return Err("channel already registered");
        }
        self.map.insert(
            key,
            ChanReg {
                display: display.to_string(),
                founder_display: founder_display.to_string(),
                topic: String::new(),
            },
        );
        self.save();
        Ok(())
    }

    pub fn drop_channel(&mut self, chan_key: &str) -> bool {
        let removed = self.map.remove(&chan_key.to_lowercase()).is_some();
        if removed {
            self.save();
        }
        removed
    }

    /// Persist a new topic for a registered channel (no-op if unregistered).
    pub fn set_topic(&mut self, chan_key: &str, topic: &str) {
        if let Some(reg) = self.map.get_mut(&chan_key.to_lowercase()) {
            reg.topic = topic.to_string();
            self.save();
        }
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let mut body = String::new();
        for (key, reg) in &self.map {
            body.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                key,
                reg.display,
                reg.founder_display,
                base64_encode(reg.topic.as_bytes()),
            ));
        }
        let tmp = format!("{}.tmp", path);
        if let Ok(mut f) = std::fs::File::create(&tmp) {
            if f.write_all(body.as_bytes()).is_ok() && f.flush().is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }
}

fn parse_line(line: &str) -> Option<(String, ChanReg)> {
    let mut it = line.split('\t');
    let key = it.next()?.to_string();
    let display = it.next()?.to_string();
    let founder_display = it.next()?.to_string();
    let topic = String::from_utf8(base64_decode(it.next()?)?).ok()?;
    if key.is_empty() || founder_display.is_empty() {
        return None;
    }
    Some((key, ChanReg { display, founder_display, topic }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_founder_and_topic() {
        let mut r = ChannelRegistry::load(None);
        assert!(r.register("#Rust", "#Rust", "Alice").is_ok());
        assert!(r.is_registered("#rust")); // case-insensitive
        assert!(r.is_founder("#rust", "alice"));
        assert!(!r.is_founder("#rust", "bob"));
        assert!(r.register("#RUST", "#RUST", "Bob").is_err()); // duplicate
        r.set_topic("#rust", "hello world");
        assert_eq!(r.get("#rust").unwrap().topic, "hello world");
        assert!(r.drop_channel("#rust"));
        assert!(!r.is_registered("#rust"));
    }

    #[test]
    fn persists_channels() {
        let path = format!("/tmp/chonkline-chan-test-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);
        {
            let mut r = ChannelRegistry::load(Some(path.clone()));
            r.register("#Ops", "#Ops", "Zed").unwrap();
            r.set_topic("#ops", "topic with spaces\tand tabs");
        }
        let r2 = ChannelRegistry::load(Some(path.clone()));
        assert!(r2.is_founder("#ops", "zed"));
        assert_eq!(r2.get("#ops").unwrap().topic, "topic with spaces\tand tabs");
        let _ = std::fs::remove_file(&path);
    }
}
