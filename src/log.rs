//! Structured security and lifecycle logging.
//!
//! Before this existed the daemon emitted exactly one line per process
//! lifetime, so an incident could only be reconstructed from surrounding
//! infrastructure. The events here are the minimum needed to answer "who
//! connected, who authenticated, who acted, and what was refused".
//!
//! Two rules shape the API:
//!
//! * **Message content is never logged.** No function here accepts a PRIVMSG or
//!   NOTICE body. Logging traffic would be both a privacy problem and a volume
//!   problem; metadata and security events are what an investigation needs.
//! * **High-volume events aggregate.** A connection flood must not become a log
//!   flood, so refusals increment counters that are flushed on a timer rather
//!   than emitting a line each.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::proto;

pub const ERROR: usize = 0;
pub const WARN: usize = 1;
pub const INFO: usize = 2;
pub const DEBUG: usize = 3;

static LEVEL: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Resolve the configured level once, from `IRC_LOG_LEVEL`.
fn level() -> usize {
    let cached = LEVEL.load(Ordering::Relaxed);
    if cached != usize::MAX {
        return cached;
    }
    let resolved = match std::env::var("IRC_LOG_LEVEL").unwrap_or_default().to_ascii_lowercase().as_str() {
        "error" => ERROR,
        "warn" | "warning" => WARN,
        "debug" => DEBUG,
        "silent" | "off" => 0usize.wrapping_sub(1) & 0xFF, // effectively suppress all
        _ => INFO,
    };
    LEVEL.store(resolved, Ordering::Relaxed);
    resolved
}

/// Reset the cached level. Test-only: the level is otherwise resolved once.
#[cfg(test)]
pub fn reset_level_cache() {
    LEVEL.store(usize::MAX, Ordering::Relaxed);
}

fn enabled(want: usize) -> bool {
    let lvl = level();
    lvl != (0usize.wrapping_sub(1) & 0xFF) && want <= lvl
}

fn label(l: usize) -> &'static str {
    match l {
        ERROR => "ERROR",
        WARN => "WARN",
        DEBUG => "DEBUG",
        _ => "INFO",
    }
}

/// Render one value, quoting when it contains spaces or is empty so that
/// key=value parsing stays unambiguous downstream.
fn val(v: &str) -> String {
    let clean: String = v.chars().filter(|c| !c.is_control()).collect();
    if clean.is_empty() || clean.contains(' ') || clean.contains('"') {
        format!("{:?}", clean)
    } else {
        clean
    }
}

/// Emit one structured event: `<ts> <LEVEL> <event> k=v k=v`.
pub fn event(lvl: usize, name: &str, fields: &[(&str, &str)]) {
    if !enabled(lvl) {
        return;
    }
    let mut line = format!("{} {} {}", proto::ircv3_timestamp(), label(lvl), name);
    for (k, v) in fields {
        line.push(' ');
        line.push_str(k);
        line.push('=');
        line.push_str(&val(v));
    }
    println!("{}", line);
}

/// A connection was admitted. Records both the real source and the cloak issued
/// for it, so operator reports naming a cloak can be tied back to an address.
pub fn conn_open(id: usize, src: &str, cloak: &str, tls_hint: &str) {
    event(INFO, "conn.open", &[
        ("id", &id.to_string()),
        ("src", src),
        ("cloak", cloak),
        ("via", tls_hint),
    ]);
}

pub fn conn_close(id: usize, src: &str, nick: &str, reason: &str) {
    event(INFO, "conn.close", &[
        ("id", &id.to_string()),
        ("src", src),
        ("nick", nick),
        ("reason", reason),
    ]);
}

/// An authentication attempt (SASL or NickServ IDENTIFY), successful or not.
pub fn auth(id: usize, src: &str, account: &str, mechanism: &str, ok: bool) {
    event(
        if ok { INFO } else { WARN },
        "auth",
        &[
            ("id", &id.to_string()),
            ("src", src),
            ("account", account),
            ("mech", mechanism),
            ("result", if ok { "ok" } else { "fail" }),
        ],
    );
}

/// An operator action: who did what, to whom, and why.
pub fn oper_action(actor: &str, action: &str, target: &str, reason: &str) {
    event(WARN, "oper.action", &[
        ("actor", actor),
        ("action", action),
        ("target", target),
        ("reason", reason),
    ]);
}

/// A PROXY header could not be trusted. Warn-level because with the feature
/// enabled this means a connection was dropped.
pub fn proxy_rejected(peer: &str) {
    counted("proxy.rejected", peer);
}

// ---------------------------------------------------------------------------
// Aggregated counters
// ---------------------------------------------------------------------------

use std::sync::Mutex;

static COUNTS: Mutex<Option<BTreeMap<String, u64>>> = Mutex::new(None);

/// Record one occurrence of a high-volume event. Nothing is printed here; the
/// totals surface on the next `flush_counters`, so a flood cannot turn into a
/// log flood.
pub fn counted(event_name: &str, detail: &str) {
    let key = if detail.is_empty() {
        event_name.to_string()
    } else {
        format!("{} {}", event_name, detail)
    };
    let mut guard = match COUNTS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // a poisoned counter must not take the server down
    };
    *guard.get_or_insert_with(BTreeMap::new).entry(key).or_insert(0) += 1;
}

/// A connection was refused by admission control.
pub fn refused(reason: &str) {
    counted("conn.refused", reason);
}

/// A source exceeded its aggregate message budget.
pub fn flood(action: &str) {
    counted("flood", action);
}

/// Emit and clear the accumulated counters. Called on the liveness tick.
pub fn flush_counters() {
    let taken = {
        let mut guard = match COUNTS.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match guard.as_mut() {
            Some(m) if !m.is_empty() => std::mem::take(m),
            _ => return,
        }
    };
    for (key, count) in taken {
        let mut parts = key.splitn(2, ' ');
        let name = parts.next().unwrap_or("event");
        let detail = parts.next().unwrap_or("");
        event(WARN, name, &[("detail", detail), ("count", &count.to_string())]);
    }
}

/// Periodic aggregate state, at a low cadence, so a quiet log still shows the
/// server is alive and roughly how loaded it is.
pub fn heartbeat(users: usize, chans: usize, conns: usize, sources: usize) {
    event(DEBUG, "server.state", &[
        ("users", &users.to_string()),
        ("channels", &chans.to_string()),
        ("connections", &conns.to_string()),
        ("sources", &sources.to_string()),
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_escaped_and_control_bytes_stripped() {
        // A nick or reason must not be able to forge extra log fields or lines.
        assert_eq!(val("bob"), "bob");
        assert_eq!(val("two words"), "\"two words\"");
        assert_eq!(val("a\nb"), "ab");
        assert_eq!(val(""), "\"\"");
    }

    #[test]
    fn counters_aggregate_then_clear() {
        for _ in 0..500 {
            refused("clones");
        }
        // Flushing empties the table, so the next flush is silent rather than
        // repeating totals forever.
        flush_counters();
        let guard = COUNTS.lock().unwrap();
        assert!(guard.as_ref().map(|m| m.is_empty()).unwrap_or(true));
    }
}
