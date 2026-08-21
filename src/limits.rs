//! Connection admission control and per-source traffic accounting.
//!
//! Both controls are keyed on the client's *real* address, which is only
//! trustworthy once the PROXY header is parsed (see `crate::proxyproto`).
//! Behind an ingress that does not forward it, every client shares one address
//! and everything here degrades to a single global bucket — so admission
//! control and PROXY support have to land together to mean anything.
//!
//! Two separate concerns live here:
//!
//! * **Admission** bounds how many connections a source may hold at once and
//!   how fast it may open them, plus a global ceiling for the server.
//! * **Traffic** bounds the aggregate message rate per source. The older
//!   per-connection window in `ops` remains the first tier; this is the second,
//!   so that spreading traffic across many connections no longer multiplies the
//!   budget by the connection count.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Tunable bounds. Defaults are deliberately generous: bouncers and bots
/// legitimately hold several sessions from one address.
pub struct Limits {
    /// Concurrent connections permitted from one source. 0 disables the cap.
    pub max_clones_per_ip: usize,
    /// Concurrent registered+unregistered connections server-wide. 0 disables.
    pub max_clients: usize,
    /// New connections permitted from one source within `connect_window`.
    pub max_connects_per_window: usize,
    pub connect_window: Duration,
    /// Aggregate messages permitted from one source within `message_window`.
    pub max_messages_per_window: usize,
    pub message_window: Duration,
    /// Aggregate-budget violations tolerated before the connection is closed.
    pub max_violations: usize,
    /// Sources exempt from every bound above. Holds the ingress address so a
    /// misconfiguration cannot lock the whole network out at once.
    pub exempt: Vec<String>,
}

/// Whether client addresses can be trusted to identify distinct clients.
///
/// Behind a proxy that does not forward the original address, every client
/// appears to come from the proxy — so a per-source cap of N would not admit N
/// connections per user, it would admit N for the *entire network*. Enabling
/// per-source caps in that state is not merely useless, it is an outage.
///
/// The per-source bounds therefore default to off unless PROXY parsing is on.
/// They can still be forced via their own env vars for a direct-to-pod
/// deployment where `peer_addr()` genuinely is the client.
fn addresses_are_trustworthy() -> bool {
    matches!(
        std::env::var("IRC_PROXY_PROTOCOL").unwrap_or_default().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

impl Default for Limits {
    fn default() -> Self {
        let trusted = addresses_are_trustworthy();
        let per_source_default = |d: usize| if trusted { d } else { 0 };
        Limits {
            max_clones_per_ip: env_usize("IRC_MAX_CLONES_PER_IP", per_source_default(5)),
            max_clients: env_usize("IRC_MAX_CLIENTS", 1024),
            max_connects_per_window: env_usize("IRC_MAX_CONNECTS_PER_MIN", per_source_default(30)),
            connect_window: Duration::from_secs(60),
            max_messages_per_window: env_usize("IRC_MAX_MESSAGES_PER_10S", per_source_default(60)),
            message_window: Duration::from_secs(10),
            max_violations: env_usize("IRC_MAX_FLOOD_VIOLATIONS", 10),
            exempt: std::env::var("IRC_LIMIT_EXEMPT")
                .ok()
                .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default(),
        }
    }
}

/// Collapse an address to the unit that actually costs an attacker money.
///
/// A single IPv6 /64 is the smallest block routinely handed to one customer, so
/// keying on the full address made every per-source bound meaningless: an
/// attacker with one /64 has 18 quintillion distinct "sources" and can take
/// every admission slot without tripping a clone cap or a connect rate. IPv4 is
/// keyed whole, since a /32 is already the unit of scarcity there.
pub fn source_key(addr: &str) -> String {
    match addr.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => {
            // An IPv4-mapped address is really IPv4; key it as such.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let o = v6.octets();
            let mut net = [0u8; 16];
            net[..8].copy_from_slice(&o[..8]);
            format!("{}/64", std::net::Ipv6Addr::from(net))
        }
        Err(_) => addr.to_string(),
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Why a connection was refused, for the client-facing message and the log.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Refusal {
    TooManyClones,
    ConnectingTooFast,
    ServerFull,
}

impl Refusal {
    /// Text sent to the client before closing. Deliberately explicit: a user
    /// hitting a limit should be able to tell that from an outage.
    pub fn message(self) -> &'static str {
        match self {
            Refusal::TooManyClones => "Too many connections from your address",
            Refusal::ConnectingTooFast => "Reconnecting too fast, try again shortly",
            Refusal::ServerFull => "Server is full, try again shortly",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::TooManyClones => "clones",
            Refusal::ConnectingTooFast => "connect_rate",
            Refusal::ServerFull => "server_full",
        }
    }
}

#[derive(Default)]
struct Source {
    active: usize,
    connects: Vec<Instant>,
    messages: Vec<Instant>,
    violations: usize,
}

/// Live per-source accounting. Entries are dropped once a source has no active
/// connections and no recent history, so an attacker cycling through addresses
/// cannot grow this table without bound.
#[derive(Default)]
pub struct SourceTable {
    sources: HashMap<String, Source>,
    /// Total admitted connections currently held, for the global ceiling.
    active_total: usize,
}

impl SourceTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Exemptions accept glob patterns (`10.2.*`), because the addresses that
    /// need exempting are infrastructure ranges -- load-balancer health checks
    /// and cluster gateways -- whose exact values change when those resources
    /// are recreated. Pinning exact IPs means the exemption silently lapses.
    /// Whether an address is exempt. Callers must pass the TCP peer, not a
    /// header-supplied address.
    pub fn is_exempt(limits: &Limits, key: &str) -> bool {
        limits.exempt.iter().any(|e| crate::bans::glob_match(e, key))
    }

    /// Admit or refuse a new connection from `key`, reserving a slot on success.
    /// Every successful call must be matched by exactly one `release`.
    ///
    /// `exempt` is decided by the caller from the TCP PEER address, never from
    /// the key. The key may come from a PROXY header, and a header is only as
    /// trustworthy as the path it arrived on -- anyone who can reach the daemon
    /// directly writes their own. Matching the exemption list against a claimed
    /// address let such a client name an exempt range and bypass every bound,
    /// including the global ceiling.
    pub fn try_admit(&mut self, limits: &Limits, key: &str, exempt: bool, now: Instant) -> Result<(), Refusal> {
        if exempt {
            // Exempt sources are infrastructure -- health checks and gateways.
            // They are deliberately kept OUT of `active_total` as well as the
            // per-source caps: counting them would let a health-check cadence
            // consume the global ceiling and lock real users out of the very
            // bound that exists to stop memory exhaustion.
            self.sources.entry(key.to_string()).or_default().active += 1;
            return Ok(());
        }

        if limits.max_clients > 0 && self.active_total >= limits.max_clients {
            return Err(Refusal::ServerFull);
        }

        let entry = self.sources.entry(key.to_string()).or_default();
        entry.connects.retain(|t| now.duration_since(*t) < limits.connect_window);

        if limits.max_clones_per_ip > 0 && entry.active >= limits.max_clones_per_ip {
            return Err(Refusal::TooManyClones);
        }
        if limits.max_connects_per_window > 0 && entry.connects.len() >= limits.max_connects_per_window {
            return Err(Refusal::ConnectingTooFast);
        }

        entry.connects.push(now);
        entry.active += 1;
        self.active_total += 1;
        Ok(())
    }

    /// Release a slot reserved by `try_admit`. Takes `limits` so the exempt
    /// check matches admission exactly -- an asymmetry here would drift
    /// `active_total` until the ceiling refused everyone.
    pub fn release(&mut self, limits: &Limits, key: &str, exempt: bool, now: Instant) {
        let is_exempt = exempt;
        let _ = limits;
        let drop_entry = match self.sources.get_mut(key) {
            Some(entry) => {
                entry.active = entry.active.saturating_sub(1);
                if !is_exempt {
                    self.active_total = self.active_total.saturating_sub(1);
                }
                entry.connects.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
                entry.active == 0 && entry.connects.is_empty()
            }
            None => false,
        };
        if drop_entry {
            self.sources.remove(key);
        }
    }

    /// Charge one message against the source's aggregate budget.
    ///
    /// Returns `Ok(())` while within budget, `Err(true)` when the budget is
    /// exceeded and the connection should be closed, and `Err(false)` when it
    /// is exceeded but the message should merely be dropped.
    pub fn charge_message(&mut self, limits: &Limits, key: &str, exempt: bool, now: Instant) -> Result<(), bool> {
        if exempt || limits.max_messages_per_window == 0 {
            return Ok(());
        }
        let entry = self.sources.entry(key.to_string()).or_default();
        entry.messages.retain(|t| now.duration_since(*t) < limits.message_window);

        if entry.messages.len() >= limits.max_messages_per_window {
            entry.violations += 1;
            return Err(limits.max_violations > 0 && entry.violations >= limits.max_violations);
        }
        entry.messages.push(now);
        Ok(())
    }

    /// Connections currently admitted, server-wide.
    pub fn active_total(&self) -> usize {
        self.active_total
    }

    /// Connections currently admitted from one source.
    pub fn active_for(&self, key: &str) -> usize {
        self.sources.get(key).map(|s| s.active).unwrap_or(0)
    }

    /// The busiest sources by live connection count, most first. This is the
    /// "who is flooding me right now" query, which had no answer in-band.
    pub fn top_sources(&self, n: usize) -> Vec<(String, usize)> {
        let mut v: Vec<(String, usize)> = self
            .sources
            .iter()
            .filter(|(_, s)| s.active > 0)
            .map(|(k, s)| (k.clone(), s.active))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Number of tracked sources, so the table's own growth stays observable.
    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_clones_per_ip: 3,
            max_clients: 10,
            max_connects_per_window: 5,
            connect_window: Duration::from_secs(60),
            max_messages_per_window: 4,
            message_window: Duration::from_secs(10),
            max_violations: 2,
            exempt: vec!["10.2.0.169".to_string()],
        }
    }

    #[test]
    fn clone_cap_is_enforced_per_source() {
        let (l, mut t, now) = (limits(), SourceTable::new(), Instant::now());
        for _ in 0..3 {
            assert!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_ok());
        }
        assert_eq!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now), Err(Refusal::TooManyClones));
    }

    #[test]
    fn sources_are_isolated_from_each_other() {
        let (l, mut t, now) = (limits(), SourceTable::new(), Instant::now());
        for _ in 0..3 {
            assert!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_ok());
        }
        // A second address is unaffected by the first exhausting its budget.
        assert!(t.try_admit(&l, "198.51.100.9", SourceTable::is_exempt(&l, "198.51.100.9"), now).is_ok());
    }

    #[test]
    fn releasing_frees_a_slot() {
        let (l, mut t, now) = (limits(), SourceTable::new(), Instant::now());
        for _ in 0..3 {
            assert!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_ok());
        }
        t.release(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now);
        assert!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_ok());
    }

    #[test]
    fn exempt_source_bypasses_every_cap() {
        let (l, mut t, now) = (limits(), SourceTable::new(), Instant::now());
        for _ in 0..50 {
            assert!(t.try_admit(&l, "10.2.0.169", SourceTable::is_exempt(&l, "10.2.0.169"), now).is_ok(), "exempt source must never be refused");
        }
    }

    #[test]
    fn exempt_sources_do_not_consume_the_global_ceiling() {
        let (l, mut t, now) = (limits(), SourceTable::new(), Instant::now());
        // A health-check cadence must not be able to exhaust the ceiling that
        // protects real users from a connect flood.
        for _ in 0..100 {
            assert!(t.try_admit(&l, "10.2.0.169", SourceTable::is_exempt(&l, "10.2.0.169"), now).is_ok());
        }
        assert_eq!(t.active_total(), 0, "exempt connections must stay out of the ceiling");
        assert!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_ok(), "a real client must still be admitted");
    }

    #[test]
    fn exemptions_accept_patterns() {
        let mut l = limits();
        l.exempt = vec!["10.2.*".to_string(), "192.168.*".to_string()];
        let (mut t, now) = (SourceTable::new(), Instant::now());
        // Health checks arrive from whichever gateway or balancer address the
        // infrastructure happens to use; a pattern survives them being recreated.
        for addr in ["10.2.0.1", "10.2.1.1", "192.168.255.65"] {
            for _ in 0..50 {
                assert!(t.try_admit(&l, addr, SourceTable::is_exempt(&l, addr), now).is_ok(), "{addr} should be exempt by pattern");
            }
        }
        // A real client is still bounded.
        for _ in 0..3 {
            assert!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_ok());
        }
        assert_eq!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now), Err(Refusal::TooManyClones));
    }

    #[test]
    fn global_ceiling_is_enforced() {
        let (l, mut t, now) = (limits(), SourceTable::new(), Instant::now());
        // Three sources of three fills nine slots; a fourth source takes the
        // tenth and last, so the eleventh connection is refused server-wide even
        // though its own source is nowhere near the per-source cap.
        for src in ["a", "b", "c"] {
            for _ in 0..3 {
                assert!(t.try_admit(&l, src, SourceTable::is_exempt(&l, src), now).is_ok());
            }
        }
        assert!(t.try_admit(&l, "d", SourceTable::is_exempt(&l, "d"), now).is_ok());
        assert_eq!(t.active_total(), 10);
        assert_eq!(t.try_admit(&l, "e", SourceTable::is_exempt(&l, "e"), now), Err(Refusal::ServerFull));
    }

    #[test]
    fn connect_rate_limits_churn() {
        let mut l = limits();
        l.max_clones_per_ip = 0; // isolate the rate limit from the clone cap
        let (mut t, now) = (SourceTable::new(), Instant::now());
        for _ in 0..5 {
            assert!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_ok());
        }
        assert_eq!(t.try_admit(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now), Err(Refusal::ConnectingTooFast));
    }

    #[test]
    fn aggregate_budget_spans_connections_from_one_source() {
        let (l, mut t, now) = (limits(), SourceTable::new(), Instant::now());
        // The budget is charged per source, so it does not matter that these
        // messages arrive on different connections.
        for _ in 0..4 {
            assert!(t.charge_message(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_ok());
        }
        assert!(t.charge_message(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_err(), "budget must not scale with connection count");
    }

    #[test]
    fn repeated_violations_escalate_to_disconnect() {
        let (l, mut t, now) = (limits(), SourceTable::new(), Instant::now());
        for _ in 0..4 {
            let _ = t.charge_message(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now);
        }
        assert_eq!(t.charge_message(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now), Err(false), "first violation drops");
        assert_eq!(t.charge_message(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now), Err(true), "second violation disconnects");
    }

    #[test]
    fn normal_traffic_is_never_penalised() {
        let (l, mut t) = (limits(), SourceTable::new());
        let start = Instant::now();
        // One message every window-length stays inside budget indefinitely.
        for i in 0..20 {
            let now = start + l.message_window * (i + 1);
            assert!(t.charge_message(&l, "203.0.113.7", SourceTable::is_exempt(&l, "203.0.113.7"), now).is_ok(), "steady traffic must not trip the limiter");
        }
    }

    #[test]
    fn table_does_not_grow_without_bound() {
        let (l, mut t, now) = (limits(), SourceTable::new(), Instant::now());
        // A source that connects and leaves is forgotten, so address cycling
        // cannot itself become a memory leak.
        for i in 0..100 {
            let key = format!("198.51.100.{}", i % 250);
            assert!(t.try_admit(&l, &key, SourceTable::is_exempt(&l, &key), now).is_ok());
            t.release(&l, &key, SourceTable::is_exempt(&l, &key), now + Duration::from_secs(120));
        }
        assert_eq!(t.tracked_sources(), 0);
        assert_eq!(t.active_total(), 0);
    }
}

#[cfg(test)]
mod interlock_tests {
    use super::*;

    /// The per-source bounds must stay off while addresses are untrustworthy,
    /// because a shared address turns a per-source cap into a global one.
    #[test]
    fn per_source_caps_default_off_without_proxy_support() {
        std::env::remove_var("IRC_PROXY_PROTOCOL");
        std::env::remove_var("IRC_MAX_CLONES_PER_IP");
        std::env::remove_var("IRC_MAX_CONNECTS_PER_MIN");
        std::env::remove_var("IRC_MAX_MESSAGES_PER_10S");
        let l = Limits::default();
        assert_eq!(l.max_clones_per_ip, 0, "a shared address must not be capped per-source");
        assert_eq!(l.max_connects_per_window, 0);
        assert_eq!(l.max_messages_per_window, 0);
        // The global ceiling is still meaningful and stays on.
        assert!(l.max_clients > 0);
    }
}

#[cfg(test)]
mod forgery_tests {
    use super::*;

    #[test]
    fn a_forged_address_cannot_buy_an_exemption() {
        // A PROXY header is only as trustworthy as the path it arrived on. Any
        // client that can reach the daemon directly writes its own, so matching
        // the exemption list against the address a header CLAIMS lets it name an
        // exempt range and bypass every bound -- including the global ceiling,
        // which exempt sources are deliberately kept out of.
        //
        // Exemption is therefore decided from the TCP peer.
        let l = Limits {
            max_clones_per_ip: 2,
            max_clients: 10,
            max_connects_per_window: 0,
            connect_window: Duration::from_secs(60),
            max_messages_per_window: 0,
            message_window: Duration::from_secs(10),
            max_violations: 0,
            exempt: vec!["192.168.*".to_string()],
        };
        let mut t = SourceTable::new();
        let now = Instant::now();

        // Claims an exempt address, but its real peer is not exempt.
        let claimed = "192.168.1.99";
        let peer_exempt = SourceTable::is_exempt(&l, "203.0.113.50");
        assert!(!peer_exempt, "the real peer is not in the exemption list");

        for _ in 0..2 {
            assert!(t.try_admit(&l, claimed, peer_exempt, now).is_ok());
        }
        assert_eq!(
            t.try_admit(&l, claimed, peer_exempt, now),
            Err(Refusal::TooManyClones),
            "a claimed exempt address must still be capped"
        );
        assert_eq!(t.active_total(), 2, "and must still count against the ceiling");
    }

    #[test]
    fn a_genuinely_exempt_peer_is_still_exempt() {
        let l = Limits {
            max_clones_per_ip: 2, max_clients: 10, max_connects_per_window: 0,
            connect_window: Duration::from_secs(60), max_messages_per_window: 0,
            message_window: Duration::from_secs(10), max_violations: 0,
            exempt: vec!["192.168.*".to_string()],
        };
        let mut t = SourceTable::new();
        let now = Instant::now();
        let peer_exempt = SourceTable::is_exempt(&l, "192.168.255.65");
        assert!(peer_exempt);
        for _ in 0..50 {
            assert!(t.try_admit(&l, "192.168.255.65", peer_exempt, now).is_ok());
        }
        assert_eq!(t.active_total(), 0, "health checks stay out of the ceiling");
    }
}
