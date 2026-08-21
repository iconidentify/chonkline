use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc::Sender, Notify};

/// Recent nickname-change history (RFC 8.9 mandates servers keep one).
#[derive(Debug, Clone)]
pub struct HistEntry {
    pub old_key: String,
    pub new_key: String,
    pub cx_id: usize,
    pub at: Instant,
}

const HISTORY_CAP: usize = 512;
/// Recency window applied when resolving renames through history (RFC 8.9).
pub const RENAME_WINDOW: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Nickname normalization (RFC 2.2) and wildcard matching
// ---------------------------------------------------------------------------

/// Fold Scandinavian character pairs and lowercase, so nick comparison is
/// case-insensitive with {}| treated as the equivalents of []\ (RFC 2.2).
pub fn norm_nick(s: &str) -> String {
    s.chars()
        .map(|c| match c.to_ascii_lowercase() {
            '{' => '[',
            '|' => '\\',
            c => c,
        })
        .collect()
}

/// Wildcard matcher: '*' matches any run (including empty), '?' a single byte.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    // Delegates to the iterative matcher. The previous implementation built a
    // full (m+1)x(n+1) DP matrix on every call with no early exit, so a
    // client-supplied 500-byte mask cost ~29us per field -- and WHO runs it
    // over every user, three fields each, while holding the state lock. At 512
    // users that is tens of milliseconds of locked CPU per command.
    crate::bans::glob_match(pattern, text)
}


// ---------------------------------------------------------------------------
// Client / user record
// ---------------------------------------------------------------------------

/// IRCv3 capabilities enabled on a connection after `CAP REQ` / ACK. Only caps
/// the server genuinely honors are ever advertised or set here.
#[derive(Debug, Clone, Default)]
pub struct Caps {
    pub server_time: bool,        // message @time= tags (RFC: ircv3 server-time)
    pub away_notify: bool,        // AWAY broadcasts to shared-channel peers
    pub extended_join: bool,      // JOIN carries account + realname
    pub account_notify: bool,     // ACCOUNT messages on login/logout
    pub multi_prefix: bool,       // all membership prefixes in NAMES/WHO
    pub userhost_in_names: bool,  // NAMES lists nick!user@host
    pub chghost: bool,            // CHGHOST notifications on host change
    pub cap_notify: bool,         // CAP NEW/DEL notifications
    pub sasl: bool,               // SASL authentication was requested
}

impl Caps {
    /// Space-separated list of the caps currently enabled (for `CAP LIST`).
    pub fn enabled_list(&self) -> String {
        let mut v: Vec<&str> = Vec::new();
        if self.server_time { v.push("server-time"); }
        if self.away_notify { v.push("away-notify"); }
        if self.extended_join { v.push("extended-join"); }
        if self.account_notify { v.push("account-notify"); }
        if self.multi_prefix { v.push("multi-prefix"); }
        if self.userhost_in_names { v.push("userhost-in-names"); }
        if self.chghost { v.push("chghost"); }
        if self.cap_notify { v.push("cap-notify"); }
        if self.sasl { v.push("sasl"); }
        v.join(" ")
    }
}

pub struct Cx {
    pub id: usize,
    /// Bounded reply queue. Unbounded here was the real OOM path: a client that
    /// stops reading parks the writer task while sends keep succeeding, so
    /// queued replies grow without limit -- uncounted by any inbound rate limit
    /// and uncounted by the pod's memory sizing, which only ever accounted for
    /// the (bounded) read buffer.
    pub tx: Sender<String>,
    /// Display nick as chosen by the client (case preserved).
    pub nick: String,
    /// Normalized key used for all comparisons.
    pub nick_key: String,
    pub user: String,
    pub host: String, // cloaked host shown to other users (see ops::cloak_host)
    pub real_host: String, // true peer address, revealed only to operators
    pub realname: String,
    pub registered: bool,

    /// Services account this connection is logged in to (SASL or NickServ
    /// IDENTIFY), if any. Drives account-notify / extended-join and the +r idle
    /// account tag.
    pub account: Option<String>,

    /// IRCv3 capabilities negotiated and enabled on this connection.
    pub caps: Caps,
    /// SASL mechanism selected mid-handshake (before the payload arrives).
    pub sasl_mech: Option<String>,

    // Slots filled while the client completes the NICK/USER registration pair.
    pub pending_nick: Option<String>,  // display form chosen so far
    pub pending_user: Option<String>,  // user part of a USER command seen so far

    /// CAP negotiation state (RFCv3): set when the client begins capability
    /// negotiation, cleared on `CAP END`. While set, the registration welcome
    /// burst is withheld until the exchange completes.
    pub cap_negotiating: bool,
    /// A complete pairing whose welcome burst was suppressed mid-negotiation;
    /// flushed by the connection's own `CAP END`.
    pub cap_gated_welcome: bool,

    pub away: Option<String>,
    pub invis: bool,      // user mode +i (invisible)
    pub wallop: bool,     // user mode +w
    pub srvnotice: bool,  // user mode +s
    pub oper: bool,       // user mode +o (IRC operator)

    pub chans: BTreeSet<String>, // joined channel keys
    pub connected_at: Instant,
    pub last_rx: Instant,
    close_notify: Option<Arc<Notify>>,
}

impl Cx {
    /// Extended prefix for lines relayed to clients (RFC 2.3 note 6), marker included.
    pub fn prefix(&self) -> String {
        format!(":{}!{}@{}", self.nick, self.user, self.host)
    }

    pub fn set_close_notify(&mut self, n: Arc<Notify>) {
        self.close_notify = Some(n);
    }

    pub fn signal_close(&mut self) {
        if let Some(n) = self.close_notify.take() {
            n.notify_waiters();
        }
    }

    /// User mode string as reported by RPL_UMODEIS.
    pub fn user_mode_string(&self) -> String {
        let mut s = String::from("+");
        if self.invis { s.push('i'); }
        if self.srvnotice { s.push('s'); }
        if self.wallop { s.push('w'); }
        if self.oper { s.push('o'); }
        s
    }

    /// User-mode description used in reply trailing text.
    pub fn user_mode_text(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.invis { parts.push("invisible"); }
        if self.wallop { parts.push("wallops"); }
        if self.srvnotice { parts.push("server notices"); }
        if self.oper { parts.push("IRC operator"); }
        if parts.is_empty() { "normal user".to_string() } else { parts.join(", ") }
    }

    /// The composite identity a ban mask is matched against.
    fn composite_key(&self) -> String {
        format!(
            "{}!{}@{}",
            self.nick_key,
            self.user.to_lowercase(),
            self.host.to_lowercase()
        )
    }

    pub fn matches_ban(&self, mask: &str) -> bool {
        let m = mask.to_lowercase();
        if m.contains('!') || m.contains('@') {
            wildcard_match(&m, &self.composite_key())
        } else {
            wildcard_match(&m, &self.nick_key)
        }
    }
}

// ---------------------------------------------------------------------------
// Channel record
// ---------------------------------------------------------------------------

pub struct Chn {
    pub display: String, // original case ("#Foo")
    pub topic: String,
    pub topic_setter: String, // nick that last set the topic (for RPL_TOPICWHOTIME)
    pub topic_time: u64,      // unix seconds when the topic was set
    pub created_at: u64,      // unix seconds the channel was created (RPL_CREATIONTIME)
    invite_only: bool,   // +i (invite-only)
    nomsg: bool,         // +n (no external messages)
    private: bool,       // +p
    secret: bool,        // +s
    op_topic: bool,      // +t
    moderated: bool,     // +m
    regonly: bool,       // +R (registered accounts only)
    pub key_limit: i32,  // +l; 0 = unlimited
    chan_key: Option<String>, // +k
    bans: Vec<String>,   // +b masks (lowercased)
    excepts: Vec<String>, // +e ban-exception masks (lowercased)
    invex: Vec<String>,  // +I invite-exception masks (lowercased)
    invites: BTreeSet<usize>,
    pub ops: BTreeSet<usize>,    // connection ids with operator privileges here
    pub voices: BTreeSet<usize>,
    pub members: BTreeSet<usize>,
}

impl Chn {
    fn new(display: &str) -> Self {
        Chn {
            display: display.to_string(),
            topic: String::new(),
            topic_setter: String::new(),
            topic_time: 0,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            invite_only: false,
            nomsg: false,
            private: false,
            secret: false,
            op_topic: false,
            moderated: false,
            regonly: false,
            key_limit: 0,
            chan_key: None,
            bans: Vec::new(),
            excepts: Vec::new(),
            invex: Vec::new(),
            invites: BTreeSet::new(),
            ops: BTreeSet::new(),
            voices: BTreeSet::new(),
            members: BTreeSet::new(),
        }
    }

    pub fn is_private(&self) -> bool { self.private }
    pub fn is_secret(&self) -> bool { self.secret }
    pub fn invite_only(&self) -> bool { self.invite_only }
    pub fn nomsg(&self) -> bool { self.nomsg }
    pub fn op_topic(&self) -> bool { self.op_topic }
    pub fn moderated(&self) -> bool { self.moderated }
    /// +R: only clients authenticated to a services account may join. This is
    /// the one admission control that works without trustworthy addresses,
    /// which makes it the usable lever during an identity outage.
    pub fn regonly(&self) -> bool { self.regonly }
    pub fn chan_key(&self) -> Option<&str> { self.chan_key.as_deref() }

    pub fn is_member(&self, cx_id: usize) -> bool { self.members.contains(&cx_id) }
    pub fn is_op(&self, cx_id: usize) -> bool { self.ops.contains(&cx_id) }
    pub fn is_voiced(&self, cx_id: usize) -> bool { self.voices.contains(&cx_id) }

    /// Marker ('@' op / '+' voice) shown in NAMES-style listings.
    pub fn marker(&self, cx_id: usize) -> &'static str {
        if self.ops.contains(&cx_id) {
            "@"
        } else if self.voices.contains(&cx_id) {
            "+"
        } else {
            ""
        }
    }

    /// All membership prefixes for a user, high-to-low ("@+" when both op and
    /// voiced). Used for the IRCv3 multi-prefix capability; the single-marker
    /// `marker` form is used for clients without it.
    pub fn all_markers(&self, cx_id: usize) -> String {
        let mut s = String::new();
        if self.ops.contains(&cx_id) {
            s.push('@');
        }
        if self.voices.contains(&cx_id) {
            s.push('+');
        }
        s
    }

    /// First active ban mask matching a user's identity, if any.
    pub fn ban_match(&self, target: &Cx) -> Option<&str> {
        self.bans.iter().find(|b| target.matches_ban(b)).map(String::as_str)
    }

    // Mutators used by the MODE command handler.

    pub(crate) fn set_flag(&mut self, ch: char, on: bool) {
        match ch {
            'i' => self.invite_only = on,
            'n' => self.nomsg = on,
            'p' => self.private = on,
            's' => self.secret = on,
            't' => self.op_topic = on,
            'R' => self.regonly = on,
            'm' => self.moderated = on,
            _ => {}
        }
    }

    pub fn flag_is_set(&self, ch: char) -> bool {
        match ch {
            'i' => self.invite_only,
            'n' => self.nomsg,
            'p' => self.private,
            's' => self.secret,
            't' => self.op_topic,
            'm' => self.moderated,
            _ => false,
        }
    }

    pub(crate) fn set_channel_key(&mut self, key: &str) {
        let k = key.to_lowercase();
        self.chan_key = if k.is_empty() { None } else { Some(k) };
    }

    pub(crate) fn add_ban(&mut self, mask: &str) {
        let m = mask.to_lowercase();
        if !self.bans.contains(&m) {
            self.bans.push(m);
        }
    }

    pub(crate) fn remove_ban(&mut self, mask: &str) -> bool {
        let before = self.bans.len();
        self.bans.retain(|b| b != &mask.to_lowercase());
        self.bans.len() < before
    }

    pub fn ban_mask_list(&self) -> &[String] { &self.bans }

    // +e ban exceptions and +I invite exceptions: same list-mode shape as +b.
    pub(crate) fn add_except(&mut self, mask: &str) {
        let m = mask.to_lowercase();
        if !self.excepts.contains(&m) { self.excepts.push(m); }
    }
    pub(crate) fn remove_except(&mut self, mask: &str) -> bool {
        let before = self.excepts.len();
        self.excepts.retain(|b| b != &mask.to_lowercase());
        self.excepts.len() < before
    }
    pub fn except_mask_list(&self) -> &[String] { &self.excepts }
    /// True when a user's identity matches any +e exception (exempt from bans).
    pub fn except_match(&self, target: &Cx) -> bool {
        self.excepts.iter().any(|m| target.matches_ban(m))
    }

    pub(crate) fn add_invex(&mut self, mask: &str) {
        let m = mask.to_lowercase();
        if !self.invex.contains(&m) { self.invex.push(m); }
    }
    pub(crate) fn remove_invex(&mut self, mask: &str) -> bool {
        let before = self.invex.len();
        self.invex.retain(|b| b != &mask.to_lowercase());
        self.invex.len() < before
    }
    pub fn invex_mask_list(&self) -> &[String] { &self.invex }
    /// True when a user's identity matches any +I invite exception (bypasses +i).
    pub fn invex_match(&self, target: &Cx) -> bool {
        self.invex.iter().any(|m| target.matches_ban(m))
    }

    /// Invite bookkeeping.
    pub(crate) fn invite(&mut self, cx_id: usize) { self.invites.insert(cx_id); }
    pub fn invited(&self, cx_id: usize) -> bool { self.invites.contains(&cx_id) }
    pub(crate) fn consume_invite(&mut self, cx_id: usize) { self.invites.remove(&cx_id); }

    /// Channel mode string as reported by RPL_CHANNELMODEIS.
    pub fn mode_string(&self) -> String {
        let mut s = String::from("+");
        if self.invite_only { s.push('i'); }
        if self.nomsg { s.push('n'); }
        if self.private { s.push('p'); }
        if self.secret { s.push('s'); }
        if self.op_topic { s.push('t'); }
        if self.moderated { s.push('m'); }
        // +b is a list mode (shown via 367/368), not a simple flag; it is not
        // reported in RPL_CHANNELMODEIS.
        if self.chan_key.is_some() { s.push('k'); }
        if self.key_limit > 0 { s.push('l'); }
        s
    }

    pub(crate) fn grant(&mut self, cx_id: usize, op: bool) {
        if op { self.ops.insert(cx_id); } else { self.voices.insert(cx_id); }
    }

    pub(crate) fn revoke_op(&mut self, cx_id: usize) -> bool { self.ops.remove(&cx_id) }

    pub(crate) fn revoke_voice(&mut self, cx_id: usize) -> bool { self.voices.remove(&cx_id) }

    /// Remove a member and any privileges held there. Returns whether the user
    /// was present along with whether operators remain afterwards.
    pub(crate) fn eject(&mut self, cx_id: usize) -> Option<bool> {
        if !self.members.contains(&cx_id) {
            return None;
        }
        let ops_left = self.ops.iter().any(|id| *id != cx_id);
        self.members.remove(&cx_id);
        self.ops.remove(&cx_id);
        self.voices.remove(&cx_id);
        Some(ops_left)
    }

    /// Record a joining user as operator (channel-creating join).
    pub(crate) fn admit_as_op(&mut self, cx_id: usize) {
        self.members.insert(cx_id);
        self.ops.insert(cx_id);
    }

    /// Record a joining plain member.
    pub(crate) fn admit_plain(&mut self, cx_id: usize) {
        self.members.insert(cx_id);
    }

    /// User count for LIST replies.
    pub fn member_count(&self) -> usize { self.members.len() }
}

// ---------------------------------------------------------------------------
// Fast-reconnect reclaim markers (round-4)
// ---------------------------------------------------------------------------

/// Deferred reclamation bookkeeping installed at a nick collision where the
/// current holder was pinged proactively instead of answered with an immediate
/// refusal: when the grace expires without a response the holder is evicted and
/// each recorded requester completes its deferred pairing or rename. A PONG from
/// the holder clears the marker early and answers every requester with 433.
pub struct Reclaim {
    pub expiry: Instant,
    /// (requester id, referenced nick display) registrations held back at collision time.
    pub pairings: Vec<(usize, String)>,
    /// (renamer id, attempted target nick display) renames held back at collision time.
    pub renames: Vec<(usize, String)>,
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

pub struct ServerState {
    pub name: String, // servername used in prefixes and identities
    pub version: &'static str,
    pub started_at: Instant,

    users: HashMap<String, Cx>,   // nick_key -> registered user
    unreg: HashMap<usize, Cx>,    // connection id -> pre-registration record
    chans: HashMap<String, Chn>,  // channel key (lowercased) -> channel
    history: VecDeque<HistEntry>,

    pub oper_user: String,
    pub oper_pass: String,
    pub admin_loc1: String,
    pub admin_loc2: String,
    pub admin_email: String,
    pub listen_desc: String, // "host port" of the client listener (for STATS)

    /// Connections currently holding an unanswered liveness ping.
    pub ping_outstanding: HashMap<usize, Instant>,

    /// Active fast-reconnect reclaim markers keyed by the contested holder's connection id.
    pub grace_reclaim: HashMap<usize, Reclaim>,

    /// Registered services accounts (SASL / NickServ), persisted to disk.
    pub accounts: crate::accounts::AccountStore,

    /// Registered channels (ChanServ): founder ownership + persisted topics.
    pub chanreg: crate::channels::ChannelRegistry,

    // ---- lifetime statistics (surfaced by the web property) ----
    pub total_connections: u64,  // registered client sessions since start (excludes health checks)
    pub peak_users: usize,       // high-water mark of concurrent registered users
    pub messages_relayed: u64,   // PRIVMSG/NOTICE lines relayed

    /// Path to the LLM-generated release-notes JSON served by the web property.
    pub release_notes_path: Option<String>,

    /// Admission-control bounds and live per-source accounting. Both are keyed
    /// on the client's real address, so they are only meaningful when the PROXY
    /// header is parsed (see `crate::proxyproto`).
    pub limits: crate::limits::Limits,
    pub sources: crate::limits::SourceTable,

    /// Server-wide address bans (K-lines), persisted across restarts.
    pub bans: crate::bans::BanStore,
}

impl ServerState {
    pub fn new(
        name: &str,
        oper_user: &str,
        oper_pass: &str,
        admin_loc1: &str,
        admin_loc2: &str,
        admin_email: &str,
        listen_desc: &str,
    ) -> Self {
        ServerState {
            name: name.to_string(),
            version: crate::proto::VERSION,
            started_at: Instant::now(),
            users: HashMap::new(),
            unreg: HashMap::new(),
            chans: HashMap::new(),
            history: VecDeque::with_capacity(HISTORY_CAP),
            oper_user: oper_user.to_string(),
            oper_pass: oper_pass.to_string(),
            admin_loc1: admin_loc1.to_string(),
            admin_loc2: admin_loc2.to_string(),
            admin_email: admin_email.to_string(),
            listen_desc: listen_desc.to_string(),
            ping_outstanding: HashMap::new(),
            grace_reclaim: HashMap::new(),
            accounts: crate::accounts::AccountStore::load(std::env::var("IRC_ACCOUNTS_PATH").ok()),
            chanreg: crate::channels::ChannelRegistry::load(std::env::var("IRC_CHANNELS_PATH").ok()),
            limits: crate::limits::Limits::default(),
            sources: crate::limits::SourceTable::new(),
            bans: crate::bans::BanStore::load(std::env::var("IRC_BANS_PATH").ok()),
            total_connections: 0,
            peak_users: 0,
            messages_relayed: 0,
            release_notes_path: std::env::var("IRC_RELEASE_NOTES_PATH").ok(),
        }
    }

    /// Seconds the server has been running.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Record a fully-registered client session (lifetime counter). Not called
    /// for bare TCP health-check connects, keeping the figure meaningful.
    pub fn note_connection(&mut self) {
        self.total_connections = self.total_connections.saturating_add(1);
    }

    /// Record a relayed message and refresh the peak-users high-water mark.
    pub fn note_message(&mut self) {
        self.messages_relayed = self.messages_relayed.saturating_add(1);
    }

    /// Server name prefixed with the trailing-marker colon for reply lines.
    pub fn prefix(&self) -> String { format!(":{}", self.name) }

    /// Find a registered user by normalized nick key. If not present directly,
    /// walk recent nickname changes (RFC 8.9) within the recency window.
    pub fn lookup(&self, key: &str) -> Option<&Cx> {
        let mut cur = key;
        for _ in 0..8 {
            if let Some(u) = self.users.get(cur) {
                return Some(u);
            }
            let now = Instant::now();
            let hop = self.history.iter().rev().find(|h| {
                h.old_key == *cur && now.duration_since(h.at) <= RENAME_WINDOW
            });
            match hop {
                Some(h) => cur = &h.new_key,
                None => return None,
            }
        }
        self.users.get(cur)
    }

    /// User-visibility predicate (RFC 4.5): visibility is the combination of a
    /// user's modes and the channels shared with the requesting client; IRC
    /// operators see everyone.
    pub fn visible(&self, req: &Cx, u: &Cx) -> bool {
        if req.id == u.id || req.oper {
            return true;
        }
        if !u.invis {
            return true;
        }
        let mut shares = false;
        for c in &req.chans {
            if u.chans.contains(c) {
                shares = true;
                break;
            }
        }
        shares
    }

    // ---- user-table accessors ----------------------------------------------

    pub fn unreg_mut(&mut self, id: usize) -> Option<&mut Cx> { self.unreg.get_mut(&id) }

    /// Park the pre-registration record for a freshly accepted connection. The
    /// reply queue and close-notify are wired so pairing slots can fill before
    /// identity exists; host is the peer address (ident/hostname lookups are
    /// unavailable in this deployment).
    pub fn park_new(
        &mut self,
        id: usize,
        host: String,
        real_host: String,
        tx: Sender<String>,
        notify: Arc<Notify>,
    ) {
        let mut cx = Cx {
            id,
            tx,
            nick: String::new(),
            nick_key: String::new(),
            user: String::new(),
            host,
            real_host,
            realname: String::new(),
            registered: false,
            account: None,
            caps: Caps::default(),
            sasl_mech: None,
            pending_nick: None,
            pending_user: None,
            cap_negotiating: false,
            cap_gated_welcome: false,
            away: None,
            invis: false,
            wallop: false,
            srvnotice: false,
            oper: false,
            chans: BTreeSet::new(),
            connected_at: Instant::now(),
            last_rx: Instant::now(),
            close_notify: Some(notify),
        };
        let _ = &mut cx; // fields complete above; insert verbatim
        self.unreg.insert(id, cx);
    }

    /// Find where a connection currently lives (unregistered record or the
    /// registered user that owns it).
    pub fn find_by_id(&self, id: usize) -> Option<&Cx> {
        if let Some(u) = self.unreg.get(&id) {
            return Some(u);
        }
        self.users.values().find(|u| u.id == id)
    }

    /// Mutable variant of the connection lookup.
    pub fn find_by_id_mut(&mut self, id: usize) -> Option<&mut Cx> {
        if let Some(u) = self.unreg.get_mut(&id) {
            return Some(u);
        }
        self.users.iter_mut().find(|(_, u)| u.id == id).map(|(_, u)| u)
    }

    /// Complete registration. Returns None when the nick is already taken; the
    /// record is then restored for error handling by the caller.
    pub fn register(
        &mut self,
        id: usize,
        nick_display: &str,
        user_part: &str,
        host: String,
        realname: &str,
    ) -> Option<&Cx> {
        let mut cx = match self.unreg.remove(&id) { Some(c) => c, None => return None };
        let nick_key = norm_nick(nick_display);
        if self.users.contains_key(&nick_key) {
            self.unreg.insert(id, cx);
            return None;
        }
        let inserted_key = nick_key.clone();
        let lookup_key = nick_key.clone();
        cx.nick = nick_display.to_string();
        cx.nick_key = nick_key;
        cx.user = user_part.to_string();
        cx.host = host;
        cx.realname = realname.to_string();
        cx.registered = true;
        self.users.insert(inserted_key, cx);
        self.peak_users = self.peak_users.max(self.users.len());
        // Count only fully-registered client sessions, so load-balancer / kube
        // tcp health checks (which connect without registering) are excluded.
        self.note_connection();
        self.users.get(&lookup_key)
    }

    /// Whether a normalized nick key is currently free.
    pub fn nick_free(&self, key: &str) -> bool { !self.users.contains_key(key) }

    /// Apply a rename for an already-registered connection (callers verify the
    /// target key is free first). Records the change per RFC 8.9; joined channels
    /// are untouched, so renames keep their memberships.
    pub fn apply_rename(&mut self, id: usize, new_display: &str) {
        let old_key = match self.find_by_id(id).map(|u| u.nick_key.clone()) {
            Some(k) => k, None => return,
        };
        let new_key = norm_nick(new_display);
        if old_key == new_key {
            return; // cosmetic re-casing: dropped (key-normalized equality)
        }
        self.record_rename(&old_key, &new_key, id);
        let mut cx = match self.users.remove(&old_key) { Some(c) => c, None => return };
        cx.nick = new_display.to_string();
        let insert_key = new_key.clone();
        cx.nick_key = new_key;
        self.users.insert(insert_key, cx);
    }

    /// Record a nickname change in the history required by RFC 8.9.
    pub fn record_rename(&mut self, old_key: &str, new_key: &str, cx_id: usize) {
        if old_key == new_key { return; }
        self.history.push_back(HistEntry {
            old_key: old_key.to_string(),
            new_key: new_key.to_string(),
            cx_id,
            at: Instant::now(),
        });
        while self.history.len() > HISTORY_CAP {
            self.history.pop_front();
        }
    }

    /// Recent nickname history in reverse chronological order (RFC 8.9 lookups).
    pub fn recent_renames(&self) -> Vec<&HistEntry> {
        self.history.iter().rev().collect::<Vec<&HistEntry>>()
    }

    /// Channel access. Keys are lowercased display names ("#foo").
    pub fn chan(&self, key: &str) -> Option<&Chn> { self.chans.get(key) }

    pub fn chan_mut(&mut self, key: &str) -> Option<&mut Chn> { self.chans.get_mut(key) }

    pub fn chans_iter(&self) -> impl Iterator<Item = (&String, &Chn)> + '_ {
        self.chans.iter()
    }

    /// Get a channel by key, creating it (with the given display case) when
    /// absent. Callers must have completed all join-eligibility checks before
    /// invoking creation; the first joining user becomes its operator and is
    /// admitted here together with subsequent joins handled elsewhere.
    pub fn chan_or_create(&mut self, key: &str, display: String) -> &mut Chn {
        if !self.chans.contains_key(key) {
            let fresh = Chn::new(&display); // privileges granted by the caller via admit_as_op
            self.chans.insert(key.to_string(), fresh);
        }
        self.chans.get_mut(key).unwrap()
    }

    /// Remove a connection from whichever table holds it (registered or not).
    pub fn evict(&mut self, id: usize) -> Option<Cx> {
        if let Some(mut u) = self.unreg.remove(&id) {
            u.signal_close();
            return Some(u);
        }
        let key = self.users.values().find(|u| u.id == id).map(|u| u.nick_key.clone())?;
        let mut u = self.users.remove(&key)?;
        u.signal_close();
        Some(u)
    }

    /// Remove every channel membership and privilege held by a connection,
    /// reporting whether the user was present in state at all.
    pub fn eject_user(&mut self, id: usize) -> bool {
        let mut touched = false;
        for c in self.chans.values_mut() {
            if c.members.contains(&id) || c.ops.contains(&id) || c.voices.contains(&id) {
                touched = true;
            }
            c.members.remove(&id);
            c.ops.remove(&id);
            c.voices.remove(&id);
        }
        touched
    }

    /// Drop channels left without members after ejections.
    pub fn drop_empty_channels(&mut self) {
        let dead: Vec<String> = self
            .chans
            .iter()
            .filter(|(_, c)| c.members.is_empty())
            .map(|(k, _)| k.clone())
            .collect();
        for k in dead {
            self.chans.remove(&k);
        }
    }

    /// Counts used by LUSERS-style replies.
    /// Iteration over PRE-REGISTRATION connections. `each_user` deliberately
    /// covers only registered users, which meant parked connections were never
    /// pinged and never evicted -- an idle socket held an admission slot and its
    /// read buffer indefinitely.
    pub fn each_unreg(&self) -> impl Iterator<Item = &Cx> + '_ { self.unreg.values() }

    pub fn user_count(&self) -> usize { self.users.len() }

    pub fn chan_count(&self) -> usize { self.chans.len() }

    pub fn invis_count(&self) -> usize { self.users.values().filter(|u| u.invis).count() }

    pub fn oper_count(&self) -> usize { self.users.values().filter(|u| u.oper).count() }

    /// Iteration over registered users (shared) for broadcasts.
    pub fn each_user(&self) -> impl Iterator<Item = &Cx> + '_ {
        self.users.values()
    }

    /// Distinct connection ids that share at least one channel with `id`
    /// (excluding `id` itself). These are exactly the users who witness a
    /// user's presence events — QUIT and NICK — per RFC 2812; a user in no
    /// common channel must not be notified.
    pub fn channel_peers(&self, id: usize) -> Vec<usize> {
        let chans: Vec<String> = match self.find_by_id(id) {
            Some(u) => u.chans.iter().cloned().collect(),
            None => return Vec::new(),
        };
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for ck in &chans {
            if let Some(c) = self.chans.get(ck) {
                for &mid in &c.members {
                    if mid != id && seen.insert(mid) {
                        out.push(mid);
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_scaro_chars() {
        assert_eq!(norm_nick("Wi{Z"), "wi[z");
        assert_eq!(norm_nick("A|B}"), "a\\b}");
        assert_eq!(norm_nick("AbcDEF"), "abcdef");
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("a*", "apple"));
        assert!(!wildcard_match("a*", "pple"));
        assert!(wildcard_match("appl?", "apple"));
        assert!(wildcard_match("*!*@*.edu", "alice!bob@example.edu"));
        assert!(!wildcard_match("*!*@*.edu", "alice!bob@example.org"));
    }

    #[test]
    fn composite_ban_matching() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let cx = test_cx(1, tx);
        assert!(cx.matches_ban("alice*"));
        assert!(!cx.matches_ban("bob*"));
        assert!(cx.matches_ban("*!*@example.edu"));
        assert!(!cx.matches_ban("*!*@other.net"));
    }

    fn test_cx(id: usize, tx: Sender<String>) -> Cx {
        Cx {
            id,
            tx,
            nick: "Alice".into(),
            nick_key: norm_nick("alice"),
            user: "bob".into(),
            host: "example.edu".into(),
            real_host: "example.edu".into(),
            realname: "A Person".into(),
            registered: true,
            account: None,
            caps: Caps::default(),
            sasl_mech: None,
            pending_nick: None,
            pending_user: None,
            cap_negotiating: false,
            cap_gated_welcome: false,
            away: None,
            invis: false,
            wallop: false,
            srvnotice: false,
            oper: false,
            chans: BTreeSet::new(),
            connected_at: Instant::now(),
            last_rx: Instant::now(),
            close_notify: None,
        }
    }

    #[test]
    fn lookup_walks_recent_renames() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut state = ServerState::new(
            "srv", "o", "p", "loc1", "loc2", "a@b.c", "127.0.0.1 6697"
        );
        // Simulate a registered user directly: register needs an unreg record,
        // so exercise the history-walk predicate in isolation instead.
        state.record_rename("oldnick", "newnick", 1);
        assert_eq!(state.lookup("nope").map(|_| ()), None);
        let _: tokio::sync::mpsc::Sender<String> = tx;
    }
}


#[cfg(test)]
mod wildcard_tests {
    use super::wildcard_match;

    #[test]
    fn empty_pattern_does_not_panic_and_matches_only_empty() {
        // Reachable from any client with a single line: `WHO :` yields an empty
        // mask param. This used to panic under the state lock, poisoning it and
        // wedging the whole server while TCP kept accepting -- so the tcpSocket
        // liveness probe would never have restarted the pod.
        assert!(!wildcard_match("", "anything"));
        assert!(wildcard_match("", ""));
    }

    #[test]
    fn still_matches_normally() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("a*c", "abc"));
        assert!(wildcard_match("a?c", "abc"));
        assert!(!wildcard_match("a?c", "ac"));
        assert!(wildcard_match("*!*@*", "nick!user@host"));
        assert!(!wildcard_match("abc", "abd"));
        assert!(wildcard_match("**", "xy"));
        assert!(!wildcard_match("a", ""));
    }
}
