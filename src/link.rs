//! InspIRCd spanning-tree protocol: the wire half of server linking.
//!
//! Deliberately a pure state machine. `handle_line` consumes one inbound line
//! and returns events for the caller to apply to server state, while outbound
//! lines queue up for the caller to write. Nothing here touches a socket, so
//! the whole protocol is testable without one -- which matters more than usual
//! for linking, where the characteristic failure is two servers quietly
//! disagreeing rather than anything crashing.
//!
//! Compatibility notes, all verified against InspIRCd 4.11.0 (see
//! `tests/interop/`):
//!
//! * Protocol 1205 is offered. A 4.11 server accepts 1205 and 1206
//!   (`PROTO_OLDEST` / `PROTO_NEWEST` in `treesocket.h`), so one implementation
//!   speaking 1205 links to both InspIRCd v3 and v4.
//! * `CAPAB CHANMODES`, `USERMODES`, `EXTBANS` and the `CASEMAPPING` key are
//!   deliberately NOT sent. Every comparison in InspIRCd's `capab.cpp` is
//!   guarded by `if (!capab->X.empty())`, so a peer that stays quiet is never
//!   compared and a reduced mode set cannot fail the link. Sending any of them
//!   with values that differ is refused -- confirmed by negative control.

use crate::network::RemoteUser;
use crate::proto::{self, Command};

/// The protocol version we speak. 1205 reaches both InspIRCd v3 and v4.
pub const PROTO_VERSION: &str = "1205";

/// How far the handshake has progressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Capability negotiation in progress.
    Capab,
    /// Peer authenticated; state exchange under way.
    Bursting,
    /// Peer finished its burst. The link is live.
    Linked,
    /// Refused or torn down.
    Dead,
}

pub struct LinkConfig {
    pub sid: String,
    pub name: String,
    pub desc: String,
    pub send_password: String,
    pub recv_password: String,
}

/// Something that happened on the link and must be applied to server state.
#[derive(Debug, PartialEq)]
pub enum Event {
    /// The peer authenticated. Carries its SID, name and description.
    PeerRegistered { sid: String, name: String, desc: String },
    /// Another server behind the peer was introduced.
    ServerIntroduced { sid: String, name: String, desc: String, via: String },
    UserIntroduced(Box<RemoteUser>),
    UserQuit { uuid: String, reason: String },
    NickChanged { uuid: String, nick: String },
    /// Channel state from a burst or a remote join.
    ChannelJoin { chan: String, ts: u64, modes: String, members: Vec<(String, String)> },
    /// A single user joining an already-known channel.
    RemoteJoin { chan: String, uuid: String },
    RemotePart { chan: String, uuid: String, reason: String },
    Message { from: String, target: String, text: String, notice: bool },
    ModeChange { target: String, ts: u64, modes: Vec<String> },
    TopicChanged { chan: String, ts: u64, setter: String, topic: String },
    Away { uuid: String, reason: Option<String> },
    /// The peer finished bursting; the link is live.
    BurstComplete,
    /// A server (and everything behind it) left.
    ServerSplit { sid: String, reason: String },
    /// The link failed. Carries the reason the peer gave, if any.
    Failed(String),
}

pub struct LinkSession {
    cfg: LinkConfig,
    pub phase: Phase,
    pub peer_sid: Option<String>,
    pub peer_name: Option<String>,
    /// True when we opened the connection, false when the peer did.
    outbound_link: bool,
    /// Whether our own SERVER line has been sent.
    sent_server: bool,
    /// Whether our burst has been sent.
    sent_burst: bool,
    out: Vec<String>,
}

impl LinkSession {
    pub fn new(cfg: LinkConfig, outbound_link: bool) -> Self {
        LinkSession {
            cfg,
            phase: Phase::Capab,
            peer_sid: None,
            peer_name: None,
            outbound_link,
            sent_server: false,
            sent_burst: false,
            out: Vec::new(),
        }
    }

    fn send(&mut self, line: impl Into<String>) {
        self.out.push(line.into());
    }

    /// Lines queued for the peer since the last call.
    pub fn take_outbound(&mut self) -> Vec<String> {
        std::mem::take(&mut self.out)
    }

    /// Begin the handshake. The side that opened the connection speaks first.
    pub fn begin(&mut self) {
        self.send_capab();
        if self.outbound_link {
            self.send_server();
        }
    }

    fn send_capab(&mut self) {
        self.send(format!("CAPAB START {}", PROTO_VERSION));
        // No CHANMODES / USERMODES / EXTBANS, and no CASEMAPPING key: each is
        // compared only when sent, and sending a set that differs from the
        // peer's is refused outright.
        self.send(
            "CAPAB CAPABILITIES :NICKMAX=30 CHANMAX=50 MAXMODES=20 IDENTMAX=10 \
             MAXQUIT=255 MAXTOPIC=390 MAXKICK=255 MAXREAL=128 MAXAWAY=200 MAXHOST=64 MAXLINE=512",
        );
        self.send("CAPAB END");
    }

    fn send_server(&mut self) {
        if self.sent_server {
            return;
        }
        self.sent_server = true;
        // Protocol 1205 carries an unused field between password and SID; it was
        // "intended for a feature that was never implemented" and removed in 1206.
        self.send(format!(
            "SERVER {} {} 0 {} :{}",
            self.cfg.name, self.cfg.send_password, self.cfg.sid, self.cfg.desc
        ));
    }

    /// Queue our own state dump. `users` and `channels` are pre-rendered by the
    /// caller, which owns local state.
    pub fn send_burst(&mut self, now: u64, users: Vec<String>, channels: Vec<String>) {
        if self.sent_burst {
            return;
        }
        self.sent_burst = true;
        let sid = self.cfg.sid.clone();
        self.send(format!(":{} BURST {}", sid, now));
        self.send(format!(":{} SINFO version :{} {} :", sid, crate::proto::VERSION, self.cfg.name));
        for line in users {
            self.send(line);
        }
        for line in channels {
            self.send(line);
        }
        self.send(format!(":{} ENDBURST", sid));
    }

    /// Consume one inbound line, returning whatever it means for server state.
    pub fn handle_line(&mut self, raw: &str) -> Vec<Event> {
        if self.phase == Phase::Dead {
            return Vec::new();
        }
        // ERROR is not a normal command and may arrive without a prefix.
        if raw.starts_with("ERROR") {
            self.phase = Phase::Dead;
            let reason = raw.splitn(2, ':').nth(1).unwrap_or("").to_string();
            return vec![Event::Failed(reason)];
        }
        let cmd = match proto::parse(raw) {
            Some(c) => c,
            None => return Vec::new(),
        };
        let source = cmd.prefix.clone().unwrap_or_default();
        match cmd.name.as_str() {
            "CAPAB" => self.on_capab(&cmd),
            "SERVER" => self.on_server(&cmd, &source),
            "BURST" => Vec::new(),
            "ENDBURST" => {
                if self.phase == Phase::Bursting {
                    self.phase = Phase::Linked;
                }
                vec![Event::BurstComplete]
            }
            "UID" => self.on_uid(&cmd, &source),
            "QUIT" => vec![Event::UserQuit {
                uuid: source,
                reason: cmd.params.first().cloned().unwrap_or_default(),
            }],
            "NICK" => self.on_nick(&cmd, &source),
            "FJOIN" => self.on_fjoin(&cmd),
            "IJOIN" => self.on_ijoin(&cmd, &source),
            "PART" => vec![Event::RemotePart {
                chan: cmd.params.first().cloned().unwrap_or_default(),
                uuid: source,
                reason: cmd.params.get(1).cloned().unwrap_or_default(),
            }],
            "PRIVMSG" | "NOTICE" => self.on_message(&cmd, &source),
            "FMODE" => self.on_fmode(&cmd),
            "FTOPIC" => self.on_ftopic(&cmd, &source),
            "AWAY" => vec![Event::Away {
                uuid: source,
                reason: cmd.params.first().filter(|r| !r.is_empty()).cloned(),
            }],
            "PING" => self.on_ping(&cmd, &source),
            "SQUIT" => vec![Event::ServerSplit {
                sid: cmd.params.first().cloned().unwrap_or_default(),
                reason: cmd.params.get(1).cloned().unwrap_or_default(),
            }],
            // Everything else is either informational (SINFO, METADATA) or a
            // feature we do not implement. Silently ignoring is correct: the
            // peer does not expect an answer, and erroring would drop the link.
            _ => Vec::new(),
        }
    }

    fn on_capab(&mut self, cmd: &Command) -> Vec<Event> {
        // The peer announces its own modes and modules; none of it obliges us,
        // and CAPAB END is where InspIRCd decides. Answer an inbound link's
        // CAPAB START with our own.
        if cmd.params.first().map(|s| s.eq_ignore_ascii_case("START")).unwrap_or(false)
            && !self.outbound_link
            && !self.sent_server
        {
            self.send_server();
        }
        Vec::new()
    }

    fn on_server(&mut self, cmd: &Command, source: &str) -> Vec<Event> {
        // A prefixed SERVER introduces a server further out on the tree.
        if !source.is_empty() && self.peer_sid.is_some() {
            // 1205: <name> <pass> <unused> <sid> :<desc>
            let name = cmd.params.first().cloned().unwrap_or_default();
            let sid = cmd.params.get(3).cloned().unwrap_or_default();
            let desc = cmd.params.get(4).cloned().unwrap_or_default();
            if sid.is_empty() {
                return Vec::new();
            }
            return vec![Event::ServerIntroduced { sid, name, desc, via: source.to_string() }];
        }

        let name = cmd.params.first().cloned().unwrap_or_default();
        let pass = cmd.params.get(1).cloned().unwrap_or_default();
        // 1205 has an unused field before the SID; 1206 does not. Accept either
        // by taking the last parameter before the description that looks like a SID.
        let sid = cmd
            .params
            .get(3)
            .filter(|s| crate::network::valid_sid(s))
            .or_else(|| cmd.params.get(2).filter(|s| crate::network::valid_sid(s)))
            .cloned()
            .unwrap_or_default();
        let desc = cmd.params.last().cloned().unwrap_or_default();

        if pass != self.cfg.recv_password {
            self.phase = Phase::Dead;
            self.send("ERROR :Link password mismatch");
            return vec![Event::Failed("link password mismatch".into())];
        }
        if !crate::network::valid_sid(&sid) {
            self.phase = Phase::Dead;
            self.send("ERROR :Invalid SID");
            return vec![Event::Failed(format!("invalid SID {sid:?}"))];
        }

        self.peer_sid = Some(sid.clone());
        self.peer_name = Some(name.clone());
        self.phase = Phase::Bursting;

        // An inbound link has not sent its SERVER yet at this point.
        if !self.outbound_link {
            self.send_server();
        }
        vec![Event::PeerRegistered { sid, name, desc }]
    }

    fn on_uid(&mut self, cmd: &Command, source: &str) -> Vec<Event> {
        // UID <uuid> <nickts> <nick> <realhost> <displayhost> <ident> <ip>
        //     <signonts> <modes> [<modeparams>...] :<realname>
        if cmd.params.len() < 10 {
            return Vec::new();
        }
        let uuid = cmd.params[0].clone();
        if !crate::network::valid_uuid(&uuid) {
            return Vec::new();
        }
        let nick = cmd.params[2].clone();
        let realname = cmd.params.last().cloned().unwrap_or_default();
        vec![Event::UserIntroduced(Box::new(RemoteUser {
            sid: if source.is_empty() { uuid[..3].to_string() } else { source.to_string() },
            nick_key: crate::state::norm_nick(&nick),
            nick,
            uuid,
            ts: cmd.params[1].parse().unwrap_or(0),
            real_host: cmd.params[3].clone(),
            host: cmd.params[4].clone(),
            user: cmd.params[5].clone(),
            modes: cmd.params[8].clone(),
            realname,
            chans: Default::default(),
            away: None,
            oper: false,
        }))]
    }

    fn on_nick(&mut self, cmd: &Command, source: &str) -> Vec<Event> {
        match cmd.params.first() {
            Some(n) if !source.is_empty() => {
                vec![Event::NickChanged { uuid: source.to_string(), nick: n.clone() }]
            }
            _ => Vec::new(),
        }
    }

    fn on_fjoin(&mut self, cmd: &Command) -> Vec<Event> {
        // FJOIN <chan> <ts> <modes> [<params>...] :[<prefixes>,<uuid>[:<membid>]]+
        if cmd.params.len() < 4 {
            return Vec::new();
        }
        let chan = cmd.params[0].clone();
        let ts: u64 = cmd.params[1].parse().unwrap_or(0);
        let modes = cmd.params[2].clone();
        let members = parse_members(cmd.params.last().map(String::as_str).unwrap_or(""));
        vec![Event::ChannelJoin { chan, ts, modes, members }]
    }

    fn on_ijoin(&mut self, cmd: &Command, source: &str) -> Vec<Event> {
        match cmd.params.first() {
            Some(c) if !source.is_empty() => {
                vec![Event::RemoteJoin { chan: c.clone(), uuid: source.to_string() }]
            }
            _ => Vec::new(),
        }
    }

    fn on_message(&mut self, cmd: &Command, source: &str) -> Vec<Event> {
        if cmd.params.len() < 2 || source.is_empty() {
            return Vec::new();
        }
        vec![Event::Message {
            from: source.to_string(),
            target: cmd.params[0].clone(),
            text: cmd.params[1].clone(),
            notice: cmd.name == "NOTICE",
        }]
    }

    fn on_fmode(&mut self, cmd: &Command) -> Vec<Event> {
        // FMODE <target> <ts> <modes> [<params>...]
        if cmd.params.len() < 3 {
            return Vec::new();
        }
        vec![Event::ModeChange {
            target: cmd.params[0].clone(),
            ts: cmd.params[1].parse().unwrap_or(0),
            modes: cmd.params[2..].to_vec(),
        }]
    }

    fn on_ftopic(&mut self, cmd: &Command, source: &str) -> Vec<Event> {
        // FTOPIC <chan> <chants> <topicts> [<setter>] :<topic>
        //
        // The setter is optional -- InspIRCd sends the four-parameter form and
        // falls back to the message source. The topic is always the LAST
        // parameter, not a fixed index. Requiring five silently dropped every
        // inbound topic change.
        if cmd.params.len() < 4 {
            return Vec::new();
        }
        let setter = if cmd.params.len() > 4 {
            cmd.params[3].clone()
        } else {
            source.to_string()
        };
        vec![Event::TopicChanged {
            chan: cmd.params[0].clone(),
            ts: cmd.params[2].parse().unwrap_or(0),
            setter,
            topic: cmd.params.last().cloned().unwrap_or_default(),
        }]
    }

    fn on_ping(&mut self, cmd: &Command, source: &str) -> Vec<Event> {
        // PING <from> <to>; the answer swaps them. A link that stops answering
        // is dropped by the peer, so this must never be conditional.
        let from = cmd.params.first().cloned().unwrap_or_else(|| source.to_string());
        let to = cmd.params.get(1).cloned().unwrap_or_else(|| self.cfg.sid.clone());
        self.send(format!(":{} PONG {} {}", to, to, from));
        Vec::new()
    }
}

/// Parse an FJOIN membership list: `prefixes,uuid[:membid]` separated by spaces.
///
/// Returns (prefix-modes, uuid). The membership id is discarded: it exists so a
/// server can distinguish two joins of the same user, which only matters for
/// features we do not implement.
pub fn parse_members(list: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in list.split(' ').filter(|e| !e.is_empty()) {
        let (prefixes, rest) = match entry.split_once(',') {
            Some(p) => p,
            None => continue,
        };
        let uuid = rest.split(':').next().unwrap_or(rest);
        if crate::network::valid_uuid(uuid) {
            out.push((prefixes.to_string(), uuid.to_string()));
        }
    }
    out
}

/// Render a local user as the UID line that introduces them to the network.
#[allow(clippy::too_many_arguments)]
pub fn uid_line(
    sid: &str,
    uuid: &str,
    nick_ts: u64,
    nick: &str,
    real_host: &str,
    display_host: &str,
    ident: &str,
    ip: &str,
    signon_ts: u64,
    modes: &str,
    realname: &str,
) -> String {
    format!(
        ":{sid} UID {uuid} {nick_ts} {nick} {real_host} {display_host} {ident} {ip} {signon_ts} {modes} :{realname}"
    )
}

/// Render a channel as the FJOIN line that introduces it.
pub fn fjoin_line(sid: &str, chan: &str, ts: u64, modes: &str, members: &[(String, String)]) -> String {
    let list = members
        .iter()
        .map(|(p, u)| format!("{},{}", p, u))
        .collect::<Vec<_>>()
        .join(" ");
    format!(":{sid} FJOIN {chan} {ts} {modes} :{list}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LinkConfig {
        LinkConfig {
            sid: "2CH".into(),
            name: "chonk.test".into(),
            desc: "Chonkline".into(),
            send_password: "pw".into(),
            recv_password: "pw".into(),
        }
    }

    fn linked() -> LinkSession {
        let mut s = LinkSession::new(cfg(), true);
        s.begin();
        s.take_outbound();
        s.handle_line("SERVER insp.test pw 0 1IN :InspIRCd");
        s.take_outbound();
        s
    }

    #[test]
    fn the_opening_capab_omits_every_compared_list() {
        let mut s = LinkSession::new(cfg(), true);
        s.begin();
        let out = s.take_outbound().join("\n");
        assert!(out.contains("CAPAB START 1205"));
        assert!(out.contains("CAPAB END"));
        // Each of these is compared by InspIRCd only when sent, and a mismatch
        // is refused. Staying quiet is what makes a reduced mode set linkable.
        assert!(!out.contains("CHANMODES"), "must not advertise channel modes");
        assert!(!out.contains("USERMODES"), "must not advertise user modes");
        assert!(!out.contains("EXTBANS"), "must not advertise extbans");
        assert!(!out.contains("CASEMAPPING"), "must not advertise casemapping");
    }

    #[test]
    fn the_server_line_carries_the_1205_unused_field() {
        let mut s = LinkSession::new(cfg(), true);
        s.begin();
        let line = s.take_outbound().into_iter().find(|l| l.starts_with("SERVER ")).unwrap();
        assert_eq!(line, "SERVER chonk.test pw 0 2CH :Chonkline");
    }

    #[test]
    fn a_peer_with_the_right_password_registers() {
        let mut s = LinkSession::new(cfg(), true);
        s.begin();
        s.take_outbound();
        let ev = s.handle_line("SERVER insp.test pw 0 1IN :InspIRCd");
        assert_eq!(
            ev,
            vec![Event::PeerRegistered { sid: "1IN".into(), name: "insp.test".into(), desc: "InspIRCd".into() }]
        );
        assert_eq!(s.phase, Phase::Bursting);
        assert_eq!(s.peer_sid.as_deref(), Some("1IN"));
    }

    #[test]
    fn a_wrong_password_kills_the_link() {
        let mut s = LinkSession::new(cfg(), true);
        s.begin();
        s.take_outbound();
        let ev = s.handle_line("SERVER insp.test WRONG 0 1IN :InspIRCd");
        assert!(matches!(ev.as_slice(), [Event::Failed(_)]));
        assert_eq!(s.phase, Phase::Dead);
        assert!(s.take_outbound().iter().any(|l| l.starts_with("ERROR")));
    }

    #[test]
    fn the_1206_server_form_is_accepted_too() {
        // 1206 dropped the unused field. Accepting both costs one lookup and
        // means a peer that negotiated up does not break us.
        let mut s = LinkSession::new(cfg(), true);
        s.begin();
        s.take_outbound();
        let ev = s.handle_line("SERVER insp.test pw 1IN :InspIRCd");
        assert!(matches!(ev.as_slice(), [Event::PeerRegistered { .. }]), "got {ev:?}");
    }

    #[test]
    fn endburst_completes_the_link() {
        let mut s = linked();
        assert_eq!(s.phase, Phase::Bursting);
        let ev = s.handle_line(":1IN ENDBURST");
        assert_eq!(ev, vec![Event::BurstComplete]);
        assert_eq!(s.phase, Phase::Linked);
    }

    #[test]
    fn a_uid_introduces_a_user() {
        let mut s = linked();
        let ev = s.handle_line(
            ":1IN UID 1INAAAAAB 1665473547 alice 10.0.0.1 cloak.example serverone 10.0.0.1 1665473527 + :Alice",
        );
        match ev.as_slice() {
            [Event::UserIntroduced(u)] => {
                assert_eq!(u.uuid, "1INAAAAAB");
                assert_eq!(u.nick, "alice");
                assert_eq!(u.real_host, "10.0.0.1");
                assert_eq!(u.host, "cloak.example", "display host, not the real one");
                assert_eq!(u.user, "serverone");
                assert_eq!(u.realname, "Alice");
                assert_eq!(u.sid, "1IN");
            }
            other => panic!("expected one user, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_uid_is_ignored_rather_than_fatal() {
        let mut s = linked();
        assert!(s.handle_line(":1IN UID short 1 a b c d e f + :x").is_empty());
        assert!(s.handle_line(":1IN UID").is_empty());
        assert_eq!(s.phase, Phase::Bursting, "a bad line must not drop the link");
    }

    #[test]
    fn fjoin_membership_parses_prefixes_and_ignores_membership_ids() {
        let m = parse_members("o,1INAAAAAB:2 ,1INAAAAAC ov,1INAAAAAD:7");
        assert_eq!(
            m,
            vec![
                ("o".to_string(), "1INAAAAAB".to_string()),
                (String::new(), "1INAAAAAC".to_string()),
                ("ov".to_string(), "1INAAAAAD".to_string()),
            ]
        );
    }

    #[test]
    fn fjoin_yields_a_channel_with_its_timestamp() {
        let mut s = linked();
        let ev = s.handle_line(":1IN FJOIN #test 1665473560 +nt :o,1INAAAAAB:2");
        match ev.as_slice() {
            [Event::ChannelJoin { chan, ts, modes, members }] => {
                assert_eq!(chan, "#test");
                assert_eq!(*ts, 1665473560);
                assert_eq!(modes, "+nt");
                assert_eq!(members.len(), 1);
                assert_eq!(members[0].1, "1INAAAAAB");
            }
            other => panic!("expected a channel join, got {other:?}"),
        }
    }

    #[test]
    fn a_ping_is_always_answered() {
        // A link that stops answering PING is dropped by the peer, so this must
        // never depend on phase or on any other state.
        let mut s = linked();
        s.handle_line(":1IN PING 1IN 2CH");
        let out = s.take_outbound();
        assert_eq!(out, vec![":2CH PONG 2CH 1IN"]);
    }

    #[test]
    fn messages_carry_their_source_uuid() {
        let mut s = linked();
        let ev = s.handle_line(":1INAAAAAB PRIVMSG #test :hello");
        assert_eq!(
            ev,
            vec![Event::Message {
                from: "1INAAAAAB".into(),
                target: "#test".into(),
                text: "hello".into(),
                notice: false
            }]
        );
        let ev = s.handle_line(":1INAAAAAB NOTICE #test :hi");
        assert!(matches!(ev.as_slice(), [Event::Message { notice: true, .. }]));
    }

    #[test]
    fn an_error_line_ends_the_session() {
        let mut s = linked();
        let ev = s.handle_line("ERROR :CAPAB negotiation failed: something");
        assert!(matches!(ev.as_slice(), [Event::Failed(_)]));
        assert_eq!(s.phase, Phase::Dead);
        assert!(s.handle_line(":1IN UID 1INAAAAAB 1 a b c d e 1 + :x").is_empty(),
            "a dead session must process nothing further");
    }

    #[test]
    fn unknown_commands_are_ignored_not_fatal() {
        // InspIRCd sends SINFO, METADATA and much else we do not implement.
        // Erroring on any of them would drop the link on connect.
        let mut s = linked();
        assert!(s.handle_line(":1IN SINFO version :InspIRCd-4 insp.test :").is_empty());
        assert!(s.handle_line(":1IN METADATA #test 123 maxlist :b 100").is_empty());
        assert!(s.handle_line(":1IN SOMETHINGNEW a b c").is_empty());
        assert_eq!(s.phase, Phase::Bursting, "none of that may kill the link");
    }

    #[test]
    fn a_split_reports_the_departing_server() {
        let mut s = linked();
        let ev = s.handle_line(":1IN SQUIT 2IN :Ping timeout");
        assert_eq!(ev, vec![Event::ServerSplit { sid: "2IN".into(), reason: "Ping timeout".into() }]);
    }

    #[test]
    fn rendering_round_trips_through_the_parser() {
        let line = uid_line("2CH", "2CHAAAAAA", 100, "bob", "10.0.0.2", "cloak", "bob", "10.0.0.2", 90, "+i", "Bob Smith");
        let mut s = linked();
        match s.handle_line(&line).as_slice() {
            [Event::UserIntroduced(u)] => {
                assert_eq!(u.nick, "bob");
                assert_eq!(u.realname, "Bob Smith", "a realname with a space survives");
                assert_eq!(u.modes, "+i");
            }
            other => panic!("expected a user, got {other:?}"),
        }

        let fj = fjoin_line("2CH", "#x", 55, "+nt", &[("o".into(), "2CHAAAAAA".into())]);
        match s.handle_line(&fj).as_slice() {
            [Event::ChannelJoin { members, ts, .. }] => {
                assert_eq!(*ts, 55);
                assert_eq!(members[0], ("o".into(), "2CHAAAAAA".into()));
            }
            other => panic!("expected a channel, got {other:?}"),
        }
    }

    #[test]
    fn an_inbound_link_answers_capab_with_its_own_server_line() {
        // The side that did not open the connection must still introduce itself,
        // or the peer waits forever and times the link out.
        let mut s = LinkSession::new(cfg(), false);
        s.begin();
        let opening = s.take_outbound().join("\n");
        assert!(!opening.contains("SERVER "), "an inbound link does not speak first");
        s.handle_line("CAPAB START 1205");
        let after = s.take_outbound().join("\n");
        assert!(after.contains("SERVER chonk.test"), "must introduce itself, got {after:?}");
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::state::ServerState;

/// Depth of a link's outbound queue. Bounded for the same reason client reply
/// queues are: a peer that stops reading must cost a known amount of memory.
const LINK_QUEUE: usize = 4096;

/// How often to ping a peer, and how long it may stay silent before the link is
/// considered dead. The timeout is a comfortable multiple of the interval so a
/// slow peer is not dropped for one missed reply.
const KEEPALIVE_SECS: u64 = 60;
const LINK_TIMEOUT_SECS: u64 = 300;

/// A live link, as seen from the rest of the server.
pub struct LinkHandle {
    pub sid: String,
    pub name: String,
    pub tx: tokio::sync::mpsc::Sender<String>,
}

/// Link settings from the environment. Returns None when linking is off, which
/// is the default: a server with no peers configured behaves exactly as before.
pub fn configured() -> Option<(LinkConfig, Option<u16>, Vec<String>)> {
    let sid = std::env::var("IRC_SID").ok()?;
    if !crate::network::valid_sid(&sid) {
        crate::log::event(crate::log::ERROR, "link.bad_sid", &[("sid", &sid)]);
        return None;
    }
    let cfg = LinkConfig {
        sid,
        name: std::env::var("IRC_SERVER_NAME").unwrap_or_else(|_| "chonkline".into()),
        desc: std::env::var("IRC_NETWORK_DESC").unwrap_or_else(|_| "Chonkline".into()),
        send_password: std::env::var("IRC_LINK_SEND_PASSWORD")
            .or_else(|_| std::env::var("IRC_LINK_PASSWORD"))
            .unwrap_or_default(),
        recv_password: std::env::var("IRC_LINK_RECV_PASSWORD")
            .or_else(|_| std::env::var("IRC_LINK_PASSWORD"))
            .unwrap_or_default(),
    };
    let listen = std::env::var("IRC_LINK_PORT").ok().and_then(|v| v.parse::<u16>().ok());
    let peers = std::env::var("IRC_LINK_PEERS")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    Some((cfg, listen, peers))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Drive one link to completion over an established stream.
pub async fn run_session(
    state: Arc<Mutex<ServerState>>,
    stream: TcpStream,
    cfg: LinkConfig,
    outbound_link: bool,
) {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let our_sid = cfg.sid.clone();
    let mut session = LinkSession::new(cfg, outbound_link);
    let (rd, mut wr) = stream.into_split();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(LINK_QUEUE);

    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if wr.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if wr.write_all(b"\r\n").await.is_err() {
                break;
            }
            let _ = wr.flush().await;
        }
    });

    let flush = |session: &mut LinkSession, tx: &tokio::sync::mpsc::Sender<String>| {
        for line in session.take_outbound() {
            if tx.try_send(line).is_err() {
                crate::log::counted("link.output_dropped", "");
            }
        }
    };

    session.begin();
    flush(&mut session, &tx);
    crate::log::event(crate::log::INFO, "link.open", &[("peer", &peer), ("dir", if outbound_link { "out" } else { "in" })]);

    let mut lines = BufReader::new(rd).lines();
    let mut registered_sid: Option<String> = None;

    // Keepalive. Without it a peer that stops answering is never noticed and
    // its users stay in our view indefinitely -- a split that never gets
    // announced is worse than one that does.
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(KEEPALIVE_SECS));
    keepalive.tick().await; // the first tick fires immediately
    let mut last_rx = std::time::Instant::now();

    loop {
        let line = tokio::select! {
            read = lines.next_line() => match read {
                Ok(Some(l)) => l,
                _ => break,
            },
            _ = keepalive.tick() => {
                if last_rx.elapsed() > std::time::Duration::from_secs(LINK_TIMEOUT_SECS) {
                    crate::log::event(crate::log::WARN, "link.timeout",
                        &[("peer", &peer), ("silent_secs", &last_rx.elapsed().as_secs().to_string())]);
                    break;
                }
                if let Some(sid) = session.peer_sid.clone() {
                    let ours = our_sid.clone();
                    if tx.try_send(format!(":{} PING {} {}", ours, ours, sid)).is_err() {
                        break;
                    }
                }
                continue;
            }
        };
        last_rx = std::time::Instant::now();
        if line.trim().is_empty() {
            continue;
        }
        let events = session.handle_line(&line);
        for ev in events {
            match ev {
                Event::PeerRegistered { ref sid, ref name, ref desc } => {
                    registered_sid = Some(sid.clone());
                    {
                        let mut stg = state.lock().unwrap_or_else(|e| e.into_inner());
                        stg.network.add_server(crate::network::RemoteServer {
                            sid: sid.clone(),
                            name: name.clone(),
                            desc: desc.clone(),
                            hop: 1,
                            via: sid.clone(),
                            bursting: true,
                        });
                        stg.links.push(LinkHandle { sid: sid.clone(), name: name.clone(), tx: tx.clone() });
                    }
                    crate::log::event(crate::log::INFO, "link.registered", &[("sid", sid), ("name", name)]);
                    // Our own state goes out as soon as the peer is known.
                    let (users, chans) = {
                        let stg = state.lock().unwrap_or_else(|e| e.into_inner());
                        (stg.burst_users(&our_sid), stg.burst_channels(&our_sid))
                    };
                    session.send_burst(now_secs(), users, chans);
                }
                other => apply_event(&state, other),
            }
        }
        flush(&mut session, &tx);
        if session.phase == Phase::Dead {
            break;
        }
    }

    // Teardown: the peer and everything behind it is gone.
    if let Some(sid) = registered_sid {
        let lost = {
            let mut stg = state.lock().unwrap_or_else(|e| e.into_inner());
            stg.links.retain(|l| l.sid != sid);
            stg.network.split_server(&sid)
        };
        crate::log::event(crate::log::WARN, "link.closed", &[("sid", &sid), ("users_lost", &lost.len().to_string())]);
        let mut stg = state.lock().unwrap_or_else(|e| e.into_inner());
        crate::cmds::snote(&mut stg, &format!("Server {} split, {} users lost", sid, lost.len()));
    } else {
        crate::log::event(crate::log::WARN, "link.failed", &[("peer", &peer)]);
    }
}

/// Apply one protocol event to server state.
fn apply_event(state: &Arc<Mutex<ServerState>>, ev: Event) {
    let mut stg = state.lock().unwrap_or_else(|e| e.into_inner());
    match ev {
        Event::ServerIntroduced { sid, name, desc, via } => {
            let hop = stg.network.server(&via).map(|s| s.hop + 1).unwrap_or(2);
            stg.network.add_server(crate::network::RemoteServer { sid, name, desc, hop, via, bursting: false });
        }
        Event::UserIntroduced(u) => {
            stg.network.add_user(*u);
        }
        Event::UserQuit { uuid, reason } => {
            if let Some(u) = stg.network.remove_user(&uuid) {
                crate::cmds::announce_remote_quit(&mut stg, &u, &reason);
            }
        }
        Event::NickChanged { uuid, nick } => {
            let key = crate::state::norm_nick(&nick);
            stg.network.rename_user(&uuid, &nick, &key);
        }
        Event::ChannelJoin { chan, ts, modes: _, members } => {
            let key = chan.to_lowercase();
            for (_, uuid) in &members {
                if let Some(u) = stg.network.user_mut(uuid) {
                    u.chans.insert(key.clone());
                }
            }
            crate::cmds::adopt_remote_channel(&mut stg, &chan, ts, &members);
        }
        Event::RemoteJoin { chan, uuid } => {
            let key = chan.to_lowercase();
            if let Some(u) = stg.network.user_mut(&uuid) {
                u.chans.insert(key.clone());
            }
            crate::cmds::announce_remote_join(&mut stg, &chan, &uuid);
        }
        Event::RemotePart { chan, uuid, reason } => {
            let key = chan.to_lowercase();
            if let Some(u) = stg.network.user_mut(&uuid) {
                u.chans.remove(&key);
            }
            crate::cmds::announce_remote_part(&mut stg, &chan, &uuid, &reason);
        }
        Event::Message { from, target, text, notice } => {
            crate::cmds::deliver_remote_message(&mut stg, &from, &target, &text, notice);
        }
        Event::TopicChanged { chan, ts, setter, topic } => {
            crate::cmds::adopt_remote_topic(&mut stg, &chan, ts, &setter, &topic);
        }
        Event::Away { uuid, reason } => {
            if let Some(u) = stg.network.user_mut(&uuid) {
                u.away = reason;
            }
        }
        Event::ServerSplit { sid, reason } => {
            let lost = stg.network.split_server(&sid);
            crate::cmds::snote(&mut stg, &format!("Server {} split ({}), {} users lost", sid, reason, lost.len()));
        }
        Event::BurstComplete => {
            crate::log::event(crate::log::INFO, "link.burst_complete", &[]);
        }
        Event::ModeChange { target, ts, modes } => {
            crate::cmds::apply_remote_mode(&mut stg, &target, ts, &modes);
        }
        Event::PeerRegistered { .. } | Event::Failed(_) => {}
    }
}

/// Listen for inbound links.
pub async fn serve_links(state: Arc<Mutex<ServerState>>, port: u16, cfg: LinkConfig) {
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            crate::log::event(crate::log::ERROR, "link.bind_failed", &[("port", &port.to_string()), ("error", &e.to_string())]);
            return;
        }
    };
    crate::log::event(crate::log::INFO, "link.listening", &[("port", &port.to_string())]);
    loop {
        let (sock, _) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => continue,
        };
        let st = state.clone();
        let c = LinkConfig {
            sid: cfg.sid.clone(),
            name: cfg.name.clone(),
            desc: cfg.desc.clone(),
            send_password: cfg.send_password.clone(),
            recv_password: cfg.recv_password.clone(),
        };
        tokio::spawn(async move { run_session(st, sock, c, false).await });
    }
}

/// Keep an outbound link to `peer` up, retrying with a fixed backoff.
pub async fn maintain_peer(state: Arc<Mutex<ServerState>>, peer: String, cfg: LinkConfig) {
    loop {
        match TcpStream::connect(&peer).await {
            Ok(sock) => {
                let c = LinkConfig {
                    sid: cfg.sid.clone(),
                    name: cfg.name.clone(),
                    desc: cfg.desc.clone(),
                    send_password: cfg.send_password.clone(),
                    recv_password: cfg.recv_password.clone(),
                };
                run_session(state.clone(), sock, c, true).await;
            }
            Err(e) => {
                crate::log::counted("link.connect_failed", &peer);
                let _ = e;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}

#[cfg(test)]
mod protocol_extra_tests {
    use super::*;

    fn cfg() -> LinkConfig {
        LinkConfig { sid: "2CH".into(), name: "chonk.test".into(), desc: "d".into(),
                     send_password: "pw".into(), recv_password: "pw".into() }
    }
    fn linked() -> LinkSession {
        let mut s = LinkSession::new(cfg(), true);
        s.begin();
        s.take_outbound();
        s.handle_line("SERVER insp.test pw 0 1IN :InspIRCd");
        s.take_outbound();
        s
    }

    #[test]
    fn fmode_carries_its_flags_and_parameters() {
        let mut s = linked();
        let ev = s.handle_line(":1IN FMODE #test 1665473560 +ntl 50");
        match ev.as_slice() {
            [Event::ModeChange { target, ts, modes }] => {
                assert_eq!(target, "#test");
                assert_eq!(*ts, 1665473560);
                assert_eq!(modes, &vec!["+ntl".to_string(), "50".to_string()]);
            }
            other => panic!("expected a mode change, got {other:?}"),
        }
    }

    #[test]
    fn ftopic_reports_setter_and_topic() {
        let mut s = linked();
        let ev = s.handle_line(":1IN FTOPIC #test 100 200 alice :the new topic");
        match ev.as_slice() {
            [Event::TopicChanged { chan, ts, setter, topic }] => {
                assert_eq!(chan, "#test");
                assert_eq!(*ts, 200, "the topic's own timestamp, not the channel's");
                assert_eq!(setter, "alice");
                assert_eq!(topic, "the new topic");
            }
            other => panic!("expected a topic change, got {other:?}"),
        }
    }

    #[test]
    fn ftopic_accepts_the_four_parameter_form() {
        // InspIRCd sends FTOPIC without a setter and falls back to the source.
        let mut s = linked();
        match s.handle_line(":1INAAAAAB FTOPIC #test 100 200 :no setter here").as_slice() {
            [Event::TopicChanged { setter, topic, ts, .. }] => {
                assert_eq!(topic, "no setter here", "the topic is the last parameter");
                assert_eq!(setter, "1INAAAAAB", "falls back to the message source");
                assert_eq!(*ts, 200);
            }
            other => panic!("expected a topic change, got {other:?}"),
        }
    }

    #[test]
    fn away_sets_and_clears() {
        let mut s = linked();
        match s.handle_line(":1INAAAAAB AWAY :at lunch").as_slice() {
            [Event::Away { uuid, reason }] => {
                assert_eq!(uuid, "1INAAAAAB");
                assert_eq!(reason.as_deref(), Some("at lunch"));
            }
            other => panic!("expected away, got {other:?}"),
        }
        match s.handle_line(":1INAAAAAB AWAY").as_slice() {
            [Event::Away { reason, .. }] => assert!(reason.is_none(), "no reason clears away"),
            other => panic!("expected away clear, got {other:?}"),
        }
    }

    #[test]
    fn a_pong_from_the_peer_is_accepted_silently() {
        // We ping on a timer; their answer must not be treated as unknown and
        // must not produce output of its own.
        let mut s = linked();
        let ev = s.handle_line(":1IN PONG 1IN 2CH");
        assert!(ev.is_empty());
        assert!(s.take_outbound().is_empty(), "a PONG must not be answered");
        assert_ne!(s.phase, Phase::Dead);
    }
}
