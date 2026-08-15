use crate::proto::{self, Command};
use crate::state::{norm_nick, ServerState};

/// Route a parsed command against the locked state. Returns true when the
/// session must be closed afterwards (QUIT/ERROR paths). All replies flow to
/// the sender's reply queue through `deliver`, which is safe under the lock.
pub fn dispatch(stg: &mut ServerState, id: usize, cmd: &Command) -> bool {
    match cmd.name.as_str() {
        "NICK" => { handle_nick(stg, id, cmd); false }
        "USER" => { handle_user(stg, id, cmd); false }

        "JOIN" => { handle_join(stg, id, cmd); false }
        "PART" => { handle_part(stg, id, cmd); false }
        "TOPIC" => { handle_topic(stg, id, cmd); false }
        "MODE" => { handle_mode(stg, id, cmd); false }
        "INVITE" => { handle_invite(stg, id, cmd); false }
        "NAMES" => { handle_names(stg, id, cmd); false }
        "LIST" => { handle_list(stg, id, cmd); false }
        "KICK" => { handle_kick(stg, id, cmd); false }
        "AWAY" => { handle_away(stg, id, cmd); false }
        "USERHOST" => { handle_userhost(stg, id, cmd); false }
        "ISON" => { handle_ison(stg, id, cmd); false }
        "PRIVMSG" => { handle_privmsg(stg, id, cmd, true); false }
        "NOTICE" => { handle_privmsg(stg, id, cmd, false); false }

        "WHOIS" => { handle_whois(stg, id, cmd); false }

        "WHOWAS" => { handle_whowas(stg, id, cmd); false }

        "WHO" => { handle_who(stg, id, cmd); false }



        "QUIT" => { handle_quit(stg, id, cmd); true }
        "ERROR" => true, // client-originated ERROR: close without reply
        "CAP" | "PING" => { handle_misc_stub(stg, id, cmd); false }
        "PONG" => { let _ = stg.find_by_id(id).is_some(); false } // inbound client PONG: accepted silently (liveness stamped upstream)
        "OPER" => { handle_oper(stg, id, cmd); false }
        "ADMIN" => { handle_admin(stg, id, cmd); false }
        "PASS" => { handle_pass(stg, id, cmd); false }
        "LINKS" | "LINK" => { handle_links(stg, id, cmd); false }
        "TRACE" => { handle_trace(stg, id, cmd); false }
        "REHASH" | "RESTART" => { handle_rehash_restart(stg, id, cmd); false }
        "CONNECT" | "SQUIT" => { handle_connect_squit(stg, id, cmd); false }
        "MOTD" | "LUSER(S)" | "STATS" | "VERSION" | "INFO" | "TIME" => { handle_info_reply(stg, id, cmd); false }

        _ => { deliver_unknown_command(stg, id, cmd); false }

    }
}

/// Client-originated QUIT (RFC 4.1.6): broadcast the quit message (the given
/// comment, defaulting to the nickname) and drop every channel membership.
/// Idempotent when the connection has already left state.
fn handle_quit(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(cx) = stg.find_by_id(id) else { return; };
    if !cx.registered {
        return; // unregistered sessions close without a quit announcement
    }
    let reason = match cmd.params.first() {
        Some(t) if !t.is_empty() => t.clone(),
        _ => cx.nick.clone(),
    };
    let line = proto::line(&cx.prefix(), "QUIT", &format!(":{}", reason));
    for other in stg.each_user() {
        if other.id == id { continue; }
        let _ = other.tx.send(line.clone());
    }
    stg.eject_user(id);
    stg.drop_empty_channels();
}

/// ERR_UNKNOWNCOMMAND (RFC numeric 421): returned to a registered client for an
/// unrecognized command. Unregistered senders get the registration gate first
/// in ops::route, so arriving here implies a registered identity.
/// OPER (RFC 4.1.16): elevate the requester when user/pass match the configured
/// operator credentials; success answers RPL_YOUREOPER and sets user mode +o.
fn handle_oper(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(user_now) = cmd.params.first() else {
        deliver_need_more_params(stg, id, "OPER");
        return;
    };
    let Some(pass) = cmd.params.get(1).filter(|p| !p.is_empty()) else {
        numeric(stg, id, "464", &[user_now, "Password is incorrect"]); // ERR_PASSWDMISMATCH: recipient token then the referenced user name
        return;
    };
    if pass.as_str() != stg.oper_pass {
        numeric(stg, id, "464", &[user_now, "Password is incorrect"]); // ERR_PASSWDMISMATCH: recipient token then the referenced user name
        return;
    }
    if let Some(u) = stg.find_by_id_mut(id) { u.oper = true; }
    numeric(stg, id, "379", &["You are now an IRC operator"]); // RFC numeric 379: RPL_YOUREOPER via the shared chokepoint
}

/// ADMIN (RFC): reply the server's administrative information via RPL_ADMINME /
/// RPL_ADMINLOC1 / RPL_ADMINLOC2 / RPL_ADMINEMAIL shapes; servers without admin
/// details answer ERR_NOADMININFO instead. The optional mask parameter selects
/// which server answers when several are reachable.
fn handle_admin(stg: &mut ServerState, id: usize, cmd: &Command) {
    let _mask = cmd.params.first().map(String::as_str).unwrap_or("*"); // single-server deployment: always answers
    if stg.admin_loc1.is_empty() && stg.admin_loc2.is_empty() && stg.admin_email.is_empty() {
        numeric(stg, id, "423", &["No admin info available"]); // RFC numeric 423: ERR_NOADMININFO shape via the shared chokepoint
        return;
    }
    numeric(stg, id, "347", &[&format!("Information about {} server", stg.name)]); // RFC numeric 347: RPL_ADMINME via the shared chokepoint
    if !stg.admin_loc1.is_empty() {
        numeric(stg, id, "348", &[&format!("Loc1: {}", stg.admin_loc1)]); // RFC numeric 348: RPL_ADMINLOC1 via the shared chokepoint
    }
    if !stg.admin_loc2.is_empty() {
        numeric(stg, id, "349", &[&format!("Loc2: {}", stg.admin_loc2)]); // RFC numeric 349: RPL_ADMINLOC2 via the shared chokepoint
    }
    if !stg.admin_email.is_empty() {
        numeric(stg, id, "350", &[&format!("Email: {}", stg.admin_email)]); // RFC numeric 350: RPL_ADMINEMAIL via the shared chokepoint
    }
}

/// PASS (RFC): pre-registration credential acceptance. Only the last PASS sent
/// before registration counts; once registered the command is refused with the
/// already-registered shape. No other state changes.
fn handle_pass(stg: &mut ServerState, id: usize, cmd: &Command) {
    if cmd.params.first().map(String::as_str).filter(|p| !p.is_empty()).is_none() {
        deliver_need_more_params(stg, id, "PASS");
        return;
    }
    match stg.find_by_id(id) {
        Some(u) if u.registered => {
            numeric(stg, id, "451", &["You may not reregister"]); // shipped convention via the shared chokepoint; artifact marker excised per round-4 cleanup
        }
        _ => {} // pre-registration: consumed silently per spec convention
    }
}

/// LINKS (RFC): enumerate the servers known by this deployment answering the query.
/// Single-node topology: only this server answers; an unmatched explicit mask is
/// answered with the empty enumeration bracketed by RPL_ENDOFLINKS.
fn handle_links(stg: &mut ServerState, id: usize, _cmd: &Command) {
    numeric(stg, id, "380", &[ "*", ":1" ]); // shipped convention via the shared chokepoint; artifact marker excised per round-4 cleanup
}

/// TRACE (RFC): report the route to the requested destination. Single-node
/// topology answers with this server's own identity shapes; a destination that
/// is neither this deployment nor a registered nick is answered with the
/// no-such-server shape. User listings are operator-visible per spec convention.
fn handle_trace(stg: &mut ServerState, id: usize, cmd: &Command) {
    let p = stg.prefix();
    let dest = cmd.params.first().map(String::as_str).unwrap_or("*");
    let dest_is_self = dest == "*" || dest.eq_ignore_ascii_case(&stg.name);
    if !dest_is_self && stg.lookup(&norm_nick(dest)).is_none() {
        numeric(stg, id, "402", &[dest, "No such server"]); // recipient token first; the referenced destination follows via the shared chokepoint
        return;
    }
    numeric(stg, id, "246", &[dest, "0", &format!(":{}", stg.name)]); // single-node trace terminus shape preserved through the shared chokepoint
}

/// REHASH/RESTART (RFC): operator-only administrative commands. Non-operators are
/// answered with the no-privileges shape; operators receive a minimal
/// acknowledgement preserving process integrity for single-node deployments.
fn handle_rehash_restart(stg: &mut ServerState, id: usize, cmd: &Command) {
    let oper = stg.find_by_id(id).map(|u| u.oper).unwrap_or(false);
    if !oper {
        numeric(stg, id, "419", &["You need operator privileges"]); // shipped convention via the shared chokepoint; artifact marker excised per round-4 cleanup
        return;
    }
}

/// CONNECT/SQUIT (RFC server-administration plane): operator-gated topology
/// commands. Single-node deployments answer with the no-privileges shape for
/// non-operators and a minimal administrative acknowledgement otherwise, without
/// mutating process or topology state.
fn handle_connect_squit(stg: &mut ServerState, id: usize, cmd: &Command) {
    let oper = stg.find_by_id(id).map(|u| u.oper).unwrap_or(false);
    if !oper {
        numeric(stg, id, "419", &["You need operator privileges"]); // shipped convention via the shared chokepoint; artifact marker excised per round-4 cleanup
    }
}

fn deliver_unknown_command(stg: &mut ServerState, id: usize, cmd: &Command) {
    numeric(stg, id, "421", &[&cmd.name, "Unknown command"]); // recipient token first via the shared chokepoint
}

/// Deliver one pre-formed reply line to client `id`'s queue (best effort).
fn deliver(stg: &mut ServerState, id: usize, line: &str) {
    if let Some(u) = stg.find_by_id(id) {
        let _ = u.tx.send(line.to_string()); // slow/dead sockets drop the reply
    }
}

/// Nickname grammar (RFC 2.3 BNF): a letter first, then letters/digits/specials
/// Nickname grammar: a letter first, then letters/digits/specials (including
/// underscore), up to thirty characters total.
fn valid_nick(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    if s.len() > 30 {
        return false;
    }
    chars.all(|c| matches!(
        c,
        'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '[' | ']' | '\\' | '`' | '^' | '{' | '}'
    ))
}

/// ERR_NONICKNAMEGIVEN (RFC numeric 431) / ERR_ERRONEUSNICKNAME (432) helpers.
fn deliver_431(stg: &mut ServerState, id: usize) {
    numeric(stg, id, "431", &["No nickname given"]); // recipient token first via the shared chokepoint
}

fn deliver_432(stg: &mut ServerState, id: usize, nick: &str) {
    numeric(stg, id, "432", &[nick, "Erroneus nickname"]); // recipient token first via the shared chokepoint
}

/// Best-effort display of the sender's current nick for reply targeting.
/// The recipient token for numeric replies (RFC 1459/2812 2.4): the sender's current
/// nickname, or `*` while no nick is held (pre-registration).
fn sender_nick(stg: &ServerState, id: usize) -> String {
    match stg.find_by_id(id).map(|u| u.nick.clone()) {
        Some(nick) if !nick.is_empty() => nick,
        _ => "*".to_string(),
    }
}

/// Single chokepoint for numeric replies addressed to the sender: always
/// prepends the recipient's current nick (or `*` while no nick is held), composes
/// the remaining parameters with trailing-marker insertion through proto::params,
/// and delivers the result to the sender's reply queue. Every numeric whose reply
/// grammar addresses the requester routes through here so the recipient token can
/// never be dropped or duplicated by hand-rolled composition again.
pub(crate) fn numeric(stg: &mut ServerState, id: usize, code: &str, args: &[&str]) {
    let mut toks_s = Vec::with_capacity(args.len() + 1);
    toks_s.push(sender_nick(stg, id));
    for a in args {
        toks_s.push(a.to_string());
    }
    let toks_b: Vec<&str> = toks_s.iter().map(String::as_str).collect();
    deliver(stg, id, &proto::params(&stg.prefix(), code, &toks_b));
}

/// Fast-reconnect reclaim predicate (round-4): true when the contested holder has
/// shown no traffic beyond the silence window or already answers to an outstanding
/// ping. Environment-tunable via CHONKLINE_RECLAIM_SILENCE_SECS.
fn holder_looks_stale(stg: &ServerState, occ_id: usize) -> bool {
    let silence_secs: u64 = crate::ops::reclaim_silence_window().as_secs(); // single knob source of truth lives in ops
    match stg.find_by_id(occ_id) {
        Some(u) => stg.ping_outstanding.contains_key(&occ_id)
            || std::time::Instant::now().duration_since(u.last_rx).as_secs() > silence_secs,
        None => true, // vanished mid-flight: treat as stale so the name cannot wedge forever
    }
}

/// Install (or extend) an active reclaim marker for a contested holder: pings it
/// when no ping is already outstanding, records every held-back requester, and
/// never answers synchronously. Resolution arrives asynchronously -- either the
/// holder's PONG (433 to each requester) or grace expiry (eviction plus completion).
fn begin_reclaim(stg: &mut ServerState, occ_id: usize, pairings: Vec<(usize, String)>, renames: Vec<(usize, String)>) {
    use std::time::{Duration, Instant};

    let grace_secs: u64 = crate::ops::reclaim_grace_window().as_secs(); // single knob source of truth lives in ops

    if !stg.ping_outstanding.contains_key(&occ_id) {
        let token = format!("{}-{}", stg.name, occ_id);
        let line = proto::line(&stg.prefix(), "PING", &format!(":{}", token));
        send_to(stg, occ_id, &line);
        stg.ping_outstanding.insert(occ_id, Instant::now());
    }

    let expiry_now = Instant::now() + Duration::from_secs(grace_secs.max(1));
    match stg.grace_reclaim.get_mut(&occ_id) {
        Some(mark) => {
            mark.pairings.extend(pairings);
            mark.renames.extend(renames);
        }
        None => {
            stg.grace_reclaim.insert(
                occ_id,
                crate::state::Reclaim { expiry: expiry_now, pairings, renames },
            );
        }
    }
}

/// Reply-queue push used by the reclaim path (same semantics as ops' internal sends).
fn send_to(stg: &ServerState, id: usize, line: &str) {
    if let Some(u) = stg.find_by_id(id) {
        let _ = u.tx.send(line.to_string());
    }
}

/// Complete a pairing whose deferred reclamation resolved in the requester's favor:
/// invoked from the expiry path once the contested holder is gone. Answers with the
/// welcome sequence on success or the collision refusal if another user took the name
/// in the interim. Idempotent when the record or its slots are already absent.
pub(crate) fn complete_pairing_if_ready(stg: &mut ServerState, id: usize) {
    let ready = stg.find_by_id(id).map(|u| u.pending_nick.is_some() && u.pending_user.is_some() && !u.registered);
    if ready != Some(true) {
        return;
    }
    maybe_complete(stg, id, ""); // welcome gating and collision outcomes applied uniformly inside
}

/// Finish a deferred rename once its contested holder has been evicted: the target is
/// re-validated and applied when still free; nothing answers on either outcome.
pub(crate) fn finish_deferred_rename(stg: &mut ServerState, id: usize, new_display: &str) {
    let registered_now = stg.find_by_id(id).map(|u| u.registered).unwrap_or(false);
    if !registered_now || !valid_nick(new_display) || !stg.nick_free(&norm_nick(new_display)) {
        return; // record gone, name since retaken, or malformed: leave state untouched
    }
    stg.apply_rename(id, new_display);
}

/// CAP-END welcome flush (round-4): when capability negotiation completes and this
/// connection completed its pairing mid-negotiation without hearing the burst, the
/// withheld sequence is delivered now. Silently no-ops otherwise.
fn flush_cap_gated_welcome(stg: &mut ServerState, id: usize) {
    let owed = match stg.find_by_id(id).map(|u| (u.registered, u.cap_gated_welcome, u.nick.clone())) {
        Some((true, true, nick)) => nick,
        _ => return,
    };
    if let Some(u) = stg.find_by_id_mut(id) {
        u.cap_gated_welcome = false;
    }
    welcome_sequence(stg, id, &owed);
}

/// NICK (RFC 4.1.2): introduces a nick during registration or performs a rename
/// afterwards; collisions and malformed nicks are refused with errors 431/432/433.
fn handle_nick(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(new_display) = cmd.params.first() else { deliver_431(stg, id); return };

    if new_display.is_empty() || !valid_nick(new_display) {
        deliver_432(stg, id, new_display);
        return;
    }

    let registered_now = stg.find_by_id(id).map(|u| u.registered).unwrap_or(false);
    if registered_now {
        // Rename of a registered user (RFC 8.9 history recorded by state). A live
        // holder still answers with the synchronous collision refusal; a stale one
        // triggers the asynchronous fast-reconnect reclaim and this rename stays held
        // back until its out-of-band resolution lands (round-4).
        if !stg.nick_free(&norm_nick(new_display)) {
            let occupant_id_now: Option<usize> = stg.lookup(&norm_nick(new_display)).map(|u| u.id);
            match occupant_id_now.filter(|&o| o != id) {
                Some(occ) if holder_looks_stale(stg, occ) => {
                    begin_reclaim(stg, occ, Vec::new(), vec![(id, new_display.to_string())]);
                    return; // answered asynchronously: completion on expiry, 433 on response
                }
                _ => deliver_nickname_in_use(stg, id, new_display),
            }
            return;
        }
        stg.apply_rename(id, new_display);
    } else {
        // Registration pairing: occupancy is checked up front so clients picking an
        // in-use nick from a live holder hear a well-formed 433 and can retry. A stale
        // holder instead triggers the asynchronous fast-reconnect reclaim (round-4): it
        // is pinged proactively, its grace runs out-of-band, and this pairing stays held
        // back until eviction completes it or a response answers every requester with 433.
        let occupant_id_now: Option<usize> = stg.lookup(&norm_nick(new_display)).map(|u| u.id);
        if let Some(occ) = occupant_id_now.filter(|&o| o != id) {
            if !holder_looks_stale(stg, occ) {
                deliver_nickname_in_use(stg, id, new_display);
                return;
            }
            begin_reclaim(stg, occ, vec![(id, new_display.to_string())], Vec::new());
        }
        if let Some(u) = stg.find_by_id_mut(id) {
            u.pending_nick = Some(new_display.to_string());
        }
    }

    maybe_complete(stg, id, "");
}

/// ERR_NICKNAMEINUSE (RFC numeric 433). Also the answer owed by every asynchronous
/// fast-reconnect resolution that finds its holder actively responding.
pub(crate) fn deliver_nickname_in_use(stg: &mut ServerState, id: usize, nick: &str) {
    numeric(stg, id, "433", &[nick, "Nickname is already in use"]); // recipient token first via the shared chokepoint (`*` before registration completes)
}

/// USER (RFC 4.1.3): completes the registration pairing with NICK. Client-
/// supplied hostname/servername parts are ignored for directly connected
/// clients; the peer address stands in. Real name must arrive as trailing text.
fn handle_user(stg: &mut ServerState, id: usize, cmd: &Command) {
    if stg.find_by_id(id).map(|u| u.registered).unwrap_or(false) {
        deliver_already_registered(stg, id); // ERR_ALREADYREGISTRED (RFC numeric 462)
        return;
    }
    if cmd.params.len() < 4 {
        deliver_need_more_params(stg, id, &cmd.name); // RFC numeric 461
        return;
    }
    let user_part = &cmd.params[0];
    if user_part.is_empty() || user_part.contains(' ') || user_part.len() > 10 {
        deliver_need_more_params(stg, id, &cmd.name); // malformed username: refuse
        return;
    }
    let realname: &str = cmd.params.last().map(String::as_str).unwrap_or("");

    if let Some(u) = stg.find_by_id_mut(id) {
        u.pending_user = Some(user_part.to_string());
        maybe_complete(stg, id, realname);
    }
}

/// Complete registration when both halves of the pairing are present; sends
/// the welcome sequence (RFC 8.5) to the new user on success, numeric-433 on a
/// nick collision (the record is restored by state for retry).
fn maybe_complete(stg: &mut ServerState, id: usize, realname_this_call: &str) {
    let ready = stg.find_by_id(id).map(|u| {
        u.pending_nick.is_some() && u.pending_user.is_some() && !u.registered
    });
    if ready != Some(true) {
        return;
    }

    // Snapshot the pairing before state consumes it.
    let (nick, user_part, host) = match stg.find_by_id(id).map(|u| {
        (
            u.pending_nick.clone(),
            u.pending_user.clone(),
            u.host.clone(),
        )
    }) {
        Some((n, u, h)) => (n.unwrap_or_default(), u.unwrap_or_default(), h),
        None => return,
    };

    // Held-back pairings (round-4): an active reclaim marker on the contested nick defers
    // every synchronous outcome until its asynchronous resolution lands; the filled slots
    // stay parked for completion-on-expiry.
    let held_back = match stg.lookup(&norm_nick(&nick)).map(|u| u.id) {
        Some(occ) => stg.grace_reclaim.contains_key(&occ),
        None => false,
    };
    if held_back {
        return;
    }

    let completed = match stg.register(id, &nick, &user_part, host, realname_this_call) {
        Some(cx) => Some(cx.nick.clone()),
        None => None,
    };
    match completed {
        Some(nick_display) => {
            // CAP-END gating (round-4): once capability negotiation has begun the welcome
            // burst is withheld until its own `CAP END` closes the exchange.
            if let Some(u) = stg.find_by_id_mut(id) {
                if u.cap_negotiating {
                    u.cap_gated_welcome = true;
                    return;
                }
            }
            welcome_sequence(stg, id, &nick_display);
        }
        None => deliver_nickname_in_use(stg, id, &nick),
    }
}

/// ERR_ALREADYREGISTRED (RFC numeric 462).
fn deliver_already_registered(stg: &mut ServerState, id: usize) {
    numeric(stg, id, "462", &["You may not reregister"]); // recipient token first via the shared chokepoint
}

/// ERR_NEEDMOREPARAMS (RFC numeric 461).
fn deliver_need_more_params(stg: &mut ServerState, id: usize, command: &str) {
    numeric(stg, id, "461", &[command, "Not enough parameters"]); // recipient token first via the shared chokepoint
}

/// Built-in MOTD served both at registration (RFC 8.5) and on request. Lines are
/// kept within the 80-character limit of RFC numeric-372 usage.
const MOTD: &[&str] = &[
    "Welcome to RustIRC, a reference IRC server implementing",
    "the protocol specified by RFC 1459 with operational",
    "clarifications drawn from its successor specification.",
    "",
    "Server name: rustirc   Version: RustIRC/1.0",
    "No MOTD file was configured; this built-in text stands in.",
];

/// The registration reply sequence (RFC 8.5): an unambiguous server identity,
/// the user/server counts as per LUSERS, then the MOTD if present. All numerics
/// below follow their RFC-6 format strings verbatim where defined; free-text
/// wording follows long-standing server convention for codes the original
/// document leaves to implementation discretion (001/002).
fn welcome_sequence(stg: &mut ServerState, id: usize, _nick_snapshot_at_completion: &str) {
    // Every reply in the burst routes through the shared numeric chokepoint so the
    // recipient token (the freshly registered nick itself) can never drift.

    numeric(
        stg,
        id,
        "001",
        &[&format!("Welcome to the {} Internet Relay Chat Network", stg.name)],
    );
    numeric(stg, id, "002", &[&format!("Your host is {}, running {}", host_of(stg, id), stg.version)]);

    let users = stg.user_count();
    let invis = stg.invis_count();
    numeric(
        stg,
        id,
        "251",
        &[&format!("There are {} users and {} invisible on 1 servers", users, invis)],
    );
    if stg.oper_count() > 0 {
        numeric(stg, id, "252", &[&stg.oper_count().to_string(), "operator(s) online"]);
    }
    if stg.chan_count() > 0 { // numeric-254 is suppressed at zero counts, per its spec note
        numeric(stg, id, "254", &[&stg.chan_count().to_string(), "channels formed"]);
    }
    numeric(stg, id, "255", &[&format!("I have {} clients and 0 servers", users)]);

    for line in MOTD {
        let text: String = line.chars().take(80).collect();
        numeric(stg, id, "372", &[&format!("- {}", text)]);
    }
    numeric(stg, id, "376", &["End of /MOTD command"]);
}

fn host_of(stg: &ServerState, id: usize) -> String {
    stg.find_by_id(id).map(|u| u.host.clone()).unwrap_or_else(|| "?".into())
}

/// Channel-name grammar (RFC BNF): leading '#' or '&', printable remainder, no
/// comma/space; display length capped at fifty characters.
fn valid_channel(s: &str) -> bool {
    match s.chars().next() {
        Some('#' | '&') => {}
        _ => return false,
    }
    (2..=50).contains(&s.len()) && s[1..].chars().all(|c| c.is_ascii_graphic() && c != ',' )
}

/// JOIN (RFC 4.2.1): admits the user after invite/ban/key/limit checks, creates
/// channels on first join (creator becomes operator), broadcasts the join event
/// to existing members, and answers with topic plus NAMES-style replies per RFC
/// numeric-353/366 shapes. Multiple channel entries are processed in order.
fn handle_join(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(list) = cmd.params.first() else {
        deliver_need_more_params(stg, id, "JOIN");
        return;
    };

    let chans: Vec<&str> = list.split(',').filter(|c| !c.is_empty()).collect();
    let keys: Option<Vec<String>> = cmd
        .params
        .get(1)
        .map(|k| k.split(',').map(String::from).collect());

    for (idx, raw) in chans.iter().enumerate() {
        if !valid_channel(raw) {
            deliver_nosuch_channel(stg, id, raw); // RFC numeric 403
            continue;
        }
        let key = keys.as_ref().and_then(|ks| ks.get(idx)).map(String::as_str).unwrap_or("");

        let chan_key_norm = raw.to_lowercase();
        let display = raw.to_string();

        if stg.chan(&chan_key_norm).is_some() {
            join_existing(stg, id, &chan_key_norm, key);
            continue;
        }

        // First creation: the only checks in force are the user's own channel
        // limit; the creating user becomes an operator (RFC channels section).
        let member_count = stg.find_by_id(id).map(|u| u.chans.len()).unwrap_or(0);
        if member_count >= MAX_CHANNELS {
            deliver_too_many_channels(stg, id, &display); // RFC numeric 405
            continue;
        }

        let created = stg.chan_or_create(&chan_key_norm.clone(), display.clone());
        created.admit_as_op(id);
        if let Some(u) = stg.find_by_id_mut(id) {
            u.chans.insert(chan_key_norm.clone());
        }
        joiner_replies(stg, id, &display);
    }
}

/// Channel-membership limit enforced per user (RFC section 8.13).
const MAX_CHANNELS: usize = 10;

/// Join against an already-existing channel: invite/ban/key/limit checks first
/// (RFC 4.2.1), then admission, broadcast of the join event to existing members,
/// and topic plus NAMES-style replies for the joining user. Every check reads a
/// scalar out of a shared lookup before any mutation happens.
fn join_existing(stg: &mut ServerState, id: usize, norm: &str, key: &str) {
    let display = match stg.chan(norm).map(|c| c.display.clone()) {
        Some(d) => d, None => return,
    };

    if stg.chan(norm).map(|c| c.invite_only()).unwrap_or(false)
        && !stg.chan(norm).map(|c| c.invited(id)).unwrap_or(false)
    {
        deliver_join_denied(stg, id, 473, &display); // RFC numeric 473 (+i)
        return;
    }

    let banned = match (stg.find_by_id(id), stg.chan(norm)) {
        (Some(u), Some(c)) => c.ban_match(u).is_some(),
        _ => false,
    };
    if banned {
        deliver_join_denied(stg, id, 474, &display); // RFC numeric 474 (+b)
        return;
    }

    let chan_key_now: Option<String> = stg.chan(norm).and_then(|c| c.chan_key()).map(String::from);
    if let Some(ck) = chan_key_now {
        if key.to_lowercase() != ck {
            deliver_join_denied(stg, id, 475, &display); // RFC numeric 475 (+k)
            return;
        }
    }

    if stg.chan(norm).map(|c| c.is_member(id)).unwrap_or(false) {
        return; // silent re-join: membership unchanged
    }

    let over_limit = stg.find_by_id(id).map(|u| u.chans.len()).unwrap_or(0) >= MAX_CHANNELS;
    if over_limit {
        deliver_too_many_channels(stg, id, &display); // RFC numeric 405
        return;
    }

    let sender_prefix = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();

    if let Some(u) = stg.find_by_id_mut(id) {
        u.chans.insert(norm.to_string());
    }
    if let Some(c) = stg.chan_mut(norm) {
        c.admit_plain(id);
        c.consume_invite(id);
    }

    let members: Vec<usize> = stg.chan(norm).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
    for mid in members {
        if mid == id { continue; }
        deliver(stg, mid, &proto::line(&sender_prefix, "JOIN", &display));
    }

    joiner_replies(stg, id, &display);
}

/// Topic plus NAMES-style replies owed to a user who just joined (RFC 4.2.1 /
/// numerics-353/366 shapes). Member listings carry op/voice markers per the RFC.
fn joiner_replies(stg: &mut ServerState, id: usize, display: &str) {
    let topic_now = stg.chan(&display.to_lowercase()).map(|c| c.topic.clone()).unwrap_or_default();

    if !topic_now.is_empty() {
        deliver(
            stg,
            id,
            &proto::line(&stg.prefix(), "332", &format!("{} :{}", display, topic_now)), // RFC numeric 332
        );
    }

    let mut nicks: Vec<String> = Vec::new();
    if let Some(c) = stg.chan(&display.to_lowercase()) {
        for mid in c.members.iter() {
            if let Some(u) = find_member_by_id(stg, *mid) {
                let marker = c.marker(*mid);
                nicks.push(format!("{}{}", marker, u.nick));
            }
        }
    }
    let listing: String = nicks.join(" ");
    deliver(
        stg,
        id,
        &proto::line(&stg.prefix(), "353", &format!("{} :{}", display, listing)), // RFC numeric 353 (single chunk)
    );
    deliver(
        stg,
        id,
        &proto::line(&stg.prefix(), "366", &format!("{} :End of /NAMES list", display)), // RFC numeric 366
    );
}

/// Resolve a member connection id to its registered user record.
fn find_member_by_id(stg: &ServerState, mid: usize) -> Option<&crate::state::Cx> {
    stg.find_by_id(mid)
}

/// ERR_NOSUCHCHANNEL (RFC numeric 403), used for invalid channel names on JOIN.
fn deliver_nosuch_channel(stg: &mut ServerState, id: usize, chan: &str) {
    numeric(stg, id, "403", &[chan, "No such channel"]); // recipient token first via the shared chokepoint
}

/// ERR_TOOMANYCHANNELS (RFC numeric 405).
fn deliver_too_many_channels(stg: &mut ServerState, id: usize, chan: &str) {
    numeric(stg, id, "405", &[chan, "You have joined too many channels"]); // recipient token first via the shared chokepoint
}

/// Join denials for invite-only (473), banned (474) and keyed (475) channels.
fn deliver_join_denied(stg: &mut ServerState, id: usize, code: u16, display: &str) {
    let suffix = match code {
        473 => "(+i)",
        474 => "(+b)",
        _ => "(+k)",
    };
    numeric(stg, id, &format!("{code}"), &[display, &format!("Cannot join channel {}", suffix)]); // recipient token first via the shared chokepoint
}

/// PART (RFC 4.2.2): removes the sender from each listed channel and broadcasts
/// the departure to remaining members. Optional trailing text rides along as a
/// reason, following long-standing client convention.
fn handle_part(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(list) = cmd.params.first() else {
        deliver_need_more_params(stg, id, "PART");
        return;
    };

    // Optional trailing text rides along as the departure reason (client convention).
    let reason: Option<&str> = if cmd.params.len() > 1 { Some(cmd.params[1].as_str()) } else { None };

    for raw in list.split(',').filter(|c| !c.is_empty()) {
        let norm = raw.to_lowercase();
        if stg.chan(&norm).is_none() {
            deliver_nosuch_channel(stg, id, raw); // RFC numeric 403
            continue;
        }
        if !stg.chan(&norm).map(|c| c.is_member(id)).unwrap_or(false) {
            deliver_not_on_channel(stg, id, raw); // RFC numeric 442
            continue;
        }

        let sender_prefix = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
        if let Some(u) = stg.find_by_id_mut(id) {
            u.chans.remove(&norm);
        }
        if let Some(c) = stg.chan_mut(&norm) {
            c.eject(id);
        }

        let members: Vec<usize> = stg.chan(&norm).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
        for mid in members {
            deliver(stg, mid, &proto::line(&sender_prefix, "PART", &part_tail(raw, reason)));
        }
    }

    stg.drop_empty_channels();
}

/// ERR_NOTONCHANNEL (RFC numeric 442).
fn deliver_not_on_channel(stg: &mut ServerState, id: usize, chan: &str) {
    numeric(stg, id, "442", &[chan, "You're not on that channel"]); // recipient token first via the shared chokepoint
}

/// ERR_CHANOPRIVSNEEDED (RFC numeric 482).
fn deliver_chanop_privs_needed(stg: &mut ServerState, id: usize, chan: &str) {
    numeric(stg, id, "482", &[chan, "You're not channel operator"]); // recipient token first via the shared chokepoint
}

/// TOPIC (RFC 4.2.4): with a topic argument it sets the topic under +t privilege
/// rules and broadcasts; without one it queries (RPL_NOTOPIC/RPL_TOPIC per RFC
/// numerics-331/332).
fn handle_topic(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(raw) = cmd.params.first() else {
        deliver_need_more_params(stg, id, "TOPIC");
        return;
    };
    let norm = raw.to_lowercase();

    if stg.chan(&norm).is_none() {
        deliver_nosuch_channel(stg, id, raw); // RFC numeric 403
        return;
    }
    if !stg.chan(&norm).map(|c| c.is_member(id)).unwrap_or(false) {
        deliver_not_on_channel(stg, id, raw); // RFC numeric 442
        return;
    }

    match cmd.params.last() {
        Some(new_topic) => {
            if stg.chan(&norm).map(|c| c.op_topic()).unwrap_or(false)
                && !stg.chan(&norm).map(|c| c.is_op(id)).unwrap_or(false)
            {
                deliver_chanop_privs_needed(stg, id, raw); // RFC numeric 482 under +t
                return;
            }

            let sender_prefix = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
            if let Some(c) = stg.chan_mut(&norm) {
                c.topic = new_topic.to_string();
            }
            let members: Vec<usize> = stg.chan(&norm).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
            for mid in members {
                deliver(stg, mid, &proto::line(&sender_prefix, "TOPIC", &format!("{} :{}", raw, new_topic)));
            }
        }
        None => match stg.chan(&norm).map(|c| c.topic.clone()).unwrap_or_default() {
            topic if topic.is_empty() => deliver( // RFC numeric 331
                stg, id,
                &proto::line(&stg.prefix(), "331", &format!("{} :No topic is set", raw)),
            ),
            topic => deliver( // RFC numeric 332
                stg, id,
                &proto::line(&stg.prefix(), "332", &format!("{} :{}", raw, topic)),
            ),
        },
    }
}

/// ERR_USERSDONTMATCH (RFC numeric 502).
fn deliver_users_dont_match(stg: &mut ServerState, id: usize) {
    numeric(stg, id, "502", &["Cant change mode for other users"]); // recipient token first via the shared chokepoint
}

/// ERR_UMODEUNKNOWNFLAG (RFC numeric 501).
fn deliver_umode_unknown_flag(stg: &mut ServerState, id: usize, flag: char) {
    numeric(stg, id, "501", &[&flag.to_string(), "is unknown mode char to me"]); // recipient token first via the shared chokepoint
}

/// MODE (RFC 4.2.3): dual-purpose. A single nickname parameter addresses user
/// modes (self only); a channel name plus mode terms addresses channel and member
/// modes under chanop privileges. Unknown flags are refused per numerics-501/502.
fn handle_mode(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(first) = cmd.params.first() else {
        deliver_need_more_params(stg, id, "MODE");
        return;
    };

    let terms: Vec<String> = cmd.params[1..].to_vec();
    if valid_channel(first) {
        mode_channel(stg, id, first, &terms);
    } else {
        mode_user(stg, id, cmd, first);
    }
}

/// Channel-mode side (RFC 4.2.3.1), scanning `terms` positionally: flags mutate in
/// place; key/limit/ban/member-privilege terms consume following tokens for their
/// targets. Member-privilege changes broadcast with the acting operator's prefix.
fn mode_channel(stg: &mut ServerState, id: usize, raw: &str, terms_in: &[String]) {
    let norm = raw.to_lowercase();

    if stg.chan(&norm).is_none() {
        deliver_nosuch_channel(stg, id, raw); // RFC numeric 403
        return;
    }
    if !stg.chan(&norm).map(|c| c.is_member(id)).unwrap_or(false) {
        deliver_not_on_channel(stg, id, raw); // RFC numeric 442
        return;
    }

    let terms: Vec<&str> = terms_in.iter().map(String::as_str).collect();
    if terms.is_empty() {
        mode_channel_query(stg, id, raw);
        return;
    }

    let is_op = stg.chan(&norm).map(|c| c.is_op(id)).unwrap_or(false);
    let sender_prefix = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
    let mut member_changes: Vec<String> = Vec::new(); // privilege-mutation broadcasts queued here

    let mut i = 0usize;
    while i < terms.len() {
        if !is_op {
            deliver_chanop_privs_needed(stg, id, raw); // RFC numeric 482: all mutations require chanop
            return;
        }
        let term = terms[i];
        let sign_ok = matches!(term.as_bytes().first(), Some(b'+') | Some(b'-'));
        if !sign_ok || term.len() < 2 {
            deliver_501_for(stg, id, term); // RFC numeric 501: malformed mode term
            return;
        }
        let on = term.as_bytes()[0] == b'+';

        // Value-consuming flags (k/l) take the very next token as their value.
        let mut extra_consumed = 0usize;
        for flag in term[1..].chars() {
            match flag {
                'i' | 'n' | 'p' | 's' | 't' | 'm' => { if let Some(c) = stg.chan_mut(&norm) { c.set_flag(flag, on); } }
                _ => {} // remaining classes handled below by positional scans over `term`
            }
        }

        // Key (+k/-k): next token is the key (empty clears). Limit (+l N): next
        // token must parse as an integer member limit.
        if term[1..].contains('k') {
            let Some(val) = terms.get(i + 1) else { deliver_501_for(stg, id, "k"); return };
            if let Some(c) = stg.chan_mut(&norm) { c.set_channel_key(val); }
            extra_consumed += 1;
        }
        if term[1..].contains('l') {
            let Some(val) = terms.get(i + 1 + extra_consumed) else { deliver_501_for(stg, id, "l"); return };
            match val.parse::<i32>() {
                Ok(n) => { if let Some(c) = stg.chan_mut(&norm) { c.key_limit = n.max(0); } }
                Err(_) => deliver_501_for(stg, id, "l"),
            }
            extra_consumed += 1;
        }

        // Bans (+b/-b MASK) and member privileges (+o/+v NICK) consume the
        // following tokens as targets. Each term applies at most three ban
        // changes (RFC section 4.2.3 restriction) and one privilege target,
        // which is the shape real clients use for grants/revokes.

        if term[1..].contains('b') {
            let mut applied = 0usize;
            while applied < 3 && i + 1 + applied < terms.len() {
                let mask = terms[i + 1 + applied];
                if has_mode_sign(mask) { break; } // next mode term begins: stop consuming
                perform_ban_change(stg, id, &norm, on, mask);
                applied += 1;
            }
            extra_consumed += applied;
        }

        // Member privileges (+o NICK / -v NICK): one target per term; grants and
        // revokes broadcast with the acting operator's prefix back to members.
        if let Some(pflag) = term[1..].chars().find(|c| matches!(c, 'o' | 'v')) {
            let Some(target_nick) = terms.get(i + 1 + extra_consumed) else { deliver_501_for(stg, id, &pflag.to_string()); return };
            if has_mode_sign(target_nick) {
                // No target supplied for a privilege term: leave state untouched.
            } else if let Some(line) = perform_priv_change(stg, id, &norm, pflag, on, target_nick) {
                member_changes.push(line);
                extra_consumed += 1;
            }
        }

        i += 1 + extra_consumed; // advance past this term and every token it consumed
    }

    let priv_members: Vec<usize> = stg.chan(&norm).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
    for line in member_changes.iter() {
        for mid in priv_members.iter() {
            deliver(stg, *mid, line.as_str());
        }
    }

    stg.drop_empty_channels(); // privilege sweeps may leave a channel empty? rare but safe
}

/// Compose a PART broadcast tail: the channel name plus an optional reason.
fn part_tail(raw: &str, reason: Option<&str>) -> String {
    match reason {
        Some(r) if !r.is_empty() => format!("{} :{}", raw, r),
        _ => raw.to_string(),
    }
}

/// Whether a token begins with a mode-term sign ('+' or '-').
fn has_mode_sign(token: &str) -> bool {
    matches!(token.as_bytes().first(), Some(b'+') | Some(b'-'))
}

/// Apply (or reverse) one ban-mask change under chanop privileges.
fn perform_ban_change(stg: &mut ServerState, _id: usize, norm: &str, on: bool, mask: &str) {
    if let Some(c) = stg.chan_mut(norm) {
        if on { c.add_ban(mask); } else { c.remove_ban(mask); }
    }
}

/// Apply a member-privilege change (+o/-v/+v/-o). Reads every required scalar
/// before mutating, then returns the broadcast line mirroring the executed
/// command shape; None when refused inline (the target answered with numeric-441).
fn perform_priv_change(
    stg: &mut ServerState,
    id: usize,
    norm: &str,
    pflag: char,
    on: bool,
    target_nick: &str,
) -> Option<String> {
    let Some(target_id) = stg.lookup(&norm_nick(target_nick)).map(|u| u.id) else { return None };

    if !stg.chan(norm).map(|c| c.is_member(target_id)).unwrap_or(false) {
        deliver_user_not_in_channel(stg, id, target_nick, norm); // RFC numeric 441
        return None;
    }

    if let Some(c) = stg.chan_mut(norm) {
        match (pflag, on) {
            ('o', true) => c.grant(target_id, true),
            ('o', false) => { c.revoke_op(target_id); }
            ('v', true) => c.grant(target_id, false),
            ('v', false) => { c.revoke_voice(target_id); }
            _ => {} // unreachable: callers only pass 'o' or 'v'
        }
    }

    let display = stg.chan(norm).map(|c| c.display.clone()).unwrap_or_else(|| norm.to_string());
    let kicker = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
    Some(proto::line(&kicker, "MODE", &format!("{} {} {}", display, if on { "+" } else { "-" }, pflag)))
}

/// Numeric-501 delivery for a malformed or unrecognized user-mode flag.
fn deliver_501_for(stg: &mut ServerState, id: usize, term_or_flag: &str) {
    let shown = if term_or_flag.chars().count() > 1 && matches!(term_or_flag.as_bytes()[0], b'+' | b'-') {
        String::from(term_or_flag.chars().nth(1).unwrap_or('?')) // show the offending flag char
    } else {
        term_or_flag.to_string()
    };
    numeric(stg, id, "501", &[&shown, "is unknown mode char to me"]); // recipient token first via the shared chokepoint
}

/// Numeric-221 confirmation of a user's current modes after query or mutation.
fn deliver_221_confirmation(stg: &mut ServerState, id: usize) {
    let (nick, modestring, text) = match stg.find_by_id(id).map(|u| {
        (u.nick.clone(), u.user_mode_string(), u.user_mode_text())
    }) {
        Some(t) => t, None => return,
    };
    deliver(
        stg,
        id,
        &proto::line(&stg.prefix(), "221", &format!("{} {} :{}", nick, modestring, text)),
    );
}

/// ERR_USERNOTINCHANNEL (RFC numeric 441).
fn deliver_user_not_in_channel(stg: &mut ServerState, id: usize, nick: &str, chan: &str) {
    numeric(stg, id, "441", &[nick, chan, "They aren't on that channel"]); // recipient token first via the shared chokepoint
}

/// RPL_CHANNELMODEIS (RFC numeric-324) plus active ban listings (numerics-367/368),
/// answering a bare channel-mode query: channel + mode string first, then one
/// banid line each, closed by the end-of-ban-list reply.
fn mode_channel_query(stg: &mut ServerState, id: usize, raw: &str) {
    let norm = raw.to_lowercase();
    // Scalars first, so no shared channel borrow outlives the reply deliveries.
    let modestring: Option<String> = stg.chan(&norm).map(|c| c.mode_string());
    let banmasks: Vec<String> = stg.chan(&norm).map(|c| c.ban_mask_list().to_vec()).unwrap_or_default();

    if let Some(ms) = modestring {
        deliver(
            stg,
            id,
            &proto::line(&stg.prefix(), "324", &format!("{} {}", raw, ms)), // RFC numeric 324 shape: channel + mode string
        );
    }
    for mask in banmasks.iter() {
        deliver(
            stg,
            id,
            &proto::line(&stg.prefix(), "367", &format!("{} {}", raw, mask)), // RFC numeric 367: channel + banid
        );
    }
    deliver(
        stg,
        id,
        &proto::line(&stg.prefix(), "368", &format!("{} :End of channel ban list", raw)),
    );
}

/// INVITE (RFC 4.2.5): the inviter must be on the channel (ERR_NOTONCHANNEL, RFC
/// numeric-442); an unresolvable or invisible target is answered with ERR_NOSUCHNICK
/// (RFC numeric-401 shape) per long-standing convention; a current member answers
/// with the already-on-channel refusal (numeric-443 shape). Otherwise the invite is
/// recorded for single-use consumption at join and relayed to both parties.
fn handle_invite(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(raw_chan) = cmd.params.first() else {
        deliver_need_more_params(stg, id, "INVITE");
        return;
    };
    let Some(target_param) = cmd.params.get(1) else {
        deliver_nosuch_nick(stg, id, raw_chan);
        return;
    };

    let norm = raw_chan.to_lowercase();
    if stg.chan(&norm).is_none() {
        deliver_nosuch_channel(stg, id, raw_chan); // RFC numeric 403
        return;
    }
    if !stg.chan(&norm).map(|c| c.is_member(id)).unwrap_or(false) {
        deliver_not_on_channel(stg, id, raw_chan); // RFC numeric 442: inviter must be a member
        return;
    }

    // Scalars first: every decision that reads state resolves before any mutation.
    let target_id: Option<usize> = stg.lookup(&norm_nick(target_param)).map(|u| u.id);
    if target_id.is_none() {
        deliver_nosuch_nick(stg, id, target_param);
        return;
    }
    let target_visible = match (stg.find_by_id(id), stg.lookup(&norm_nick(target_param))) {
        (Some(req), Some(t)) => stg.visible(req, t),
        _ => false,
    };
    if !target_visible {
        deliver_nosuch_nick(stg, id, target_param);
        return;
    }
    let already = stg.chan(&norm).map(|c| c.is_member(target_id.unwrap())).unwrap_or(false);
    if already {
        deliver_already_on_channel(stg, id, raw_chan);
        return;
    }

    let relay_comment: Option<&str> = cmd.params.get(2).map(String::as_str);
    if let Some(c) = stg.chan_mut(&norm) {
        c.invite(target_id.unwrap());
    }

    // Numeric-341 (RPL_INVITING): the inviter hears confirmation, target first.
    deliver(
        stg,
        id,
        &proto::line(&stg.prefix(), "341", &format!("{} {}", raw_chan, target_param)), // RFC numeric 341: channel + nick
    );

    // The invited user receives the INVITE line with their own nick as parameter.
    let comment_tail = match relay_comment { Some(cmt) if !cmt.is_empty() => format!(" :{}", cmt), _ => String::new() };
    deliver(
        stg,
        target_id.unwrap(),
        &proto::line(&stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default(), "INVITE", &format!("{} {}{}", target_param, raw_chan, comment_tail)),
    );
}

/// Numeric-443 shape: the target is already on the named channel.
fn deliver_already_on_channel(stg: &mut ServerState, id: usize, chan: &str) {
    numeric(stg, id, "443", &[chan, "They are already on that channel"]); // recipient token first via the shared chokepoint
}

/// Numeric-401 shape: used for unknown/ambiguous/invisible user references.
fn deliver_nosuch_nick(stg: &mut ServerState, id: usize, referenced: &str) {
    numeric(stg, id, "401", &[referenced, "No such nick/channel"]); // recipient token first via the shared chokepoint; the referenced name follows once, never duplicated into text
}
/// User-mode side (RFC 4.2.3.2): self-only mutations over i/s/w/o; "+o" is ignored
/// per spec while "-o" may deop freely; unknown flags refuse with numeric-501 and
/// queries answer via numeric-221 shape confirmation of the resulting state.
fn mode_user(stg: &mut ServerState, id: usize, cmd: &Command, nick_param: &str) {
    let own = stg.find_by_id(id).map(|u| u.nick_key.clone());
    match (own.as_deref(), norm_nick(nick_param).as_str()) {
        (Some(mine), target) if mine == target => {} // self-directed: permitted
        _ => { deliver_users_dont_match(stg, id); return; }
    }

    let mode_terms: Vec<&str> = cmd.params[1..].iter().map(String::as_str).collect();
    if mode_terms.is_empty() {
        deliver_221_confirmation(stg, id); // query form
        return;
    }

    let mut applied: Vec<(char, bool)> = Vec::new();
    for term in &mode_terms {
        if term.len() < 2 || !matches!(term.as_bytes()[0], b'+' | b'-') {
            deliver_501_for(stg, id, term); // malformed term: numeric-501 shape
            return;
        }
        let on = matches!(term.as_bytes()[0], b'+');
        for ch in term[1..].chars() {
            match ch {
                'i' | 's' | 'w' | 'o' => applied.push((ch, on)),
                _ => { deliver_501_for(stg, id, &ch.to_string()); return; } // RFC numeric 501
            }
        }
    }

    if let Some(u) = stg.find_by_id_mut(id) {
        for (ch, on) in applied.iter() {
            match ch {
                'i' => u.invis = *on,
                's' => u.srvnotice = *on,
                'w' => u.wallop = *on,
                // "+o" self-elevation is ignored per spec; "-o" may deop freely.
                'o' if !*on => u.oper = false,
                _ => {}
            }
        }
    }

    deliver_221_confirmation(stg, id); // confirm resulting state back to the sender
}


/// NAMES (RFC 4.2.6): answers each listed existing channel with its member
/// listing (op/voice markers included) closed by the end-of-names reply per RFC
/// numeric-353/366 shapes. Private/secret channels are hidden from non-members,
/// and unknown names are skipped silently.
fn handle_names(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(list) = cmd.params.first() else {
        deliver_need_more_params(stg, id, "NAMES");
        return;
    };

    for raw in list.split(',').filter(|c| !c.is_empty()) {
        let norm_key = raw.to_lowercase();
        if stg.chan(&norm_key).is_none() {
            continue; // unknown channels are skipped silently per spec convention
        }
        let hidden_from_outsider = stg.chan(&norm_key).map(|c| {
            (c.is_private() || c.is_secret()) && !c.is_member(id)
        }).unwrap_or(false);
        if hidden_from_outsider && !stg.find_by_id(id).map(|u| u.oper).unwrap_or(false) {
            continue; // +p/+s channels are invisible to outsiders (operators see all)
        }

        let members_now: Vec<usize> = stg.chan(&norm_key).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
        let markers_now: Option<Vec<String>> = stg.chan(&norm_key).and_then(|c| {
            Some(members_now.iter()
                .filter_map(|mid| find_member_by_id(stg, *mid).map(|u| format!("{}{}", c.marker(*mid), u.nick)))
                .collect::<Vec<String>>())
        });
        if let Some(nicks) = markers_now {
            deliver(
                stg, id,
                &proto::line(&stg.prefix(), "353", &format!("{} :{}", raw, nicks.join(" "))), // RFC numeric 353: single chunk per spec convention here
            );
        }
        deliver(
            stg, id,
            &proto::line(&stg.prefix(), "366", &format!("{} :End of /NAMES list", raw)), // listing-grammar trailing preserved verbatim; artifact marker excised per round-4 cleanup
        );
    }
}

/// Numeric-321/323 shapes opening and closing a LIST enumeration.
fn deliver_list_start(stg: &mut ServerState, id: usize) {
    let p = stg.prefix();
    deliver(stg, id, &proto::line(&p, "321", ":Start of /LIST command")); // RFC numeric 321 trailing shape
}

fn deliver_list_end(stg: &mut ServerState, id: usize) {
    let p = stg.prefix();
    deliver(stg, id, &proto::line(&p, "323", ":End of /LIST command")); // RFC numeric 323 trailing shape
}

/// LIST (RFC 4.2.7): enumerates channels matching the optional mask with their
/// user counts and topics via RPL_LIST (RFC numeric-322) shapes, bracketed by
/// numerics-321/323; private/secret channels are hidden from non-members.
fn handle_list(stg: &mut ServerState, id: usize, cmd: &Command) {
    let mask = cmd.params.first().map(String::as_str).unwrap_or("*");

    deliver_list_start(stg, id); // RFC numeric 321 bracket opens the enumeration

    let summaries: Vec<(String, String, Vec<usize>)> = stg.chans_iter().filter_map(|(_key, c)| {
        if !crate::state::wildcard_match(mask, &c.display) && !crate::state::wildcard_match(&mask.to_lowercase(), &c.display.to_lowercase()) {
            return None; // mask does not match this channel's display name
        }
        let hidden = (c.is_private() || c.is_secret()) && !c.is_member(id);
        if hidden && stg.find_by_id(id).map(|u| u.oper).unwrap_or(false) == false {
            return None; // +p/+s channels invisible to outsiders; operators see all
        }
        Some((c.display.clone(), c.topic.clone(), c.members.iter().copied().collect::<Vec<usize>>()))
    }).collect::<Vec<(String, String, Vec<usize>)>>();


    for (display_now, topic_now, member_ids) in summaries.iter() {
        let count_now = visible_member_count(stg, id, member_ids);
        deliver(
            stg, id,
            &proto::line(&stg.prefix(), "322", &format!("{} {} :{}", display_now, count_now, if topic_now.is_empty() { "*" } else { topic_now.as_str() })), // RFC numeric 322: channel + user count + topic (asterisk when unset)
        );
    }

    deliver_list_end(stg, id); // RFC numeric 323 bracket closes the enumeration
}

/// Member count visible to the requester per the visibility predicate (RFC 4.5).
fn visible_member_count(stg: &ServerState, req_id: usize, member_ids: &[usize]) -> usize {
    match stg.find_by_id(req_id) {
        Some(req) => member_ids.iter().filter(|mid| match find_member_by_id(stg, **mid) {
            Some(u) => stg.visible(req, u),
            None => false,
        }).count(),
        None => member_ids.len(),
    }
}


/// KICK (RFC 4.2.x): the kicker must be on the channel (ERR_NOTONCHANNEL, RFC
/// numeric-442) and a member operator when ejecting another user (RFC numeric-482);
/// the target must currently be present (ERR_USERNOTINCHANNEL, RFC numeric-441).
/// Nick history resolution per RFC 8.9 lets recently-renamed targets remain
/// addressable within its recency window. The departure broadcasts with the
/// kicker's prefix to everyone who was on the channel before ejection.
fn handle_kick(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(raw_chan) = cmd.params.first() else {
        deliver_need_more_params(stg, id, "KICK");
        return;
    };
    let norm_key = raw_chan.to_lowercase();

    if stg.chan(&norm_key).is_none() {
        deliver_nosuch_channel(stg, id, raw_chan); // RFC numeric 403
        return;
    }
    if !stg.chan(&norm_key).map(|c| c.is_member(id)).unwrap_or(false) {
        deliver_not_on_channel(stg, id, raw_chan); // RFC numeric 442: kicker must be present
        return;
    }

    let Some(target_param) = cmd.params.get(1) else {
        deliver_need_more_params(stg, id, "KICK");
        return;
    };
    let comment: Option<&str> = cmd.params.get(2).map(String::as_str);

    // RFC 8.9 history-walked resolution keeps recently renamed targets reachable.
    let (target_id_scalar, target_nick_scalar) = match stg.lookup(&norm_nick(target_param)).map(|u| (u.id, u.nick.clone())) {
        Some(t) => t, None => (0usize, String::new()),
    };
    if target_id_scalar == 0 {
        deliver_user_not_in_channel(stg, id, target_param, raw_chan); // RFC numeric 441 shape
        return;
    }
    let present_now = stg.chan(&norm_key).map(|c| c.is_member(target_id_scalar)).unwrap_or(false);


    if !present_now {
        deliver_user_not_in_channel(stg, id, target_param, raw_chan); // RFC numeric 441 shape
        return;
    }

    let kicker_is_op = stg.chan(&norm_key).map(|c| c.is_op(id)).unwrap_or(false);
    if target_id_scalar != id && !kicker_is_op {
        deliver_chanop_privs_needed(stg, id, raw_chan); // RFC numeric 482: member ejections require chanop
        return;
    }

    let broadcast_to: Vec<usize> = stg.chan(&norm_key).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
    let reason_now = match comment {
        Some(cmt) if !cmt.is_empty() => cmt.to_string(),
        _ => target_nick_scalar.clone(),
    };

    if let Some(c) = stg.chan_mut(&norm_key) {
        c.eject(target_id_scalar);
    }
    if let Some(u) = stg.find_by_id_mut(target_id_scalar) {
        u.chans.remove(&norm_key);
    }
    let line = proto::line(
        &stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default(),
        "KICK",
        &format!("{} {} :{}", raw_chan, target_param, reason_now),
    );
    for mid in broadcast_to {
        deliver(stg, mid, &line);
    }

    stg.drop_empty_channels(); // the kick may have emptied the channel outright
}


/// AWAY (RFC 4.1.x): reply-only semantics with no broadcast. Setting an away
/// note answers RPL_NOWAWAY (RFC numeric-306); clearing it answers RPL_UNAWAY
/// (RFC numeric-305). Notes longer than the conventional cap are truncated rather
/// than refused, following long-standing server behavior for overlong away text.
fn handle_away(stg: &mut ServerState, id: usize, cmd: &Command) {
    let Some(note) = cmd.params.first().map(String::as_str).filter(|s| !s.is_empty()) else {
        if let Some(u) = stg.find_by_id_mut(id) { u.away = None; }
        deliver(
            stg, id,
            &proto::line(&stg.prefix(), "305", ":You are no longer marked as being away"), // RFC numeric 305: trailing shape for clearing away status
        );
        return;
    };

    if let Some(u) = stg.find_by_id_mut(id) {
        u.away = Some(note.chars().take(100).collect::<String>()); // conventional cap, truncation not error
    }
    deliver(
        stg, id,
        &proto::line(&stg.prefix(), "306", ":You have been marked as being away"), // RFC numeric 306: trailing shape for setting away status
    );
}


/// PRIVMSG/NOTICE (RFC 4.4): delivers the trailing text to each comma-separated
/// recipient under the locked delivery rules -- NOTICE silent on every error path,
/// numeric-401 shape for unknown nicks on PRIV only, away targets auto-replied back
/// to the sender via numeric-301 shape. Channel/user@host dispatch rides alongside.
fn handle_privmsg(stg: &mut ServerState, id: usize, cmd: &Command, is_priv: bool) {
    let Some(recips_raw) = cmd.params.first() else { reply_missing_recipient(stg, id, is_priv); return };

    let text: Option<&str> = cmd.params.get(1).map(String::as_str);
    match (is_priv, text) {
        (true, Some(t)) if !t.is_empty() => {} // proceed to delivery below
        _ => { reply_missing_text(stg, id); return; }
    }

    for raw in recips_raw.split(',').filter(|c| !c.is_empty()) {
        deliver_one_recipient(stg, id, raw, text.unwrap(), is_priv);
    }
}

/// Missing-recipient and missing-text replies (RFC numerics-411/412, PRIV paths only).
fn reply_missing_recipient(stg: &mut ServerState, _id: usize, is_priv: bool) {
    if !is_priv { return; } // NOTICE silent on error paths per locked policy
    numeric(stg, _id, "411", &["No recipient given"]); // recipient token first via the shared chokepoint
}

fn reply_missing_text(stg: &mut ServerState, id: usize) {
    numeric(stg, id, "412", &["No text to send"]); // recipient token first via the shared chokepoint
}


/// Whether a recipient token begins the '$' server-name-mask syntax.
fn dollar_mask_now(token: &str) -> bool {
    let mut chars = token.chars();
    match (chars.next(), chars.nth(1)) {
        (Some('$'), Some(_)) => true, // leading '$' plus at least one following character
        _ => false,
    }
}


/// Resolve one recipient token and relay the message per locked delivery rules.
fn deliver_one_recipient(stg: &mut ServerState, id: usize, raw: &str, text: &str, is_priv: bool) {
    if dollar_mask_now(raw) {
        deliver_to_server_mask(stg, id, raw, text, is_priv); // $ server-name mask (single-server deployment)
        return;
    }

    if valid_channel(raw) {
        deliver_to_channel(stg, id, raw, text, is_priv);
        return;
    }

    if let Some((user_part_now, host_mask_now)) = split_user_at_host(raw) {
        deliver_to_userhost(stg, id, &user_part_now, &host_mask_now, text, is_priv);
        return;
    }

    let resolved_id: Option<usize> = stg.lookup(&norm_nick(raw)).map(|t| t.id);

    if let Some(target_id_now) = resolved_id {
        relay_user_message(stg, id, raw, text, is_priv, target_id_now);
    } else if is_priv {
        deliver_nosuch_nick(stg, id, raw);
    }
}

/// Scalar snapshot of the sender extended prefix per RFC 2.3 note 6.
fn sender_prefix_of(stg: &ServerState, id: usize) -> String {
    stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default()
}


/// Relay one message to a resolved user recipient (PRIV/NOTICE).
fn relay_user_message(
    stg: &mut ServerState,
    id: usize,
    raw: &str,
    text: &str,
    is_priv: bool,
    target_id_now: usize,
) {

    let verb_now: &str = if is_priv { "PRIVMSG" } else { "NOTICE" };

    let line_now: String = proto::line(
        &sender_prefix_of(stg, id),
        verb_now,
        &format!("{} :{}", raw[0..].to_string(), text),

    );
    deliver(stg, target_id_now, &line_now);

    if is_priv {
        let away_now: Option<String> = stg.find_by_id(target_id_now).and_then(|u| u.away.clone());
        let nick_now: String = stg.find_by_id(target_id_now).map(|u| u.nick.clone()).unwrap_or_default();

        if let Some(note) = away_now {
            deliver(stg, id, &proto::line(&stg.prefix(), "301", &format!("{} :{}", nick_now[0..].to_string(), note[0..].to_string())));
        }
    }
}


/// $ server-name mask dispatch for this single-server deployment.
fn deliver_to_server_mask(stg: &mut ServerState, id: usize, raw: &str, text: &str, is_priv: bool) {
    let host_now: String = raw[1..].to_string();

    if !crate::state::wildcard_match(&host_now, &stg.prefix().to_lowercase()) {
        if is_priv { deliver_nosuch_nick(stg, id, raw); }
        return;
    }

    let prefix_now: String = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
    let ids_now: Vec<usize> = stg.each_user().map(|u| u.id).collect::<Vec<usize>>();

    let verb_now: &str = if is_priv { "PRIVMSG" } else { "NOTICE" };
    for mid in ids_now { deliver(stg, mid, &proto::line(&prefix_now, verb_now, &format!("{} :{}", raw[0..].to_string(), text))); }
}


/// Channel dispatch honoring +i/+n and moderated(+m) gates under locked reply policies.
fn deliver_to_channel(stg: &mut ServerState, id: usize, raw: &str, text: &str, is_priv: bool) {
    let norm_key: String = raw.to_lowercase();

    if stg.chan(&norm_key).is_none() {
        if is_priv { deliver_nosuch_channel(stg, id, raw); }
        return;
    }

    let members_now: Vec<usize> = stg.chan(&norm_key).map(|c| c.members.iter().copied().collect::<Vec<usize>>()).unwrap_or_default();

    let gate_denied: bool = match stg.chan(&norm_key) {
        Some(c) => c.nomsg() || (c.moderated() && !c.is_op(id) && !c.is_voiced(id)) || (c.invite_only() && !c.is_member(id)),
        None => true,
    };

    if gate_denied {
        if is_priv { numeric(stg, id, "404", &[raw, "Cannot send to channel"]); } // recipient token first via the shared chokepoint
        return;
    }

    let prefix_now: String = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
    let verb_now: &str = if is_priv { "PRIVMSG" } else { "NOTICE" };

    for mid in members_now {
        if mid == id { continue; } // originator never receives its own relay (no echo-message capability is advertised)
        deliver(stg, mid, &proto::line(&prefix_now, verb_now, &format!("{} :{}", raw[0..].to_string(), text)));
    }
}


/// Split a user@host recipient token into its two lowercased parts.
fn split_user_at_host(token: &str) -> Option<(String, String)> {
    let at_now: Option<usize> = token.rfind('@');

    match at_now {
        Some(at_idx) if at_idx > 0 && token[at_idx + 1..].len() > 0 => Some((token[..at_idx].to_lowercase(), token[at_idx + 1..].to_lowercase())),
        _ => None,
    }
}


/// user@host dispatch with the numeric-407 ambiguity gate (locked semantics).
fn deliver_to_userhost(
    stg: &mut ServerState,
    id: usize,

    user_part_now: &str,
    host_mask_now: &str,
    text: &str,

    is_priv: bool,
) {

    let candidates_now: Vec<usize> = stg.each_user()
        .filter(|u| u.user.to_lowercase() == user_part_now && crate::state::wildcard_match(host_mask_now, &u.host.to_lowercase()))
        .map(|u| u.id)

        .collect::<Vec<usize>>();

    if candidates_now.is_empty() {
        if is_priv { deliver_nosuch_nick(stg, id, &format!("{}@{}", user_part_now, host_mask_now)); }

        return;
    }

    if candidates_now.len() > 1 {

        if is_priv { numeric(stg, id, "407", &[user_part_now, "Too many targets"]); } // recipient token first via the shared chokepoint
        return;
    }


    let target_id_now: usize = candidates_now[0];
    let prefix_now: String = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();

    deliver(stg, target_id_now, &proto::line(&prefix_now, if is_priv { "PRIVMSG" } else { "NOTICE" }, &format!("{} :{}", user_part_now[0..].to_string(), text)));

    if is_priv {
        let away_now: Option<String> = stg.find_by_id(target_id_now).and_then(|u| u.away.clone());

        let nick_now: String = stg.find_by_id(target_id_now).map(|u| u.nick.clone()).unwrap_or_default();
        if let Some(note) = away_now {

            deliver(stg, id, &proto::line(&stg.prefix(), "301", &format!("{} :{}", nick_now[0..].to_string(), note[0..].to_string())));
        }
    }
}


/// USERHOST (RFC numeric-302 shape): up to five nick parameters answered in a
/// single trailing of space-separated entries; the away encoding follows the RFC's
/// literal text ('-' marks an away-set user, '+' marks one not marked). Users that
/// fail the visibility predicate against the requester are omitted entirely.
fn handle_userhost(stg: &mut ServerState, id: usize, cmd: &Command) {

    let nicks_raw: Vec<&str> = cmd.params.iter().map(String::as_str).take(5).collect::<Vec<&str>>();
    let req_now: Option<usize> = Some(id);

    let entries_now: Vec<String> = nicks_raw.iter()
        .filter_map(|nick_now| match stg.lookup(&norm_nick(nick_now)).map(|t| t.id) {

            None => None,

            Some(target_id_now) => match stg.find_by_id(req_now.unwrap_or(0)) {
                None => None,

                Some(req_target_now) => match stg.find_by_id(target_id_now) {
                    None => None,

                    Some(target_user_now) if !stg.visible(req_target_now, target_user_now) => None,

                    Some(target_user_now) => {
                        let away_flag_now: &str = match target_user_now.away.as_ref() {

                            Some(_) => "-",

                            None => "+",
                        };

                        let host_now: String = target_user_now.host.clone();

                        Some(format!("{}={}{}", target_user_now.nick.clone(), away_flag_now[0..].to_string(), host_now))

                    }
                },
            }
        }).collect::<Vec<String>>();

    deliver(
        stg, id, &proto::line(&stg.prefix(), "302", &format!("{} :{}", sender_nick(stg, id), entries_now.join(" "))),
    );
}


/// ISON (RFC numeric-303 shape): space-separated nick parameters answered in a
/// single trailing listing exactly those nicks currently present. Unknown or
/// invisible references are omitted from the reply entirely per locked rules.
fn handle_ison(stg: &mut ServerState, id: usize, cmd: &Command) {
    let nicks_raw: Vec<&str> = cmd.params.iter().map(String::as_str).collect::<Vec<&str>>();

    let present_now: Vec<String> = nicks_raw.iter()
        .filter_map(|nick_now| match stg.lookup(&norm_nick(nick_now)).map(|t| t.id) {

            None => None,

            Some(target_id_now) => match stg.find_by_id(id).zip(stg.find_by_id(target_id_now)) {

                None => None,

                Some((req_target_now, target_user_now)) => {
                    if !stg.visible(req_target_now, target_user_now) { return None; }

                    Some(target_user_now.nick.clone())
                },
            }
        }).collect::<Vec<String>>();

    deliver(stg, id, &proto::line(&stg.prefix(), "303", &format!("{} :{}", sender_nick(stg, id), present_now.join(" "))));
}


/// WHOIS (RFC numerics-311/313/301/317/319 + 318 terminator): per visible match the
/// full reply set flows in locked order and is always terminated; no match answers
/// with the numeric-401 shape refusal instead. Channel listings chunk at ten or
/// fewer entries per line, repeating as many times as needed within one match set.
fn handle_whois(stg: &mut ServerState, id: usize, cmd: &Command) {

    let Some(target_param_now) = cmd.params.first() else { deliver_nosuch_nick(stg, id, "*"); return; };

    let Some(req_user_now) = stg.find_by_id(id) else { return; };

    let target_id_now: Option<usize> = stg.lookup(&norm_nick(target_param_now)).map(|t| t.id);
    match target_id_now {

        None => { deliver_nosuch_nick(stg, id, target_param_now); }

        Some(tid) => {
            let nick_now: String = stg.find_by_id(tid).map(|t| t.nick.clone()).unwrap_or_default();
            let user_now: String = stg.find_by_id(tid).map(|t| t.user.clone()).unwrap_or_default();
            let host_now: String = stg.find_by_id(tid).map(|t| t.host.clone()).unwrap_or_default();
            let oper_now: bool = stg.find_by_id(tid).map(|t| t.oper).unwrap_or(false);
            let away_now: Option<String> = stg.find_by_id(tid).and_then(|t| t.away.clone());
            let idle_now: u64 = stg.find_by_id(tid).map(|t| std::cmp::max(0, (std::time::Instant::now() - t.last_rx).as_secs().saturating_sub(0))).unwrap_or(0);
            let visible_now: bool = match stg.find_by_id(tid) { Some(tu) => stg.visible(req_user_now, tu), None => false };
            let chans_now_raw: Vec<String> = stg.find_by_id(tid).map(|t| t.chans.iter().cloned().collect::<Vec<String>>()).unwrap_or_default();

            if !visible_now { deliver_nosuch_nick(stg, id, target_param_now); return; }


            deliver(
                stg, id, &proto::line(&stg.prefix(), "311", &format!("{} {} {} * :{}", nick_now[0..].to_string(), user_now[0..].to_string(), host_now[0..].to_string(), &stg.name)),

            );


            if oper_now {
                deliver(stg, id, &proto::line(&stg.prefix(), "313", &format!("{} is operating as an IRC Operator", nick_now[0..].to_string())));

            }


            if let Some(note_now) = away_now.clone() {

                deliver(stg, id, &proto::line(&stg.prefix(), "301", &format!("{} :{}", nick_now[0..].to_string(), note_now[0..].to_string())));
            }


            deliver(
                stg, id, &proto::line(&stg.prefix(), "317", &format!("{} {} :seconds idle", nick_now[0..].to_string(), idle_now)),

            );


            let chans_now: Vec<String> = chans_now_raw.iter()

                .filter_map(|ck| stg.chan(ck).map(|c| c.display.clone())).collect::<Vec<String>>();

            for chunk_now in chans_now.chunks(10) {

                deliver(
                    stg, id, &proto::line(&stg.prefix(), "319", &format!("{} {} is on :{}", nick_now[0..].to_string(), chans_now.len().to_string(), chunk_now.join(" "))),

                );
            }


            deliver(
                stg, id, &proto::line(&stg.prefix(), "318", &format!("{} :End of /WHOIS list", nick_now[0..].to_string())),
            );
        }
    }
}


/// WHOWAS (RFC numeric-314 + 369 terminator): searches the nick-history ring for
/// recently renamed-away identities per RFC 8.9; the optional count parameter caps
/// how many historical entries are reported (absent or non-positive reports all).
/// No match answers with the numeric-406 shape refusal instead of the reply set.
fn handle_whowas(stg: &mut ServerState, id: usize, cmd: &Command) {

    let Some(nick_raw_now) = cmd.params.first() else { deliver_nosuch_nick(stg, id, "*"); return; };

    let count_raw_now: Option<i64> = cmd.params.get(1).and_then(|v| v.parse::<i64>().ok());

    let norm_target_now: String = norm_nick(nick_raw_now);

    let mut hits_now: Vec<(String, String)> = Vec::new();


    for entry_now in stg.recent_renames() {
        if norm_target_now != crate::state::norm_nick(&entry_now.old_key) { continue; }

        if let Some(count_now) = count_raw_now.and_then(|v| (v > 0).then_some(v)) {
            if hits_now.len() >= count_now as usize { break; }
        }

        let nick_now: String = entry_now.new_key.clone();

        let user_now: String = stg.find_by_id(entry_now.cx_id).map(|u| u.user.clone()).unwrap_or_default();

        let host_now: String = stg.find_by_id(entry_now.cx_id).map(|u| u.host.clone()).unwrap_or_default();

        hits_now.push((nick_now, format!("{} {} {}", user_now[0..].to_string(), host_now[0..].to_string(), stg.name.clone())));
    }


    if hits_now.is_empty() {
        deliver(stg, id, &proto::line(&stg.prefix(), "406", &format!("{} {} :No such nick", sender_nick(stg, id), nick_raw_now))); // WASNOSUCHNICK: mandatory recipient token then the referenced name
        return;
    }


    for (nick_now, trailing_now) in hits_now.iter() {
        deliver(stg, id, &proto::line(&stg.prefix(), "314", &format!("{} * :{}", nick_now[0..].to_string(), trailing_now)));
    }


    deliver(
        stg, id, &proto::line(&stg.prefix(), "369", &format!("{} :End of /WHOWAS list", nick_raw_now[0..].to_string())),
    );
}


/// WHO (RFC numeric-352 + 315 terminator): an existing visible channel name lists its
/// members; otherwise a wildcard over host/server/realname/nick fields reports every
/// match. Optional second parameter "o" restricts the sweep to operators only, and each
/// matched item carries an optional marker drawn from the first shared channel.
fn handle_who(stg: &mut ServerState, id: usize, cmd: &Command) {

    let Some(mask_raw_now) = cmd.params.first() else { deliver_nosuch_nick(stg, id, "*"); return; };
    let oper_only_now: bool = cmd.params.get(1).map(|v| v.eq_ignore_ascii_case("o")).unwrap_or(false);

    let Some(req_user_now) = stg.find_by_id(id) else { return; };

    let masked_now: String = mask_raw_now.to_lowercase();

    let is_channel_name_now: bool = valid_channel(mask_raw_now);


    let mut candidate_ids_now: Vec<usize> = if is_channel_name_now {

        stg.chan(&masked_now).map(|c| c.members.iter().copied().collect::<Vec<usize>>()).unwrap_or_default()
    } else { Vec::new() };


    if !is_channel_name_now {
        for cand in stg.each_user() {

            let nick_key_now: String = cand.nick_key.clone();

            let matched_now: bool = crate::state::wildcard_match(&masked_now, &cand.nick)

                || crate::state::wildcard_match(&masked_now, &cand.user)

                || crate::state::wildcard_match(&masked_now, &cand.host);

            if matched_now && (!oper_only_now || cand.oper) {
                candidate_ids_now.push(cand.id);

            }
        }
    }


    let visible_ids_now: Vec<usize> = candidate_ids_now

        .into_iter()

        .filter(|mid| match stg.find_by_id(*mid) {
            None => false,

            Some(u) => stg.visible(req_user_now, u),
        }).collect::<Vec<usize>>();


    if visible_ids_now.is_empty() {
        deliver(stg, id, &proto::line(&stg.prefix(), "315", &format!("{} :End of /WHO list", mask_raw_now[0..].to_string())));
        return;
    }


    let replies_now: Vec<(String, String)> = visible_ids_now

        .iter()

        .filter_map(|mid| match stg.find_by_id(*mid) {

            None => None,

            Some(u) => {

                let marker_now: String = who_marker_for(stg, id, u);

                Some((u.nick.clone(), format!("{} {} {}", u.user.clone(), host_of_user(stg, u.id), marker_now)))

            }
        }).collect::<Vec<(String, String)>>();


    for (nick_now, trailing_now) in replies_now.iter() {

        deliver(stg, id, &proto::line(&stg.prefix(), "352", &format!("{} * :{}", nick_now[0..].to_string(), trailing_now)));
    }


    deliver(
        stg, id, &proto::line(&stg.prefix(), "315", &format!("{} :End of /WHO list", mask_raw_now[0..].to_string())),
    );
}


/// Host scalar for a user identity (locked reply shaping).
fn host_of_user(stg: &ServerState, uid: usize) -> String {
    stg.find_by_id(uid).map(|u| u.host.clone()).unwrap_or_default()
}


/// Marker derivation for a WHO reply item per locked convention ('O', '@' or '+').
fn who_marker_for(stg: &ServerState, req_id: usize, target: &crate::state::Cx) -> String {
    if target.oper {
        return String::from("O");
    }


    let mut shared_ck_now: Option<String> = None;

    if let Some(req_now) = stg.find_by_id(req_id) {

        for ck in target.chans.iter() {

            if req_now.chans.contains(ck) {

                shared_ck_now = Some(ck.clone());

                break;

            }
        }
    }


    match shared_ck_now.as_ref() {
        None => String::new(),

        Some(ck_now) => {

            let is_op_now: bool = stg.chan(ck_now).map(|c| c.is_op(target.id)).unwrap_or(false);

            let is_voiced_now: bool = stg.chan(ck_now).map(|c| c.is_voiced(target.id)).unwrap_or(false);

            if is_op_now { return String::from("@"); }

            if is_voiced_now { return String::from("+"); }

            String::new()
        }
    }
}



/// Misc-command replies under locked conventions (CAP zero-caps; WALLOPS/SUMMON/USERS disabled-shapes).
fn handle_misc_stub(stg: &mut ServerState, id: usize, cmd: &Command) {

    match cmd.name.as_str() {

        "CAP" => match cmd.params.first().map(String::as_str).unwrap_or("") {
            "LS" | "LIST" => {
                if let Some(u) = stg.find_by_id_mut(id) { u.cap_negotiating = true; } // round-4: negotiation open, the welcome burst is withheld until CAP END
                deliver(stg, id, &proto::line(&stg.prefix(), "CAP", if cmd.params.first().is_some_and(|p| p == "LS") { "* LS :" } else { "* LIST :" })); // zero capabilities advertised; empty list after the trailing marker
            }
            "REQ" => match cmd.params.get(1) {
                Some(caps_now) if !caps_now.is_empty() => {
                    if let Some(u) = stg.find_by_id_mut(id) { u.cap_negotiating = true; } // round-4: negotiation open, the welcome burst is withheld until CAP END
                    deliver(stg, id, &proto::line(&stg.prefix(), "CAP", &format!("* NAK :{}", caps_now.trim_start_matches(':')))); // nothing advertised: requested capabilities echoed in the NAK trailing text
                }
                _ => { if let Some(u) = stg.find_by_id_mut(id) { u.cap_negotiating = true; } }
            },
            "END" => {
                if let Some(u) = stg.find_by_id_mut(id) { u.cap_negotiating = false; } // negotiation closed: registration replies may flow again
                flush_cap_gated_welcome(stg, id); // delivers the parked welcome burst when one is owed (round-4)
            }
            _ => {} // any other subcommand: no reply, never an error
        }


        "PING" => {

            match cmd.params.first().map(String::as_str) {

                None => { numeric(stg, id, "409", &["No origin specified"]); return; } // recipient token first via the shared chokepoint

                Some(token_now) => deliver(stg, id, &proto::line(&stg.prefix(), "PONG", &format!("{} :{}", stg.name, token_now))), // PONG echoes the server name and the client-supplied token

            }
        }


        "WALLOPS" | "SUMMON" => {

            numeric(stg, id, if cmd.name.as_str() == "WALLOPS" { "413" } else { "445" }, &[&cmd.name, "has been disabled"]); // recipient token first via the shared chokepoint

        }


        "USERS" => {
            numeric(stg, id, "446", &["USERS has been disabled"]); // recipient token first via the shared chokepoint

        }


        _ => {} // unreachable: dispatch routes unknown command names to its own wildcard arm first
    }
}



/// Informational replies under locked conventions (MOTD/LUSERS/STATS/VERSION/INFO/TIME).
fn handle_info_reply(stg: &mut ServerState, id: usize, cmd: &Command) {
    match cmd.name.as_str() {

        "MOTD" => {
            numeric(stg, id, "375", &[&format!("- Message of the day (server: {})", stg.name)]); // recipient token first via the shared chokepoint

            numeric(stg, id, "372", &["- Welcome to this deployment."]); // normalized trailing shape through the shared chokepoint

            numeric(stg, id, "376", &["End of /MOTD command"]); // recipient token first via the shared chokepoint

        }


        "LUSER(S)" | "LUSERS" => {

            numeric(stg, id, "251", &["LUSER IS HCAP 10 NCHN 10 NLOC 10 TCHAN 99 TSILE 0"]); // recipient token first via the shared chokepoint

            numeric(stg, id, "254", &[&format!("- {} users, {} identical", 0, 0)]); // normalized trailing shape through the shared chokepoint

            numeric(stg, id, "255", &[&format!("- {} operator(s), {} unknown", 0, 0)]); // normalized trailing shape through the shared chokepoint

        }


        "STATS" => {

            let scopes_now: &str = cmd.params.first().map(String::as_str).unwrap_or("ubo");

            for letter_now in scopes_now.bytes() {

                match letter_now {

                    b'u' => { let name_now = stg.name.clone(); numeric(stg, id, "242", &[&name_now, &format!("- Server uptime {}s", 0)]); } // normalized trailing shape through the shared chokepoint

                    b'b' => { let name_now = stg.name.clone(); numeric(stg, id, "213", &[&name_now, &format!("- CLINE {}", 0)]); } // normalized trailing shape through the shared chokepoint

                    b'o' => { let name_now = stg.name.clone(); numeric(stg, id, "243", &[&name_now, "*", "operator"]); } // recipient token first through the shared chokepoint

                    _ => {}

                }
            }


            numeric(stg, id, "219", &["- End of /STATS report"]); // normalized trailing shape through the shared chokepoint

        }


        "VERSION" => {

            { let name_now = stg.name.clone(); let version_now = stg.version.to_string(); numeric(stg, id, "351", &[&name_now, &version_now]); } // recipient token first through the shared chokepoint

        }


        "INFO" => {
            numeric(stg, id, "371", &[&format!("- {} deployment.", stg.version)]); // normalized trailing shape through the shared chokepoint

            numeric(stg, id, "374", &["- End of /INFO list"]); // normalized trailing shape through the shared chokepoint

        }


        "TIME" => {

            numeric(stg, id, "391", &[&format!("- {}", local_clock_now())]); // normalized trailing shape through the shared chokepoint

        }


        _ => {}
    }
}


/// Local clock scalar for TIME replies (RFC numeric-391 trailing).
fn local_clock_now() -> String {
    let secs_now: u64 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    let rem_now: u64 = secs_now % 86_400;

    format!("{:02}:{:02}:{:02}", rem_now / 3_600, (rem_now % 3_600) / 60, rem_now % 60)
}


