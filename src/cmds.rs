use crate::proto::{self, Command};

/// Username length carried in a user's prefix. Longer values are truncated to
/// this rather than refused (see `handle_user`).
const MAX_USER_LEN: usize = 10;

/// Distinct recipients permitted in one PRIVMSG/NOTICE, advertised as TARGMAX.
const MAX_TARGETS: usize = 4;
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
        "CAP" => { handle_cap(stg, id, cmd); false }
        "AUTHENTICATE" => { handle_authenticate(stg, id, cmd); false }
        "PING" => { handle_misc_stub(stg, id, cmd); false }
        "PONG" => { let _ = stg.find_by_id(id).is_some(); false } // inbound client PONG: accepted silently (liveness stamped upstream)
        "OPER" => { handle_oper(stg, id, cmd); false }
        "KILL" => { handle_kill(stg, id, cmd); false }
        "KLINE" => { handle_kline(stg, id, cmd); false }
        "UNKLINE" => { handle_unkline(stg, id, cmd); false }
        "ADMIN" => { handle_admin(stg, id, cmd); false }
        "PASS" => { handle_pass(stg, id, cmd); false }
        "LINKS" | "LINK" => { handle_links(stg, id, cmd); false }
        "TRACE" => { handle_trace(stg, id, cmd); false }
        "REHASH" | "RESTART" => { handle_rehash_restart(stg, id, cmd); false }
        "CONNECT" | "SQUIT" => { handle_connect_squit(stg, id, cmd); false }
        "MOTD" | "LUSERS" | "STATS" | "VERSION" | "INFO" | "TIME" => { handle_info_reply(stg, id, cmd); false }
        "WALLOPS" => { handle_wallops(stg, id, cmd); false }
        "SUMMON" => { numeric(stg, id, "445", &["SUMMON has been disabled"]); false } // ERR_SUMMONDISABLED
        "USERS" => { numeric(stg, id, "446", &["USERS has been disabled"]); false }   // ERR_USERSDISABLED

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
    // Only users sharing a channel witness the quit (RFC 2812 3.1.7).
    for mid in stg.channel_peers(id) {
        deliver(stg, mid, &line);
    }
    stg.eject_user(id);
    stg.drop_empty_channels();
    // Remove the record now so the post-dispatch cleanup does not announce a
    // second, duplicate QUIT for the same session.
    let _ = stg.evict(id);
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
    // The username was previously ignored entirely: any name with the correct
    // password became an operator, and IRC_OPER_USER was configured, logged and
    // never compared. Both halves are now checked, in constant time, so a wrong
    // username is not distinguishable from a wrong password by timing.
    let user_ok = crate::crypto::constant_time_eq(user_now.as_bytes(), stg.oper_user.as_bytes());
    let pass_ok = crate::crypto::constant_time_eq(pass.as_bytes(), stg.oper_pass.as_bytes());
    if !(user_ok && pass_ok) {
        let src = stg.find_by_id(id).map(|u| u.real_host.clone()).unwrap_or_default();
        crate::log::auth(id, &src, user_now, "OPER", false);
        snote(stg, &format!("Failed OPER attempt from {}", src));
        numeric(stg, id, "464", &[user_now, "Password is incorrect"]); // ERR_PASSWDMISMATCH: recipient token then the referenced user name
        return;
    }
    {
        let src = stg.find_by_id(id).map(|u| u.real_host.clone()).unwrap_or_default();
        crate::log::auth(id, &src, user_now, "OPER", true);
        let who = stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default();
        snote(stg, &format!("{} is now an IRC operator", who));
    }
    if let Some(u) = stg.find_by_id_mut(id) { u.oper = true; }
    numeric(stg, id, "381", &["You are now an IRC operator"]); // RPL_YOUREOPER (381), not 379 (RPL_WHOISOPERATOR)
    // Reflect the new +o user mode back to the client (MODE self-echo).
    let nick = stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default();
    deliver(stg, id, &proto::line(&stg.prefix(), "MODE", &format!("{} +o", nick)));
}

/// Broadcast a server notice to every operator carrying user mode +s.
///
/// `+s` was parseable, storable and rendered in RPL_UMODEIS, but nothing ever
/// sent one -- so an operator had no in-band signal that anything was wrong and
/// learned about incidents from users. This is that signal.
pub(crate) fn snote(stg: &mut ServerState, text: &str) {
    let recipients: Vec<usize> = stg
        .each_user()
        .filter(|u| u.oper && u.srvnotice)
        .map(|u| u.id)
        .collect();
    if recipients.is_empty() {
        return;
    }
    let p = stg.prefix();
    for rid in recipients {
        let nick = stg.find_by_id(rid).map(|u| u.nick.clone()).unwrap_or_default();
        deliver(stg, rid, &proto::line(&p, "NOTICE", &format!("{} :*** Notice -- {}", nick, text)));
    }
}

/// Reject a command from a non-operator with ERR_NOPRIVILEGES (481). Returns
/// true when the caller lacks privilege and the command must not proceed.
fn refuse_non_oper(stg: &mut ServerState, id: usize) -> bool {
    if stg.find_by_id(id).map(|u| u.oper).unwrap_or(false) {
        return false;
    }
    numeric(stg, id, "481", &["Permission Denied- You're not an IRC operator"]);
    true
}

/// KILL <nick> [:reason] (RFC 2812 3.7.1) — operator-only forced disconnect.
///
/// Until this existed an operator who had correctly identified an attacker had
/// no way to remove them; the only lever was a channel ban on a mask, which is
/// useless when every client shares one cloak.
fn handle_kill(stg: &mut ServerState, id: usize, cmd: &Command) {
    if refuse_non_oper(stg, id) {
        return;
    }
    let Some(target) = cmd.params.first() else {
        deliver_need_more_params(stg, id, "KILL");
        return;
    };
    let reason = cmd.params.get(1).filter(|r| !r.is_empty()).map(String::as_str).unwrap_or("Killed by operator");

    // Pattern form: KILL Sol* :flood. During the 2026-08-20 incident the only
    // option was one KILL per drone against several hundred of them, issued
    // through a limiter that silently dropped most of them.
    if target.contains('*') || target.contains('?') {
        let pat = norm_nick(target);
        let hits: Vec<usize> = stg
            .each_user()
            // Never let a pattern disarm the responders.
            .filter(|u| !u.oper && crate::bans::glob_match(&pat, &u.nick_key))
            .map(|u| u.id)
            .collect();
        let actor = stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default();

        // Guardrail: refuse a pattern that would take out most of the server
        // unless it is unambiguous. `KILL *` is almost always a mistake.
        let total = stg.user_count();
        if hits.len() > total / 2 && total > 4 {
            numeric(stg, id, "NOTICE", &[&format!(
                "Refusing KILL {}: would match {} of {} users. Narrow the pattern.",
                target, hits.len(), total
            )]);
            return;
        }

        for h in &hits {
            crate::ops::announce_loss_and_evict(stg, *h, &format!("Killed by {}: {}", actor, reason));
        }
        crate::log::oper_action(&actor, "KILL-PATTERN", target, reason);
        snote(stg, &format!("{} used KILL {} ({} killed)", actor, target, hits.len()));
        deliver(stg, id, &proto::line(&stg.prefix(), "NOTICE", &format!("{} :Killed {} matching {}", actor, hits.len(), target)));
        return;
    }

    let Some(target_id) = stg.lookup(&norm_nick(target)).map(|u| u.id) else {
        numeric(stg, id, "401", &[target, "No such nick/channel"]); // ERR_NOSUCHNICK
        return;
    };

    let actor = stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default();
    let target_nick = stg.find_by_id(target_id).map(|u| u.nick.clone()).unwrap_or_default();
    crate::log::oper_action(&actor, "KILL", &target_nick, reason);
    snote(stg, &format!("{} used KILL on {} ({})", actor, target_nick, reason));

    let notice = proto::line(&stg.prefix(), "NOTICE", &format!("{} :Killed by {}: {}", target_nick, actor, reason));
    deliver(stg, target_id, &notice);
    crate::ops::announce_loss_and_evict(stg, target_id, &format!("Killed by {}: {}", actor, reason));
    numeric(stg, id, "NOTICE", &[&format!("Killed {}", target_nick)]);
}

/// KLINE <mask> [duration-secs] [:reason] — operator-only persistent address ban.
///
/// Masks match the client's real address (glob syntax), never the cloak: a
/// cloak match would ban every user at once behind a proxy that does not
/// forward client addresses. Duration 0, or omitted, means permanent. Any
/// connected client matching the mask is killed immediately.
fn handle_kline(stg: &mut ServerState, id: usize, cmd: &Command) {
    if refuse_non_oper(stg, id) {
        return;
    }
    let Some(mask) = cmd.params.first().filter(|m| !m.is_empty()) else {
        deliver_need_more_params(stg, id, "KLINE");
        return;
    };
    let mask = mask.clone();
    let duration: u64 = cmd.params.get(1).and_then(|d| d.parse().ok()).unwrap_or(0);
    let reason = cmd
        .params
        .get(2)
        .filter(|r| !r.is_empty())
        .map(String::as_str)
        .unwrap_or("Banned")
        .to_string();

    let actor = stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default();
    stg.bans.add(&mask, duration, &actor, &reason);
    crate::log::oper_action(&actor, "KLINE", &mask, &reason);
    snote(stg, &format!("{} added K-line for {} ({})", actor, mask, reason));

    // Remove anyone already connected from a matching address.
    let hits: Vec<usize> = stg
        .each_connection()
        .filter(|u| crate::bans::glob_match(&mask, &u.real_host))
        .map(|u| u.id)
        .collect();
    for hit in &hits {
        crate::ops::announce_loss_and_evict(stg, *hit, &format!("Banned: {}", reason));
    }

    let summary = format!("Added K-line for {} ({} killed)", mask, hits.len());
    deliver(stg, id, &proto::line(&stg.prefix(), "NOTICE", &format!("{} :{}", actor, summary)));
}

/// UNKLINE <mask> — operator-only removal of a persistent ban by exact mask.
fn handle_unkline(stg: &mut ServerState, id: usize, cmd: &Command) {
    if refuse_non_oper(stg, id) {
        return;
    }
    let Some(mask) = cmd.params.first().filter(|m| !m.is_empty()) else {
        deliver_need_more_params(stg, id, "UNKLINE");
        return;
    };
    let removed = stg.bans.remove(mask);
    let actor = stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default();
    if removed {
        crate::log::oper_action(&actor, "UNKLINE", mask, "");
    }
    let text = if removed {
        format!("Removed K-line for {}", mask)
    } else {
        format!("No K-line for {}", mask)
    };
    deliver(stg, id, &proto::line(&stg.prefix(), "NOTICE", &format!("{} :{}", actor, text)));
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
    numeric(stg, id, "256", &[&format!("Administrative info about {}", stg.name)]); // RPL_ADMINME (256)
    if !stg.admin_loc1.is_empty() {
        numeric(stg, id, "257", &[&format!(":{}", stg.admin_loc1)]); // RPL_ADMINLOC1 (257)
    }
    if !stg.admin_loc2.is_empty() {
        numeric(stg, id, "258", &[&format!(":{}", stg.admin_loc2)]); // RPL_ADMINLOC2 (258)
    }
    if !stg.admin_email.is_empty() {
        numeric(stg, id, "259", &[&format!(":{}", stg.admin_email)]); // RPL_ADMINEMAIL (259)
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
fn handle_links(stg: &mut ServerState, id: usize, cmd: &Command) {
    let mask = cmd.params.last().map(String::as_str).unwrap_or("*");
    let srv = stg.name.clone();
    let ver = stg.version;
    // Single-node topology: this server is the only link. RPL_LINKS (364) then
    // RPL_ENDOFLINKS (365).
    numeric(stg, id, "364", &[&srv, &srv, &format!(":0 {}", ver)]);
    numeric(stg, id, "365", &[mask, "End of /LINKS list"]);
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
    let _ = p;
    // Operators additionally see a RPL_TRACEOPERATOR/USER-style line for the
    // requester; every trace ends with RPL_TRACEEND (262).
    let srv = stg.name.clone();
    let ver = stg.version;
    numeric(stg, id, "262", &[&srv, ver, "End of TRACE"]);
}

/// REHASH/RESTART (RFC): operator-only administrative commands. Non-operators are
/// answered with the no-privileges shape; operators receive a minimal
/// acknowledgement preserving process integrity for single-node deployments.
fn handle_rehash_restart(stg: &mut ServerState, id: usize, _cmd: &Command) {
    let oper = stg.find_by_id(id).map(|u| u.oper).unwrap_or(false);
    if !oper {
        numeric(stg, id, "481", &["Permission Denied- You're not an IRC operator"]); // ERR_NOPRIVILEGES (481)
        return;
    }
}

/// CONNECT/SQUIT (RFC server-administration plane): operator-gated topology
/// commands. Single-node deployments answer with the no-privileges shape for
/// non-operators and a minimal administrative acknowledgement otherwise, without
/// mutating process or topology state.
fn handle_connect_squit(stg: &mut ServerState, id: usize, _cmd: &Command) {
    let oper = stg.find_by_id(id).map(|u| u.oper).unwrap_or(false);
    if !oper {
        numeric(stg, id, "481", &["Permission Denied- You're not an IRC operator"]); // ERR_NOPRIVILEGES (481)
    }
}

fn deliver_unknown_command(stg: &mut ServerState, id: usize, cmd: &Command) {
    numeric(stg, id, "421", &[&cmd.name, "Unknown command"]); // recipient token first via the shared chokepoint
}

/// WALLOPS (RFC 4.7): an operator broadcasts a message to every user carrying
/// mode +w. Non-operators are refused with ERR_NOPRIVILEGES (481).
fn handle_wallops(stg: &mut ServerState, id: usize, cmd: &Command) {
    if !stg.find_by_id(id).map(|u| u.oper).unwrap_or(false) {
        numeric(stg, id, "481", &["Permission Denied- You're not an IRC operator"]);
        return;
    }
    let Some(text) = cmd.params.first().filter(|t| !t.is_empty()) else {
        deliver_need_more_params(stg, id, "WALLOPS");
        return;
    };
    let prefix = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
    let line = proto::line(&prefix, "WALLOPS", &format!(":{}", text));
    let recipients: Vec<usize> = stg.each_user().filter(|u| u.wallop).map(|u| u.id).collect();
    for rid in recipients {
        deliver(stg, rid, &line);
    }
}

/// Deliver one pre-formed reply line to client `id`'s queue (best effort).
fn deliver(stg: &mut ServerState, id: usize, line: &str) {
    if let Some(u) = stg.find_by_id(id) {
        // try_send, not send: a full queue means the peer is not draining, and
        // dropping the line is what keeps memory bounded.
        if u.tx.try_send(line.to_string()).is_err() { crate::log::counted("output.dropped", ""); }
    }
}

/// Deliver a user-visible event line, prepending an IRCv3 `@time=` tag for
/// recipients that negotiated `server-time`. Used for every relayed message and
/// membership event so bouncers and loggers get accurate timestamps.
fn relay_tagged(stg: &mut ServerState, target_id: usize, base_line: &str) {
    let with_time = stg.find_by_id(target_id).map(|u| u.caps.server_time).unwrap_or(false);
    if with_time {
        deliver(stg, target_id, &format!("@time={} {}", proto::ircv3_timestamp(), base_line));
    } else {
        deliver(stg, target_id, base_line);
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
        if u.tx.try_send(line.to_string()).is_err() { crate::log::counted("output.dropped", ""); }
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
        // Announce the rename to the user itself and every channel peer (RFC
        // 2812 3.1.2). The prefix carries the OLD nick, captured before the
        // rename is applied. Without this, nick changes are invisible: peers'
        // member lists never update.
        let old_prefix = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
        stg.apply_rename(id, new_display);
        let line = proto::line(&old_prefix, "NICK", new_display);
        let mut recipients = stg.channel_peers(id);
        recipients.push(id);
        for mid in recipients {
            relay_tagged(stg, mid, &line);
        }
        return; // rename complete; maybe_complete is only for registration pairing
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
    let user_raw = &cmd.params[0];
    if user_raw.is_empty() || user_raw.contains(' ') {
        deliver_need_more_params(stg, id, &cmd.name); // malformed username: refuse
        return;
    }
    // Overlong usernames are TRUNCATED, not refused. Clients send the local
    // system username here without asking, so refusing an 11-character one
    // makes the server unreachable for those users -- they see only a bare 461
    // with nothing to act on. Truncation is what other servers do, and it keeps
    // the length bound that the rest of the code relies on.
    let user_part: String = user_raw.chars().take(MAX_USER_LEN).collect();
    let realname: &str = cmd.params.last().map(String::as_str).unwrap_or("");

    if let Some(u) = stg.find_by_id_mut(id) {
        u.pending_user = Some(user_part);
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

    // Anti-bot registration challenge. Both pairing slots are filled, so send a
    // PING and require any PONG before completing. Real clients answer this
    // automatically and the user never sees it; a scripted flood that blasts
    // NICK/USER/JOIN without reading the socket never gets past here.
    //
    // Any PONG is accepted, not a matching cookie: matching adds nothing
    // against a bot that reads the socket, and only risks breaking a client
    // that echoes the token oddly.
    if crate::ops::registration_challenge_enabled() {
        let (challenged, verified) = match stg.find_by_id(id) {
            Some(u) => (u.reg_challenged, u.reg_verified),
            None => return,
        };
        if !verified {
            if !challenged {
                let token = format!("{}-reg-{}", stg.name, id);
                let p = stg.prefix();
                deliver(stg, id, &proto::line(&p, "PING", &format!(":{}", token)));
                if let Some(u) = stg.find_by_id_mut(id) {
                    u.reg_challenged = true;
                }
            }
            return; // completion resumes from the PONG path
        }
    }

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
    if completed.is_some() {
        // The connection event worth keeping at INFO: a real session, tied to a
        // real address. Health checks never get this far.
        if let Some(u) = stg.find_by_id(id) {
            crate::log::session_registered(id, &u.real_host, &u.host, &u.nick);
        }
        crate::log::counted("session.new", "");
    }
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
    "",
    "      _                 _    _ _",
    "  ___| |__   ___  _ __ | | _| (_)_ __   ___",
    " / __| '_ \\ / _ \\| '_ \\| |/ / | | '_ \\ / _ \\",
    "| (__| | | | (_) | | | |   <| | | | | |  __/",
    " \\___|_| |_|\\___/|_| |_|_|\\_\\_|_|_| |_|\\___|",
    "",
    "        Chonkbase IRC  --  irc.chonkbase.net  (beta)",
    "",
    "  A small, fast IRC server written in Rust. What it offers:",
    "",
    "    *  TLS on port 6697, plaintext on 6667",
    "    *  SASL PLAIN authentication at connect time",
    "    *  IRCv3: server-time, away-notify, extended-join,",
    "              account-notify, multi-prefix",
    "    *  Your address is cloaked -- other users never see your IP",
    "",
    "  Services -- claim and protect your identity:",
    "",
    "    Nicknames / accounts  (NickServ)",
    "        /msg NickServ REGISTER <password>",
    "        /msg NickServ IDENTIFY <password>",
    "",
    "    Channels  (ChanServ) -- register one you operate",
    "        /msg ChanServ REGISTER #channel",
    "        /msg ChanServ INFO #channel",
    "",
    "  Release notes & live stats:  https://irc.chonkbase.net",
    "",
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
    numeric(stg, id, "002", &[&format!("Your host is {}, running {}", stg.name, stg.version)]); // RPL_YOURHOST: server name, not client peer
    numeric(stg, id, "003", &["This server is continuously created"]);
    // RPL_MYINFO: servername, version, user modes, channel modes actually supported.
    let myinfo_srv = stg.name.clone();
    numeric(stg, id, "004", &[&myinfo_srv, stg.version, "iow", "biklmnotv"]);
    // RPL_ISUPPORT: advertise only tokens the server genuinely honors.
    numeric(stg, id, "005", &["CHANTYPES=#", "PREFIX=(ov)@+", "CHANMODES=beI,k,l,imntR", "STATUSMSG=@+", "EXCEPTS=e", "INVEX=I", "CASEMAPPING=rfc1459", "NICKLEN=30", "CHANNELLEN=50", "TOPICLEN=390", "TARGMAX=PRIVMSG:4,NOTICE:4", "NETWORK=Chonkbase", ":are supported by this server"]);

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
    // RPL_LOCALUSERS (265) / RPL_GLOBALUSERS (266): single-node, so local == global.
    numeric(stg, id, "265", &[&users.to_string(), &users.to_string(), &format!("Current local users {}, max {}", users, users)]);
    numeric(stg, id, "266", &[&users.to_string(), &users.to_string(), &format!("Current global users {}, max {}", users, users)]);

    // RPL_MOTDSTART (375) MUST precede the 372 lines: strict clients (BitchX)
    // allocate their MOTD buffer here and crash on 372 without it.
    numeric(stg, id, "375", &[&format!("- {} Message of the Day -", stg.name)]);
    // MOTD lines are emitted verbatim (no forced "- " prefix) so the ASCII art
    // renders with a clean left edge; empty lines become a single space to keep
    // a valid trailing parameter.
    for line in MOTD {
        let text: String = line.chars().take(120).collect();
        let shown: &str = if text.is_empty() { " " } else { &text };
        numeric(stg, id, "372", &[shown]);
    }
    numeric(stg, id, "376", &["End of /MOTD command"]);
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

        // A registered channel that had emptied out is being recreated: restore
        // its persisted topic and withhold the automatic creator-op — only the
        // founder is opped (below), so ownership survives the channel emptying.
        let registered = stg.chanreg.is_registered(&chan_key_norm);
        let restore_topic = if registered {
            stg.chanreg.get(&chan_key_norm).map(|r| r.topic.clone()).unwrap_or_default()
        } else {
            String::new()
        };
        let created = stg.chan_or_create(&chan_key_norm.clone(), display.clone());
        if registered {
            created.admit_plain(id);
        } else {
            created.admit_as_op(id);
        }
        if registered && !restore_topic.is_empty() {
            if let Some(c) = stg.chan_mut(&chan_key_norm) {
                c.topic = restore_topic;
            }
        }
        if let Some(u) = stg.find_by_id_mut(id) {
            u.chans.insert(chan_key_norm.clone());
        }
        joiner_replies(stg, id, &display);
        if registered {
            apply_founder_status(stg, id, &chan_key_norm);
        }
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

    // +i (invite-only) is bypassed by an explicit invite or a matching +I mask.
    let invex_ok = match (stg.find_by_id(id), stg.chan(norm)) {
        (Some(u), Some(c)) => c.invex_match(u),
        _ => false,
    };
    if stg.chan(norm).map(|c| c.invite_only()).unwrap_or(false)
        && !stg.chan(norm).map(|c| c.invited(id)).unwrap_or(false)
        && !invex_ok
    {
        deliver_join_denied(stg, id, 473, &display); // RFC numeric 473 (+i)
        return;
    }

    // +R (registered only): the one channel admission control that does not
    // depend on trustworthy client addresses, so it stays usable even while
    // cloaks or PROXY handling are misconfigured.
    let regonly_block = match (stg.find_by_id(id), stg.chan(norm)) {
        (Some(u), Some(c)) => c.regonly() && u.account.is_none(),
        _ => false,
    };
    if regonly_block {
        // ERR_NEEDREGGEDNICK: the conventional numeric for "authenticate first".
        numeric(stg, id, "477", &[&display, "You must be identified to a registered account to join this channel"]);
        return;
    }

    // A +b ban is overridden by a matching +e ban exception.
    let banned = match (stg.find_by_id(id), stg.chan(norm)) {
        (Some(u), Some(c)) => c.ban_match(u).is_some() && !c.except_match(u),
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
    broadcast_join(stg, id, &members, &sender_prefix, &display);

    joiner_replies(stg, id, &display);
    apply_founder_status(stg, id, norm); // founder rejoining a registered channel regains +o
}

/// Broadcast a JOIN to existing members, choosing the extended-join form
/// (`JOIN <chan> <account> :<realname>`) for recipients that negotiated it and
/// the plain form otherwise, each stamped with server-time where enabled.
fn broadcast_join(stg: &mut ServerState, id: usize, members: &[usize], sender_prefix: &str, display: &str) {
    let (acct, realname) = stg
        .find_by_id(id)
        .map(|u| (u.account.clone().unwrap_or_else(|| "*".into()), u.realname.clone()))
        .unwrap_or_else(|| ("*".into(), String::new()));
    for &mid in members {
        if mid == id {
            continue;
        }
        let ext = stg.find_by_id(mid).map(|u| u.caps.extended_join).unwrap_or(false);
        let line = if ext {
            proto::line(sender_prefix, "JOIN", &format!("{} {} :{}", display, acct, realname))
        } else {
            proto::line(sender_prefix, "JOIN", display)
        };
        relay_tagged(stg, mid, &line);
    }
}

/// Topic plus NAMES-style replies owed to a user who just joined (RFC 4.2.1 /
/// numerics-353/366 shapes). Member listings carry op/voice markers per the RFC.
/// The joiner also receives its own `JOIN` membership line (RFC 3.2.1) before the
/// topic and NAMES burst, so clients that open a channel buffer on self-join work.
fn joiner_replies(stg: &mut ServerState, id: usize, display: &str) {
    let sender_prefix = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
    // RFC 3.2.1 self-echo, in the client's own negotiated JOIN form.
    let self_join = match stg.find_by_id(id).map(|u| (u.caps.extended_join, u.account.clone(), u.realname.clone())) {
        Some((true, acct, realname)) => proto::line(
            &sender_prefix,
            "JOIN",
            &format!("{} {} :{}", display, acct.unwrap_or_else(|| "*".into()), realname),
        ),
        _ => proto::line(&sender_prefix, "JOIN", display),
    };
    relay_tagged(stg, id, &self_join);

    send_topic_state(stg, id, display); // RPL_TOPIC (+ RPL_TOPICWHOTIME) / RPL_NOTOPIC

    let multi = stg.find_by_id(id).map(|u| u.caps.multi_prefix).unwrap_or(false);
    let uhin = stg.find_by_id(id).map(|u| u.caps.userhost_in_names).unwrap_or(false);
    let mut nicks: Vec<String> = Vec::new();
    if let Some(c) = stg.chan(&display.to_lowercase()) {
        for mid in c.members.iter() {
            if let Some(u) = find_member_by_id(stg, *mid) {
                let marker = if multi { c.all_markers(*mid) } else { c.marker(*mid).to_string() };
                nicks.push(names_entry(&marker, u, uhin));
            }
        }
    }
    let listing: String = nicks.join(" ");
    let sym = stg.chan(&display.to_lowercase()).map(names_symbol).unwrap_or("=");
    numeric(stg, id, "353", &[sym, display, &format!(":{}", listing)]); // RFC 353: =/*/@ visibility symbol then channel
    numeric(stg, id, "366", &[display, "End of /NAMES list"]); // RFC numeric 366
}

/// One RPL_NAMREPLY member entry: `<prefix><nick>`, or `<prefix><nick>!user@host`
/// when the requester negotiated the userhost-in-names capability.
fn names_entry(marker: &str, u: &crate::state::Cx, userhost: bool) -> String {
    if userhost {
        format!("{}{}!{}@{}", marker, u.nick, u.user, u.host)
    } else {
        format!("{}{}", marker, u.nick)
    }
}

/// RPL_NAMREPLY visibility symbol (RFC 2812 5.1): "@" for a secret channel
/// (+s), "*" for a private channel (+p), "=" otherwise.
fn names_symbol(c: &crate::state::Chn) -> &'static str {
    if c.is_secret() {
        "@"
    } else if c.is_private() {
        "*"
    } else {
        "="
    }
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

        // RFC 3.2.1: the parting user must receive its own PART line (the
        // self-echo suppression that keeps channel messages quiet is wrong here).
        relay_tagged(stg, id, &proto::line(&sender_prefix, "PART", &part_tail(raw, reason)));

        let members: Vec<usize> = stg.chan(&norm).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
        for mid in members {
            relay_tagged(stg, mid, &proto::line(&sender_prefix, "PART", &part_tail(raw, reason)));
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

/// Topic replies for a channel: RPL_TOPIC (332) followed by RPL_TOPICWHOTIME
/// (333, who set it and when) when a topic is present, else RPL_NOTOPIC (331).
/// Clients such as WeeChat rely on 333 to render "topic set by X at T".
fn send_topic_state(stg: &mut ServerState, id: usize, display: &str) {
    let key = display.to_lowercase();
    let (topic, setter, time) = match stg.chan(&key) {
        Some(c) => (c.topic.clone(), c.topic_setter.clone(), c.topic_time),
        None => (String::new(), String::new(), 0),
    };
    if topic.is_empty() {
        numeric(stg, id, "331", &[display, "No topic is set"]);
    } else {
        numeric(stg, id, "332", &[display, &format!(":{}", topic)]);
        if !setter.is_empty() && time > 0 {
            numeric(stg, id, "333", &[display, &setter, &time.to_string()]);
        }
    }
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
            let setter_nick = stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default();
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if let Some(c) = stg.chan_mut(&norm) {
                c.topic = new_topic.to_string();
                c.topic_setter = setter_nick;
                c.topic_time = now_secs;
            }
            // Registered channels keep their topic across restarts.
            if stg.chanreg.is_registered(&norm) {
                stg.chanreg.set_topic(&norm, new_topic);
            }
            let members: Vec<usize> = stg.chan(&norm).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
            for mid in members {
                relay_tagged(stg, mid, &proto::line(&sender_prefix, "TOPIC", &format!("{} :{}", raw, new_topic)));
            }
        }
        None => send_topic_state(stg, id, raw),
    }
}

/// ERR_USERSDONTMATCH (RFC numeric 502).
fn deliver_users_dont_match(stg: &mut ServerState, id: usize) {
    numeric(stg, id, "502", &["Cant change mode for other users"]); // recipient token first via the shared chokepoint
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

    // Bare list-mode query (MODE #chan b / e / I): list the masks, available to
    // any user without chanop.
    if terms.len() == 1 {
        match terms[0].trim_start_matches(['+', '-']) {
            "b" => { mode_ban_list(stg, id, raw); return; }
            "e" => { mode_except_list(stg, id, raw); return; }
            "I" => { mode_invex_list(stg, id, raw); return; }
            _ => {}
        }
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
                'i' | 'n' | 'p' | 's' | 't' | 'm' | 'R' => { if let Some(c) = stg.chan_mut(&norm) { c.set_flag(flag, on); } }
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

        // Ban exceptions (+e) and invite exceptions (+I): one mask per term.
        if term[1..].contains('e') {
            if let Some(mask) = terms.get(i + 1 + extra_consumed).filter(|m| !has_mode_sign(m)) {
                if let Some(c) = stg.chan_mut(&norm) {
                    if on { c.add_except(mask); } else { c.remove_except(mask); }
                }
                extra_consumed += 1;
            }
        }
        if term[1..].contains('I') {
            if let Some(mask) = terms.get(i + 1 + extra_consumed).filter(|m| !has_mode_sign(m)) {
                if let Some(c) = stg.chan_mut(&norm) {
                    if on { c.add_invex(mask); } else { c.remove_invex(mask); }
                }
                extra_consumed += 1;
            }
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

        // #8: broadcast the applied channel-mode change to every member. +o/+v
        // already broadcast via perform_priv_change; this covers the simple/key/
        // limit/ban modes that were previously applied silently.
        let has_ov = term[1..].chars().any(|c| c == 'o' || c == 'v');
        if !has_ov {
            let end = (i + 1 + extra_consumed).min(terms.len());
            let args = terms[i + 1..end].join(" ");
            let body = if args.is_empty() { format!("{} {}", raw, term) } else { format!("{} {} {}", raw, term, args) };
            member_changes.push(proto::line(&sender_prefix, "MODE", &body));
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
    let target_display = stg.find_by_id(target_id).map(|u| u.nick.clone()).unwrap_or_else(|| target_nick.to_string());
    let setter = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
    // Correct membership-mode shape: "<chan> +o <nick>" — the sign and flag are a
    // single token and the affected nick is the mode argument. (Previously emitted
    // "<chan> + o" with a stray space and no target, which broke mode tracking in
    // clients and bots such as eggdrop.)
    Some(proto::line(&setter, "MODE", &format!("{} {}{} {}", display, if on { "+" } else { "-" }, pflag, target_display)))
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
    let Some(ms) = stg.chan(&norm).map(|c| c.mode_string()) else { return };
    let is_member = stg.chan(&norm).map(|c| c.is_member(id)).unwrap_or(false);
    // Key is only disclosed to members; the limit is public.
    let key = if is_member { stg.chan(&norm).and_then(|c| c.chan_key().map(String::from)) } else { None };
    let limit = stg.chan(&norm).map(|c| c.key_limit).unwrap_or(0);
    let created = stg.chan(&norm).map(|c| c.created_at).unwrap_or(0);

    // RPL_CHANNELMODEIS (324): channel, modes, then the +k/+l arguments in flag order.
    let mut parts: Vec<String> = vec![raw.to_string(), ms.clone()];
    if let Some(k) = key {
        if ms.contains('k') {
            parts.push(k);
        }
    }
    if limit > 0 {
        parts.push(limit.to_string());
    }
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    numeric(stg, id, "324", &refs);

    // RPL_CREATIONTIME (329): channel + unix creation time.
    if created > 0 {
        numeric(stg, id, "329", &[raw, &created.to_string()]);
    }
}

/// RPL_BANLIST (367) for each active ban, closed by RPL_ENDOFBANLIST (368).
fn mode_ban_list(stg: &mut ServerState, id: usize, raw: &str) {
    let norm = raw.to_lowercase();
    let banmasks: Vec<String> = stg.chan(&norm).map(|c| c.ban_mask_list().to_vec()).unwrap_or_default();
    for mask in banmasks.iter() {
        numeric(stg, id, "367", &[raw, mask]); // RFC numeric 367: channel + banid
    }
    numeric(stg, id, "368", &[raw, "End of channel ban list"]); // RFC numeric 368
}

/// RPL_EXCEPTLIST (348) per +e mask, closed by RPL_ENDOFEXCEPTLIST (349).
fn mode_except_list(stg: &mut ServerState, id: usize, raw: &str) {
    let norm = raw.to_lowercase();
    let masks: Vec<String> = stg.chan(&norm).map(|c| c.except_mask_list().to_vec()).unwrap_or_default();
    for m in masks.iter() {
        numeric(stg, id, "348", &[raw, m]);
    }
    numeric(stg, id, "349", &[raw, "End of channel exception list"]);
}

/// RPL_INVITELIST (346) per +I mask, closed by RPL_ENDOFINVITELIST (347).
fn mode_invex_list(stg: &mut ServerState, id: usize, raw: &str) {
    let norm = raw.to_lowercase();
    let masks: Vec<String> = stg.chan(&norm).map(|c| c.invex_mask_list().to_vec()).unwrap_or_default();
    for m in masks.iter() {
        numeric(stg, id, "346", &[raw, m]);
    }
    numeric(stg, id, "347", &[raw, "End of channel invite list"]);
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
    numeric(stg, id, "341", &[raw_chan, target_param]); // RFC numeric 341: channel + nick

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

        let multi = stg.find_by_id(id).map(|u| u.caps.multi_prefix).unwrap_or(false);
        let uhin = stg.find_by_id(id).map(|u| u.caps.userhost_in_names).unwrap_or(false);
        let members_now: Vec<usize> = stg.chan(&norm_key).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
        let markers_now: Option<Vec<String>> = stg.chan(&norm_key).and_then(|c| {
            Some(members_now.iter()
                .filter_map(|mid| find_member_by_id(stg, *mid).map(|u| {
                    let pfx = if multi { c.all_markers(*mid) } else { c.marker(*mid).to_string() };
                    names_entry(&pfx, u, uhin)
                }))
                .collect::<Vec<String>>())
        });
        if let Some(nicks) = markers_now {
            let sym = stg.chan(&norm_key).map(names_symbol).unwrap_or("=");
            numeric(stg, id, "353", &[sym, raw, &format!(":{}", nicks.join(" "))]); // RFC 353: visibility symbol then channel
        }
        numeric(stg, id, "366", &[raw, "End of /NAMES list"]); // RFC numeric 366
    }
}

/// Numeric-321/323 shapes opening and closing a LIST enumeration.
fn deliver_list_start(stg: &mut ServerState, id: usize) {
    numeric(stg, id, "321", &["Start of /LIST command"]); // RFC numeric 321 trailing shape
}

fn deliver_list_end(stg: &mut ServerState, id: usize) {
    numeric(stg, id, "323", &["End of /LIST command"]); // RFC numeric 323 trailing shape
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
        let topic_text_now = if topic_now.is_empty() { "*".to_string() } else { topic_now.clone() };
        numeric(stg, id, "322", &[display_now, &count_now.to_string(), &format!(":{}", topic_text_now)]); // RFC numeric 322: channel + user count + topic (asterisk when unset)
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
    // Broadcast the resolved current nick of the target, not the raw token the
    // kicker typed (which may be mis-cased or a history-resolved old nick).
    let line = proto::line(
        &stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default(),
        "KICK",
        &format!("{} {} :{}", raw_chan, target_nick_scalar, reason_now),
    );
    for mid in broadcast_to {
        relay_tagged(stg, mid, &line);
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
        numeric(stg, id, "305", &["You are no longer marked as being away"]); // RFC numeric 305: trailing shape for clearing away status
        announce_away_change(stg, id, None);
        return;
    };

    let truncated: String = note.chars().take(100).collect(); // conventional cap, truncation not error
    if let Some(u) = stg.find_by_id_mut(id) {
        u.away = Some(truncated.clone());
    }
    numeric(stg, id, "306", &["You have been marked as being away"]); // RFC numeric 306: trailing shape for setting away status
    announce_away_change(stg, id, Some(&truncated));
}

/// away-notify (IRCv3): tell shared-channel peers who negotiated the cap that
/// this user went away (`AWAY :message`) or came back (`AWAY`, no argument).
fn announce_away_change(stg: &mut ServerState, id: usize, message: Option<&str>) {
    let prefix = match stg.find_by_id(id) {
        Some(u) => u.prefix(),
        None => return,
    };
    let line = match message {
        Some(m) => proto::line(&prefix, "AWAY", &format!(":{}", m)),
        None => proto::line(&prefix, "AWAY", ""),
    };
    let recipients = shared_channel_peers(stg, id, |u| u.caps.away_notify);
    for rid in recipients {
        relay_tagged(stg, rid, &line);
    }
}


/// PRIVMSG/NOTICE (RFC 4.4): delivers the trailing text to each comma-separated
/// recipient under the locked delivery rules -- NOTICE silent on every error path,
/// numeric-401 shape for unknown nicks on PRIV only, away targets auto-replied back
/// to the sender via numeric-301 shape. Channel/user@host dispatch rides alongside.
fn handle_privmsg(stg: &mut ServerState, id: usize, cmd: &Command, is_priv: bool) {
    let Some(recips_raw) = cmd.params.first() else { reply_missing_recipient(stg, id, is_priv); return };

    let text: Option<&str> = cmd.params.get(1).map(String::as_str);
    // Both PRIVMSG and NOTICE require non-empty text; on a missing body PRIVMSG
    // answers 412 while NOTICE stays silent (RFC 4.4 forbids NOTICE error
    // replies). NOTICE is the transport for CTCP replies and bot output, so it
    // must reach the same delivery path as PRIVMSG.
    match text {
        Some(t) if !t.is_empty() => {} // proceed to delivery below
        _ => { if is_priv { reply_missing_text(stg, id); } return; }
    }

    // Cap and de-duplicate the target list. Uncapped, one 512-byte line could
    // name the same victim 161 times and produce 161 deliveries -- a ~19x
    // amplifier that both flood tiers charged as a SINGLE message, because they
    // count input lines rather than deliveries. That multiplier, not CTCP
    // itself, is what made the reflection flood effective.
    let mut seen: Vec<String> = Vec::with_capacity(MAX_TARGETS);
    let mut over = false;
    for raw in recips_raw.split(',').filter(|c| !c.is_empty()) {
        let key = raw.to_lowercase();
        if seen.iter().any(|s| *s == key) {
            continue; // same target twice in one line is one delivery
        }
        if seen.len() >= MAX_TARGETS {
            over = true;
            break;
        }
        seen.push(key);
        stg.note_message(); // lifetime relay counter for the stats page
        deliver_one_recipient(stg, id, raw, text.unwrap(), is_priv);
    }
    if over {
        // ERR_TOOMANYTARGETS
        numeric(stg, id, "407", &[recips_raw, "Too many recipients"]);
    }
}

/// NickServ services pseudo-user: account registration and login. Replies are
/// NOTICEs from a synthetic `NickServ!services@<server>` prefix. Only PRIVMSGs
/// are acted on (NOTICEs are ignored to avoid client auto-reply loops).
fn handle_nickserv(stg: &mut ServerState, id: usize, text: &str, is_priv: bool) {
    if !is_priv {
        return;
    }
    let registered = stg.find_by_id(id).map(|u| u.registered).unwrap_or(false);
    if !registered {
        return;
    }
    let mut parts = text.split_whitespace();
    let sub = parts.next().unwrap_or("").to_uppercase();
    match sub.as_str() {
        "REGISTER" => {
            let pass = parts.next().unwrap_or("");
            let nick = stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default();
            if pass.is_empty() {
                nickserv_notice(stg, id, "Syntax: REGISTER <password>");
                return;
            }
            match stg.accounts.register(&nick, pass) {
                Ok(()) => {
                    if let Some(u) = stg.find_by_id_mut(id) {
                        u.account = Some(nick.clone());
                    }
                    nickserv_notice(stg, id, &format!("Account \x02{}\x02 registered; you are now identified.", nick));
                    apply_host_change(stg, id, account_host(&nick));
                    announce_account_change(stg, id, Some(&nick));
                }
                Err(e) => nickserv_notice(stg, id, &format!("Registration failed: {}.", e)),
            }
        }
        "IDENTIFY" | "LOGIN" => {
            let a = parts.next().unwrap_or("");
            let b = parts.next();
            let (acct, pass) = match b {
                Some(p) => (a.to_string(), p),
                None => (stg.find_by_id(id).map(|u| u.nick.clone()).unwrap_or_default(), a),
            };
            if pass.is_empty() {
                nickserv_notice(stg, id, "Syntax: IDENTIFY [account] <password>");
                return;
            }
            if stg.accounts.verify(&acct, pass) {
                let disp = stg.accounts.display_name(&acct).unwrap_or(acct);
                if let Some(u) = stg.find_by_id_mut(id) {
                    u.account = Some(disp.clone());
                }
                nickserv_notice(stg, id, &format!("You are now identified for \x02{}\x02.", disp));
                apply_host_change(stg, id, account_host(&disp));
                announce_account_change(stg, id, Some(&disp));
            } else {
                nickserv_notice(stg, id, "Invalid account or password.");
            }
        }
        "LOGOUT" => {
            let was = stg.find_by_id(id).and_then(|u| u.account.clone());
            let real = stg.find_by_id(id).map(|u| u.real_host.clone()).unwrap_or_default();
            if let Some(u) = stg.find_by_id_mut(id) {
                u.account = None;
            }
            if was.is_some() {
                apply_host_change(stg, id, crate::ops::cloak_host(&real)); // revert to IP cloak
                announce_account_change(stg, id, None);
            }
            nickserv_notice(stg, id, "You are now logged out.");
        }
        "GHOST" | "RECOVER" => {
            // Reclaim a registered nick held by a lingering ("ghost") session --
            // e.g. after a network drop where the old connection is not yet reaped.
            // Authorized either by being identified to that account or by supplying
            // its password. The held session is disconnected, freeing the nick.
            let target = parts.next().unwrap_or("");
            let pass = parts.next().unwrap_or("");
            if target.is_empty() {
                nickserv_notice(stg, id, "Syntax: GHOST <nick> [password]");
                return;
            }
            if !stg.accounts.exists(target) {
                nickserv_notice(stg, id, &format!("\x02{}\x02 is not a registered nick.", target));
                return;
            }
            let caller_account = stg.find_by_id(id).and_then(|u| u.account.clone());
            let authorized = caller_account
                .as_deref()
                .map(|a| norm_nick(a) == norm_nick(target))
                .unwrap_or(false)
                || (!pass.is_empty() && stg.accounts.verify(target, pass));
            if !authorized {
                nickserv_notice(stg, id, "Access denied. Identify to the account or supply its password.");
                return;
            }
            match stg.lookup(&norm_nick(target)).map(|u| u.id).filter(|&g| g != id) {
                Some(gid) => {
                    crate::ops::announce_loss_and_evict(stg, gid, "Ghosted by services");
                    nickserv_notice(stg, id, &format!("Session holding \x02{}\x02 has been disconnected. It is now free.", target));
                }
                None => nickserv_notice(stg, id, &format!("No other session is currently using \x02{}\x02.", target)),
            }
        }
        "" | "HELP" => {
            nickserv_notice(stg, id, "NickServ: REGISTER <password> | IDENTIFY [account] <password> | GHOST <nick> [password] | LOGOUT");
        }
        _ => nickserv_notice(stg, id, "Unknown command. Try HELP."),
    }
}

/// Send one NickServ NOTICE to a connection.
fn nickserv_notice(stg: &mut ServerState, id: usize, text: &str) {
    services_notice(stg, id, "NickServ", text);
}

/// ChanServ services pseudo-user: channel registration keyed to services
/// accounts. REGISTER requires the caller to be logged in and hold operator
/// status on the target channel; the founder is then auto-opped on join and the
/// channel's topic persists across restarts.
fn handle_chanserv(stg: &mut ServerState, id: usize, text: &str, is_priv: bool) {
    if !is_priv {
        return;
    }
    if !stg.find_by_id(id).map(|u| u.registered).unwrap_or(false) {
        return;
    }
    let mut parts = text.split_whitespace();
    let sub = parts.next().unwrap_or("").to_uppercase();
    let chan = parts.next().unwrap_or("");
    match sub.as_str() {
        "REGISTER" => {
            let account = stg.find_by_id(id).and_then(|u| u.account.clone());
            let Some(account) = account else {
                chanserv_notice(stg, id, "You must be logged in (see NickServ) to register a channel.");
                return;
            };
            if !valid_channel(chan) {
                chanserv_notice(stg, id, "Syntax: REGISTER #channel");
                return;
            }
            let key = chan.to_lowercase();
            if stg.chanreg.is_registered(&key) {
                chanserv_notice(stg, id, &format!("\x02{}\x02 is already registered.", chan));
                return;
            }
            let is_op = stg.chan(&key).map(|c| c.is_op(id)).unwrap_or(false);
            if !is_op {
                chanserv_notice(stg, id, &format!("You must be a channel operator on \x02{}\x02 to register it.", chan));
                return;
            }
            let display = stg.chan(&key).map(|c| c.display.clone()).unwrap_or_else(|| chan.to_string());
            match stg.chanreg.register(&key, &display, &account) {
                Ok(()) => {
                    // Persist the current topic, if any, immediately.
                    let topic_now = stg.chan(&key).map(|c| c.topic.clone()).unwrap_or_default();
                    if !topic_now.is_empty() {
                        stg.chanreg.set_topic(&key, &topic_now);
                    }
                    chanserv_notice(stg, id, &format!("Channel \x02{}\x02 registered to \x02{}\x02.", display, account));
                }
                Err(e) => chanserv_notice(stg, id, &format!("Registration failed: {}.", e)),
            }
        }
        "DROP" => {
            let account = stg.find_by_id(id).and_then(|u| u.account.clone()).unwrap_or_default();
            if !stg.chanreg.is_registered(&chan.to_lowercase()) {
                chanserv_notice(stg, id, "That channel is not registered.");
                return;
            }
            if !stg.chanreg.is_founder(&chan.to_lowercase(), &account) {
                chanserv_notice(stg, id, "Only the channel founder may drop it.");
                return;
            }
            stg.chanreg.drop_channel(&chan.to_lowercase());
            chanserv_notice(stg, id, &format!("Channel \x02{}\x02 dropped.", chan));
        }
        "INFO" => {
            match stg.chanreg.get(&chan.to_lowercase()) {
                Some(reg) => {
                    let (disp, founder) = (reg.display.clone(), reg.founder_display.clone());
                    chanserv_notice(stg, id, &format!("\x02{}\x02 -- founder: \x02{}\x02", disp, founder));
                }
                None => chanserv_notice(stg, id, "That channel is not registered."),
            }
        }
        "" | "HELP" => {
            chanserv_notice(stg, id, "ChanServ: REGISTER #channel | INFO #channel | DROP #channel");
        }
        _ => chanserv_notice(stg, id, "Unknown command. Try HELP."),
    }
}

fn chanserv_notice(stg: &mut ServerState, id: usize, text: &str) {
    services_notice(stg, id, "ChanServ", text);
}

/// Send one services NOTICE from `who!services@<server>` to a connection.
fn services_notice(stg: &mut ServerState, id: usize, who: &str, text: &str) {
    let srv = stg.name.clone();
    let nick = sender_nick(stg, id);
    let line = proto::line(
        &format!(":{}!services@{}", who, srv),
        "NOTICE",
        &format!("{} :{}", nick, text),
    );
    deliver(stg, id, &line);
}

/// Grant channel-operator status to a founder who has joined a channel they own
/// (their services account matches the ChanServ founder). Broadcasts a
/// `MODE +o` from ChanServ so every member — and the founder's own client — sees
/// the grant. No-op when the channel is unregistered or the user is not the
/// founder or is already opped.
fn apply_founder_status(stg: &mut ServerState, id: usize, norm_key: &str) {
    let account = match stg.find_by_id(id).and_then(|u| u.account.clone()) {
        Some(a) => a,
        None => return,
    };
    if !stg.chanreg.is_founder(norm_key, &account) {
        return;
    }
    let already = stg.chan(norm_key).map(|c| c.is_op(id)).unwrap_or(true);
    if already {
        return;
    }
    let (display, nick) = match (
        stg.chan(norm_key).map(|c| c.display.clone()),
        stg.find_by_id(id).map(|u| u.nick.clone()),
    ) {
        (Some(d), Some(n)) => (d, n),
        _ => return,
    };
    if let Some(c) = stg.chan_mut(norm_key) {
        c.grant(id, true);
    }
    let srv = stg.name.clone();
    let line = proto::line(&format!(":ChanServ!services@{}", srv), "MODE", &format!("{} +o {}", display, nick));
    let members: Vec<usize> = stg.chan(norm_key).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
    for mid in members {
        relay_tagged(stg, mid, &line);
    }
}

/// account-notify (IRCv3): tell shared-channel peers who negotiated the cap that
/// this connection logged in (`ACCOUNT <name>`) or out (`ACCOUNT *`).
fn announce_account_change(stg: &mut ServerState, id: usize, account: Option<&str>) {
    let prefix = match stg.find_by_id(id) {
        Some(u) => u.prefix(),
        None => return,
    };
    let line = proto::line(&prefix, "ACCOUNT", account.unwrap_or("*"));
    let recipients = shared_channel_peers(stg, id, |u| u.caps.account_notify);
    for rid in recipients {
        deliver(stg, rid, &line);
    }
}

/// Distinct connection ids sharing at least one channel with `id` (excluding
/// `id` itself) whose capability predicate holds. Used by the notify caps.
/// Stable per-account cloak `<account>.user.<suffix>`, replacing the IP-derived
/// cloak once a user authenticates.
fn account_host(account: &str) -> String {
    let suffix = std::env::var("IRC_CLOAK_SUFFIX").unwrap_or_else(|_| "chonkbase.net".to_string());
    let safe: String = account
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '-' })
        .collect();
    format!("{}.user.{}", safe, suffix)
}

/// Change a user's visible host (on account login/logout) and notify chghost-
/// capable channel peers, plus the user's own client, with a CHGHOST message.
fn apply_host_change(stg: &mut ServerState, id: usize, new_host: String) {
    let (old_prefix, user, registered, cur_host) = match stg.find_by_id(id) {
        Some(u) => (u.prefix(), u.user.clone(), u.registered, u.host.clone()),
        None => return,
    };
    if cur_host == new_host {
        return;
    }
    if let Some(u) = stg.find_by_id_mut(id) {
        u.host = new_host.clone();
    }
    if !registered {
        return; // pre-registration: host simply takes effect at welcome time
    }
    let line = proto::line(&old_prefix, "CHGHOST", &format!("{} {}", user, new_host));
    let mut targets = shared_channel_peers(stg, id, |u| u.caps.chghost);
    if stg.find_by_id(id).map(|u| u.caps.chghost).unwrap_or(false) {
        targets.push(id); // the user's own client learns its new host too
    }
    for rid in targets {
        deliver(stg, rid, &line);
    }
}

fn shared_channel_peers<F: Fn(&crate::state::Cx) -> bool>(
    stg: &ServerState,
    id: usize,
    pred: F,
) -> Vec<usize> {
    let chans: Vec<String> = stg
        .find_by_id(id)
        .map(|u| u.chans.iter().cloned().collect())
        .unwrap_or_default();
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for ck in &chans {
        if let Some(c) = stg.chan(ck) {
            for mid in c.members.iter().copied() {
                if mid == id || !seen.insert(mid) {
                    continue;
                }
                if stg.find_by_id(mid).map(&pred).unwrap_or(false) {
                    out.push(mid);
                }
            }
        }
    }
    out
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

    // Services pseudo-users: NickServ handles account registration / login and
    // ChanServ handles channel registration. Neither is a real connection, so
    // they are answered here rather than relayed.
    if norm_nick(raw) == "nickserv" {
        handle_nickserv(stg, id, text, is_priv);
        return;
    }
    if norm_nick(raw) == "chanserv" {
        handle_chanserv(stg, id, text, is_priv);
        return;
    }

    // STATUSMSG: "@#chan" reaches only channel operators, "+#chan" only
    // voiced-or-above. The prefix is preserved in the relayed target.
    if let Some((needed, chan)) = split_statusmsg(raw) {
        deliver_to_channel_status(stg, id, needed, chan, raw, text, is_priv);
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
    relay_tagged(stg, target_id_now, &line_now);

    if is_priv {
        let away_now: Option<String> = stg.find_by_id(target_id_now).and_then(|u| u.away.clone());
        let nick_now: String = stg.find_by_id(target_id_now).map(|u| u.nick.clone()).unwrap_or_default();

        if let Some(note) = away_now {
            numeric(stg, id, "301", &[&nick_now, &format!(":{}", note)]);
        }
    }
}


/// $ server-name mask dispatch for this single-server deployment.
fn deliver_to_server_mask(stg: &mut ServerState, id: usize, raw: &str, text: &str, is_priv: bool) {
    // Operator-only, as on every other ircd. Without this any registered client
    // could fan one small command out to every user on the server: a broadcast
    // amplifier, and a memory amplifier against per-connection reply queues.
    if !stg.find_by_id(id).map(|u| u.oper).unwrap_or(false) {
        numeric(stg, id, "481", &["Permission Denied- You're not an IRC operator"]);
        return;
    }

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
/// STATUSMSG target parse: "@#chan" or "+#chan" -> (prefix, channel).
fn split_statusmsg(raw: &str) -> Option<(char, &str)> {
    let mut chars = raw.chars();
    match chars.next() {
        Some(c @ ('@' | '+')) => {
            let rest = &raw[1..];
            if valid_channel(rest) {
                Some((c, rest))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Deliver a STATUSMSG to the subset of channel members at or above the required
/// status ('@' = operators, '+' = voiced-or-operators). The relayed target keeps
/// the status prefix so clients render it as a status message.
fn deliver_to_channel_status(
    stg: &mut ServerState,
    id: usize,
    needed: char,
    chan: &str,
    full_target: &str,
    text: &str,
    is_priv: bool,
) {
    let norm = chan.to_lowercase();
    if stg.chan(&norm).is_none() {
        if is_priv { deliver_nosuch_channel(stg, id, full_target); }
        return;
    }
    let gate_denied = match stg.chan(&norm) {
        Some(c) => c.nomsg() || (c.moderated() && !c.is_op(id) && !c.is_voiced(id)) || (c.invite_only() && !c.is_member(id)),
        None => true,
    };
    if gate_denied {
        if is_priv { numeric(stg, id, "404", &[full_target, "Cannot send to channel"]); }
        return;
    }
    let prefix = stg.find_by_id(id).map(|u| u.prefix()).unwrap_or_default();
    let verb = if is_priv { "PRIVMSG" } else { "NOTICE" };
    let members: Vec<usize> = stg.chan(&norm).map(|c| c.members.iter().copied().collect()).unwrap_or_default();
    for mid in members {
        if mid == id { continue; }
        let ok = match needed {
            '@' => stg.chan(&norm).map(|c| c.is_op(mid)).unwrap_or(false),
            '+' => stg.chan(&norm).map(|c| c.is_op(mid) || c.is_voiced(mid)).unwrap_or(false),
            _ => false,
        };
        if ok {
            relay_tagged(stg, mid, &proto::line(&prefix, verb, &format!("{} :{}", full_target, text)));
        }
    }
}

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
        relay_tagged(stg, mid, &proto::line(&prefix_now, verb_now, &format!("{} :{}", raw[0..].to_string(), text)));
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

            numeric(stg, id, "301", &[&nick_now, &format!(":{}", note)]);
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
                        let user_now: String = target_user_now.user.clone();

                        // RFC-shape reply: nick[*]=<+|-><user>@<host>. The user@ segment is
                        // mandatory in practice — clients such as BitchX do strchr(reply,'@')
                        // and dereference the result unconditionally, so a bare host segfaults them.
                        Some(format!("{}={}{}@{}", target_user_now.nick.clone(), away_flag_now, user_now, host_now))

                    }
                },
            }
        }).collect::<Vec<String>>();

    numeric(stg, id, "302", &[&format!(":{}", entries_now.join(" "))]);
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

    numeric(stg, id, "303", &[&format!(":{}", present_now.join(" "))]);
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


            numeric(stg, id, "311", &[&nick_now, &user_now, &host_now, "*", &format!(":{}", stg.name)]);

            // RPL_WHOISACCOUNT (330): the services account the target is logged in to.
            if let Some(acct_now) = stg.find_by_id(tid).and_then(|t| t.account.clone()) {
                numeric(stg, id, "330", &[&nick_now, &acct_now, "is logged in as"]);
            }

            // RPL_WHOISACTUALLY (338): operators (and self) may see the real host
            // behind the cloak; ordinary users never do.
            let req_is_oper = stg.find_by_id(id).map(|u| u.oper).unwrap_or(false);
            if req_is_oper || id == tid {
                if let Some(real_now) = stg.find_by_id(tid).map(|t| t.real_host.clone()) {
                    numeric(stg, id, "338", &[&nick_now, &format!("{}@{}", user_now, real_now), "is actually using host"]);
                }
            }

            if oper_now {
                numeric(stg, id, "313", &[&format!("{} is operating as an IRC Operator", nick_now)]);
            }


            if let Some(note_now) = away_now.clone() {
                numeric(stg, id, "301", &[&nick_now, &format!(":{}", note_now)]);
            }


            numeric(stg, id, "317", &[&nick_now, &idle_now.to_string(), "seconds idle"]);


            let chans_now: Vec<String> = chans_now_raw.iter()

                .filter_map(|ck| stg.chan(ck).map(|c| c.display.clone())).collect::<Vec<String>>();

            for chunk_now in chans_now.chunks(10) {
                numeric(stg, id, "319", &[&nick_now, &chans_now.len().to_string(), &format!("is on :{}", chunk_now.join(" "))]);
            }


            numeric(stg, id, "318", &[&nick_now, "End of /WHOIS list"]);
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
        numeric(stg, id, "406", &[nick_raw_now, "No such nick"]); // WASNOSUCHNICK: mandatory recipient token then the referenced name
        return;
    }


    for (nick_now, trailing_now) in hits_now.iter() {
        numeric(stg, id, "314", &[nick_now, "*", trailing_now]);
    }


    numeric(stg, id, "369", &[nick_raw_now, "End of /WHOWAS list"]);
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

            let _nick_key_now: String = cand.nick_key.clone();

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
        numeric(stg, id, "315", &[mask_raw_now, "End of /WHO list"]);
        return;
    }


    let who_chan_now: String = if is_channel_name_now { mask_raw_now.clone() } else { "*".to_string() };
    let server_name_now: String = stg.name.clone();

    // WHOX: a parameter carrying '%' selects the extended 354 reply with only the
    // requested fields. e.g. `WHO #chan %cuhnfar,152`.
    let whox_spec: Option<String> = cmd.params.iter().find(|p| p.contains('%')).cloned();

    if let Some(spec) = whox_spec {
        let after = spec.splitn(2, '%').nth(1).unwrap_or("");
        let mut it = after.splitn(2, ',');
        let fields = it.next().unwrap_or("").to_string();
        let token = it.next().map(|s| s.to_string());
        // Build every reply's field list first (immutable borrows), then emit.
        let rows: Vec<Vec<String>> = visible_ids_now
            .iter()
            .filter_map(|mid| stg.find_by_id(*mid).map(|u| {
                whox_fields(stg, id, u, &who_chan_now, &fields, token.as_deref())
            }))
            .collect();
        for row in rows {
            let refs: Vec<&str> = row.iter().map(String::as_str).collect();
            numeric(stg, id, "354", &refs); // RPL_WHOSPCRPL
        }
        numeric(stg, id, "315", &[mask_raw_now, "End of /WHO list"]);
        return;
    }

    let replies_now: Vec<[String; 7]> = visible_ids_now
        .iter()
        .filter_map(|mid| match stg.find_by_id(*mid) {
            None => None,
            // RFC 2812 352: <channel> <user> <host> <server> <nick> <flags> :<hop> <realname>
            Some(u) => Some([
                who_chan_now.clone(),
                u.user.clone(),
                host_of_user(stg, u.id),
                server_name_now.clone(),
                u.nick.clone(),
                who_marker_for(stg, id, u),
                format!(":0 {}", u.realname),
            ]),
        })
        .collect();

    for r in replies_now.iter() {
        numeric(stg, id, "352", &[&r[0], &r[1], &r[2], &r[3], &r[4], &r[5], &r[6]]);
    }


    numeric(stg, id, "315", &[mask_raw_now, "End of /WHO list"]);
}

/// Build the ordered field list for a WHOX (354) reply, honoring only the
/// requested field letters in their canonical order `tcuihsnfdlar`.
fn whox_fields(
    stg: &ServerState,
    req_id: usize,
    u: &crate::state::Cx,
    chan: &str,
    fields: &str,
    token: Option<&str>,
) -> Vec<String> {
    let idle = std::time::Instant::now().duration_since(u.last_rx).as_secs();
    let mut out: Vec<String> = Vec::new();
    for f in "tcuihsnfdlar".chars() {
        if !fields.contains(f) {
            continue;
        }
        out.push(match f {
            't' => token.unwrap_or("0").to_string(),
            'c' => chan.to_string(),
            'u' => u.user.clone(),
            'i' => u.host.clone(), // real IP never exposed; report the cloak
            'h' => u.host.clone(),
            's' => stg.name.clone(),
            'n' => u.nick.clone(),
            'f' => who_marker_for(stg, req_id, u),
            'd' => "0".to_string(),
            'l' => idle.to_string(),
            'a' => u.account.clone().unwrap_or_else(|| "0".to_string()),
            'r' => u.realname.clone(),
            _ => continue,
        });
    }
    out
}


/// Host scalar for a user identity (locked reply shaping).
fn host_of_user(stg: &ServerState, uid: usize) -> String {
    stg.find_by_id(uid).map(|u| u.host.clone()).unwrap_or_default()
}


/// Marker derivation for a WHO reply item per locked convention ('O', '@' or '+').
fn who_marker_for(stg: &ServerState, req_id: usize, target: &crate::state::Cx) -> String {
    // RFC 2812 RPL_WHOREPLY flags: <"H"|"G">["*"][ "@"|"+" ].
    //   H = here, G = gone (away); * = IRC operator; @/+ = channel op/voice.
    let mut flags = String::new();
    flags.push(if target.away.is_some() { 'G' } else { 'H' });
    if target.oper {
        flags.push('*');
    }

    // Channel status on the first channel shared with the requester.
    let shared = stg.find_by_id(req_id).and_then(|req| {
        target.chans.iter().find(|ck| req.chans.contains(*ck)).cloned()
    });
    if let Some(ck) = shared {
        if stg.chan(&ck).map(|c| c.is_op(target.id)).unwrap_or(false) {
            flags.push('@');
        } else if stg.chan(&ck).map(|c| c.is_voiced(target.id)).unwrap_or(false) {
            flags.push('+');
        }
    }
    flags
}



/// IRCv3 capabilities this server advertises AND honors. Never advertise a cap
/// that is not actually implemented.
const SUPPORTED_CAPS: &[&str] = &[
    "sasl",
    "server-time",
    "away-notify",
    "extended-join",
    "account-notify",
    "multi-prefix",
    "userhost-in-names",
    "chghost",
    "cap-notify",
];

fn cap_token(c: &str, with_values: bool) -> String {
    if with_values && c == "sasl" {
        "sasl=PLAIN".to_string()
    } else {
        c.to_string()
    }
}

fn set_cap(caps: &mut crate::state::Caps, name: &str, on: bool) {
    match name {
        "server-time" => caps.server_time = on,
        "away-notify" => caps.away_notify = on,
        "extended-join" => caps.extended_join = on,
        "account-notify" => caps.account_notify = on,
        "multi-prefix" => caps.multi_prefix = on,
        "userhost-in-names" => caps.userhost_in_names = on,
        "chghost" => caps.chghost = on,
        "cap-notify" => caps.cap_notify = on,
        "sasl" => caps.sasl = on,
        _ => {}
    }
}

/// CAP negotiation (IRCv3 capability-negotiation-3.2). LS advertises the honored
/// set (with `sasl=PLAIN` under `CAP LS 302`); REQ is all-or-nothing ACK/NAK;
/// LIST reports the enabled set; END closes negotiation and releases the welcome
/// burst withheld during the exchange.
fn handle_cap(stg: &mut ServerState, id: usize, cmd: &Command) {
    let sub = cmd.params.first().map(|s| s.to_uppercase()).unwrap_or_default();
    match sub.as_str() {
        "LS" => {
            if let Some(u) = stg.find_by_id_mut(id) {
                u.cap_negotiating = true;
            }
            let with_values = cmd.params.get(1).map(|v| v == "302").unwrap_or(false);
            let list = SUPPORTED_CAPS
                .iter()
                .map(|c| cap_token(c, with_values))
                .collect::<Vec<String>>()
                .join(" ");
            deliver(stg, id, &proto::line(&stg.prefix(), "CAP", &format!("* LS :{}", list)));
        }
        "LIST" => {
            let enabled = stg.find_by_id(id).map(|u| u.caps.enabled_list()).unwrap_or_default();
            deliver(stg, id, &proto::line(&stg.prefix(), "CAP", &format!("* LIST :{}", enabled)));
        }
        "REQ" => {
            let req = cmd.params.get(1).map(|s| s.trim_start_matches(':').trim()).unwrap_or("");
            let tokens: Vec<&str> = req.split_whitespace().collect();
            let all_ok = !tokens.is_empty()
                && tokens.iter().all(|t| SUPPORTED_CAPS.contains(&t.trim_start_matches('-')));
            if let Some(u) = stg.find_by_id_mut(id) {
                u.cap_negotiating = true;
            }
            if all_ok {
                for t in &tokens {
                    let enable = !t.starts_with('-');
                    let name = t.trim_start_matches('-');
                    if let Some(u) = stg.find_by_id_mut(id) {
                        set_cap(&mut u.caps, name, enable);
                    }
                }
                deliver(stg, id, &proto::line(&stg.prefix(), "CAP", &format!("* ACK :{}", req)));
            } else {
                deliver(stg, id, &proto::line(&stg.prefix(), "CAP", &format!("* NAK :{}", req)));
            }
        }
        "END" => {
            if let Some(u) = stg.find_by_id_mut(id) {
                u.cap_negotiating = false;
            }
            flush_cap_gated_welcome(stg, id);
        }
        _ => {} // unknown subcommand: silently ignored, never an error
    }
}

/// SASL PLAIN (IRCv3 sasl-3.1). The exchange is: client `AUTHENTICATE PLAIN`,
/// server `AUTHENTICATE +`, client base64(authzid \0 authcid \0 passwd), then
/// 900 (RPL_LOGGEDIN) + 903 (RPL_SASLSUCCESS) on success or 904 on failure.
fn handle_authenticate(stg: &mut ServerState, id: usize, cmd: &Command) {
    // SASL is only meaningful when the client negotiated the cap and is not yet
    // registered (RFC: authentication happens during registration).
    let (has_cap, registered) = stg
        .find_by_id(id)
        .map(|u| (u.caps.sasl, u.registered))
        .unwrap_or((false, false));
    if registered {
        numeric(stg, id, "907", &["You have already authenticated using SASL"]);
        return;
    }
    if !has_cap {
        numeric(stg, id, "906", &["SASL authentication aborted"]);
        return;
    }

    let arg = cmd.params.first().map(String::as_str).unwrap_or("");

    // Abort request.
    if arg == "*" {
        if let Some(u) = stg.find_by_id_mut(id) {
            u.sasl_mech = None;
        }
        numeric(stg, id, "906", &["SASL authentication aborted"]);
        return;
    }

    // Mechanism selection step.
    let pending_mech = stg.find_by_id(id).and_then(|u| u.sasl_mech.clone());
    if pending_mech.is_none() {
        if arg.eq_ignore_ascii_case("PLAIN") {
            if let Some(u) = stg.find_by_id_mut(id) {
                u.sasl_mech = Some("PLAIN".to_string());
            }
            deliver(stg, id, &proto::line("", "AUTHENTICATE", "+"));
        } else {
            // Only PLAIN is offered; steer the client to it.
            numeric(stg, id, "908", &["PLAIN", "are the available SASL mechanisms"]);
            numeric(stg, id, "904", &["SASL authentication failed"]);
        }
        return;
    }

    // Credential step: `arg` is the base64 PLAIN payload.
    let decoded = match crate::crypto::base64_decode(arg) {
        Some(d) => d,
        None => {
            reset_sasl(stg, id);
            numeric(stg, id, "904", &["SASL authentication failed"]);
            return;
        }
    };
    // PLAIN = authzid \0 authcid \0 passwd
    let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
    if parts.len() != 3 {
        reset_sasl(stg, id);
        numeric(stg, id, "904", &["SASL authentication failed"]);
        return;
    }
    let authcid = String::from_utf8_lossy(parts[1]).to_string();
    let passwd = String::from_utf8_lossy(parts[2]).to_string();

    if stg.accounts.verify(&authcid, &passwd) {
        let disp = stg.accounts.display_name(&authcid).unwrap_or(authcid);
        if let Some(u) = stg.find_by_id_mut(id) {
            u.account = Some(disp.clone());
            u.sasl_mech = None;
        }
        // Pre-registration host takes the account cloak; it becomes visible when
        // the welcome burst completes (no CHGHOST needed yet, not in channels).
        apply_host_change(stg, id, account_host(&disp));
        // 900 RPL_LOGGEDIN wants a nick!user@host; pre-registration these may be
        // partially known, so fall back to '*' fields where absent.
        let ident = stg
            .find_by_id(id)
            .map(|u| {
                let n = if u.nick.is_empty() { "*" } else { &u.nick };
                let us = if u.user.is_empty() { "*" } else { &u.user };
                format!("{}!{}@{}", n, us, u.host)
            })
            .unwrap_or_else(|| "*!*@*".into());
        numeric(stg, id, "900", &[&ident, &disp, &format!(":You are now logged in as {}", disp)]);
        numeric(stg, id, "903", &["SASL authentication successful"]);
    } else {
        reset_sasl(stg, id);
        numeric(stg, id, "904", &["SASL authentication failed"]);
    }
}

fn reset_sasl(stg: &mut ServerState, id: usize) {
    if let Some(u) = stg.find_by_id_mut(id) {
        u.sasl_mech = None;
    }
}

/// Misc-command replies under locked conventions (PING; WALLOPS/SUMMON/USERS disabled-shapes).
fn handle_misc_stub(stg: &mut ServerState, id: usize, cmd: &Command) {
    // Only PING routes here now; every other command has its own dispatch arm.
    if cmd.name == "PING" {
        match cmd.params.first().map(String::as_str) {
            None => { numeric(stg, id, "409", &["No origin specified"]); } // ERR_NOORIGIN
            Some(token_now) => deliver(
                stg,
                id,
                &proto::line(&stg.prefix(), "PONG", &format!("{} :{}", stg.name, token_now)),
            ),
        }
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
            let users = stg.user_count();
            numeric(stg, id, "251", &[&format!("There are {} users and {} invisible on 1 servers", users, stg.invis_count())]);
            numeric(stg, id, "254", &[&stg.chan_count().to_string(), "channels formed"]);
            numeric(stg, id, "255", &[&format!("I have {} clients and 0 servers", users)]);
            numeric(stg, id, "265", &[&users.to_string(), &users.to_string(), &format!("Current local users {}, max {}", users, users)]);
            numeric(stg, id, "266", &[&users.to_string(), &users.to_string(), &format!("Current global users {}, max {}", users, users)]);
        }


        "STATS" => {

            let scopes_now: &str = cmd.params.first().map(String::as_str).unwrap_or("ubo");

            for letter_now in scopes_now.bytes() {

                match letter_now {

                    // Real uptime; this reported a literal 0 before.
                    b'u' => { let name_now = stg.name.clone(); let up = stg.uptime_secs(); numeric(stg, id, "242", &[&name_now, &format!("- Server uptime {}s", up)]); }

                    b'b' => { let name_now = stg.name.clone(); numeric(stg, id, "213", &[&name_now, &format!("- CLINE {}", 0)]); } // normalized trailing shape through the shared chokepoint

                    b'o' => { let name_now = stg.name.clone(); numeric(stg, id, "243", &[&name_now, "*", "operator"]); } // recipient token first through the shared chokepoint

                    // K-lines. The store existed and was unreadable, so an
                    // operator could not list the bans they had set.
                    b'K' | b'k' => {
                        if stg.find_by_id(id).map(|u| u.oper).unwrap_or(false) {
                            let rows: Vec<(String, String, u64)> = stg
                                .bans
                                .list()
                                .iter()
                                .map(|b| (b.mask.clone(), b.reason.clone(), b.expiry))
                                .collect();
                            for (mask, reason, expiry) in rows {
                                let when = if expiry == 0 { "permanent".to_string() } else { format!("expires {}", expiry) };
                                numeric(stg, id, "216", &["K", &mask, &format!("- {} ({})", reason, when)]);
                            }
                        } else {
                            numeric(stg, id, "481", &["Permission Denied- You're not an IRC operator"]);
                        }
                    }

                    // Live limits, so an operator can see what is actually in
                    // force rather than inferring it from the manifest.
                    b'I' | b'i' => {
                        if stg.find_by_id(id).map(|u| u.oper).unwrap_or(false) {
                            let l = &stg.limits;
                            let rows = [
                                format!("- max_clients {}", l.max_clients),
                                format!("- clones_per_ip {}", l.max_clones_per_ip),
                                format!("- connects_per_window {}", l.max_connects_per_window),
                                format!("- messages_per_window {}", l.max_messages_per_window),
                                format!("- flood_violations {}", l.max_violations),
                                format!("- exempt {}", l.exempt.join(",")),
                            ];
                            for r in rows { numeric(stg, id, "215", &["I", &r]); }
                        } else {
                            numeric(stg, id, "481", &["Permission Denied- You're not an IRC operator"]);
                        }
                    }

                    // Busiest sources right now: the "who is flooding me" query.
                    b'L' | b'l' => {
                        if stg.find_by_id(id).map(|u| u.oper).unwrap_or(false) {
                            let top = stg.sources.top_sources(15);
                            let total = stg.sources.active_total();
                            let tracked = stg.sources.tracked_sources();
                            numeric(stg, id, "211", &["*", &format!("- {} connections from {} sources", total, tracked)]);
                            for (src, n) in top {
                                numeric(stg, id, "211", &[&src, &format!("- {} connections", n)]);
                            }
                        } else {
                            numeric(stg, id, "481", &["Permission Denied- You're not an IRC operator"]);
                        }
                    }

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


