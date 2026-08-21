//! Network state: other servers on the spanning tree, and the users they own.
//!
//! The protocol identifies every user by an immutable UUID (a 3-character SID
//! naming their server plus a 6-character UID), never by nickname. The
//! documentation is explicit about why: "referring to users by their nickname
//! may cause race conditions" -- two servers can accept a user called `alice`
//! in the same instant, and a protocol that routes by nickname cannot say which
//! one it meant.
//!
//! Local users keep their existing nickname-keyed home in `ServerState`; this
//! module adds the UUID layer beside it and owns everything remote. Keeping the
//! two separate means linking does not require re-keying the entire local user
//! table in one step, at the cost of two lookups where a fully re-keyed server
//! would have one.

use std::collections::{BTreeSet, HashMap};

/// SID grammar: `[0-9][A-Z0-9]{2}`.
pub fn valid_sid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 3
        && b[0].is_ascii_digit()
        && b[1..].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// UID grammar: `[A-Z0-9]{6}`.
pub fn valid_uid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 6 && b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// A full UUID is a SID followed by a UID.
pub fn valid_uuid(s: &str) -> bool {
    s.len() == 9 && valid_sid(&s[..3]) && valid_uid(&s[3..])
}

/// One other server on the tree.
#[derive(Clone, Debug, PartialEq)]
pub struct RemoteServer {
    pub sid: String,
    pub name: String,
    pub desc: String,
    /// Distance in hops; 1 is a directly-linked peer.
    pub hop: u32,
    /// SID of the neighbour this server is reached through.
    pub via: String,
    /// Still sending its initial state dump.
    pub bursting: bool,
}

/// A user owned by another server.
#[derive(Clone, Debug, PartialEq)]
pub struct RemoteUser {
    pub uuid: String,
    pub sid: String,
    pub nick: String,
    pub nick_key: String,
    pub user: String,
    /// Displayed host, which may be a cloak applied by their server.
    pub host: String,
    pub real_host: String,
    pub realname: String,
    pub ts: u64,
    pub modes: String,
    pub chans: BTreeSet<String>,
    pub away: Option<String>,
    pub oper: bool,
}

/// Everything this server knows about the rest of the network.
pub struct Network {
    /// Our own SID.
    pub sid: String,
    servers: HashMap<String, RemoteServer>,
    users: HashMap<String, RemoteUser>,
    /// Normalised nickname to UUID, for the places IRC still speaks in nicks.
    nick_index: HashMap<String, String>,
    /// Local connection id to the UUID minted for it.
    local_uuids: HashMap<usize, String>,
    next_uid: u64,
}

const UID_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

impl Network {
    pub fn new(sid: &str) -> Self {
        Network {
            sid: sid.to_string(),
            servers: HashMap::new(),
            users: HashMap::new(),
            nick_index: HashMap::new(),
            local_uuids: HashMap::new(),
            next_uid: 0,
        }
    }

    /// Mint the next UID in sequence, matching the conventional `AAAAAA`,
    /// `AAAAAB`, ... ordering so a capture is readable next to InspIRCd's own.
    pub fn next_uid(&mut self) -> String {
        let mut n = self.next_uid;
        self.next_uid = self.next_uid.wrapping_add(1);
        let base = UID_ALPHABET.len() as u64;
        let mut out = [b'A'; 6];
        for slot in out.iter_mut().rev() {
            *slot = UID_ALPHABET[(n % base) as usize];
            n /= base;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Assign (or return the existing) UUID for a local connection.
    pub fn uuid_for_local(&mut self, id: usize) -> String {
        if let Some(existing) = self.local_uuids.get(&id) {
            return existing.clone();
        }
        let uid = self.next_uid();
        let uuid = format!("{}{}", self.sid, uid);
        self.local_uuids.insert(id, uuid.clone());
        uuid
    }

    pub fn local_uuid(&self, id: usize) -> Option<&String> {
        self.local_uuids.get(&id)
    }

    /// The local connection that owns a UUID, if we minted it.
    pub fn local_uuid_owner(&self, uuid: &str) -> Option<usize> {
        self.local_uuids.iter().find(|(_, v)| v.as_str() == uuid).map(|(k, _)| *k)
    }

    pub fn forget_local(&mut self, id: usize) {
        self.local_uuids.remove(&id);
    }

    // ---- servers ----

    pub fn add_server(&mut self, s: RemoteServer) {
        self.servers.insert(s.sid.clone(), s);
    }

    pub fn server(&self, sid: &str) -> Option<&RemoteServer> {
        self.servers.get(sid)
    }

    pub fn server_mut(&mut self, sid: &str) -> Option<&mut RemoteServer> {
        self.servers.get_mut(sid)
    }

    pub fn servers(&self) -> impl Iterator<Item = &RemoteServer> + '_ {
        self.servers.values()
    }

    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Remove a server and everything behind it, returning the UUIDs of every
    /// user lost. A split takes the whole subtree, not just the neighbour.
    pub fn split_server(&mut self, sid: &str) -> Vec<String> {
        let mut gone = vec![sid.to_string()];
        // Servers reached through the one leaving are unreachable too.
        loop {
            let next: Vec<String> = self
                .servers
                .values()
                .filter(|s| gone.contains(&s.via) && !gone.contains(&s.sid))
                .map(|s| s.sid.clone())
                .collect();
            if next.is_empty() {
                break;
            }
            gone.extend(next);
        }
        for s in &gone {
            self.servers.remove(s);
        }
        let lost: Vec<String> = self
            .users
            .values()
            .filter(|u| gone.contains(&u.sid))
            .map(|u| u.uuid.clone())
            .collect();
        for uuid in &lost {
            self.remove_user(uuid);
        }
        lost
    }

    // ---- users ----

    pub fn add_user(&mut self, u: RemoteUser) {
        self.nick_index.insert(u.nick_key.clone(), u.uuid.clone());
        self.users.insert(u.uuid.clone(), u);
    }

    pub fn user(&self, uuid: &str) -> Option<&RemoteUser> {
        self.users.get(uuid)
    }

    pub fn user_mut(&mut self, uuid: &str) -> Option<&mut RemoteUser> {
        self.users.get_mut(uuid)
    }

    pub fn by_nick(&self, nick_key: &str) -> Option<&RemoteUser> {
        self.nick_index.get(nick_key).and_then(|u| self.users.get(u))
    }

    pub fn remove_user(&mut self, uuid: &str) -> Option<RemoteUser> {
        let u = self.users.remove(uuid)?;
        // Only clear the index if it still points at this user: a collision may
        // already have handed the nickname to somebody else.
        if self.nick_index.get(&u.nick_key) == Some(&u.uuid) {
            self.nick_index.remove(&u.nick_key);
        }
        Some(u)
    }

    /// Apply a remote nickname change, keeping the index consistent.
    pub fn rename_user(&mut self, uuid: &str, new_nick: &str, new_key: &str) -> bool {
        let old_key = match self.users.get(uuid) {
            Some(u) => u.nick_key.clone(),
            None => return false,
        };
        if self.nick_index.get(&old_key) == Some(&uuid.to_string()) {
            self.nick_index.remove(&old_key);
        }
        if let Some(u) = self.users.get_mut(uuid) {
            u.nick = new_nick.to_string();
            u.nick_key = new_key.to_string();
        }
        self.nick_index.insert(new_key.to_string(), uuid.to_string());
        true
    }

    pub fn users(&self) -> impl Iterator<Item = &RemoteUser> + '_ {
        self.users.values()
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// UUIDs of remote users in a channel.
    pub fn members_of(&self, chan_key: &str) -> Vec<String> {
        self.users
            .values()
            .filter(|u| u.chans.contains(chan_key))
            .map(|u| u.uuid.clone())
            .collect()
    }

    /// SIDs that have at least one user in the channel, so a channel message
    /// reaches exactly the servers that need it and no others.
    pub fn sids_in_channel(&self, chan_key: &str) -> BTreeSet<String> {
        self.users
            .values()
            .filter(|u| u.chans.contains(chan_key))
            .map(|u| u.sid.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_grammars() {
        assert!(valid_sid("1IN"));
        assert!(valid_sid("079"));
        assert!(!valid_sid("IN1"), "a SID must start with a digit");
        assert!(!valid_sid("1in"), "lowercase is not permitted");
        assert!(!valid_sid("12"));
        assert!(valid_uid("AAAAAA"));
        assert!(valid_uid("Z9Z9Z9"));
        assert!(!valid_uid("AAAAA"));
        assert!(!valid_uid("aaaaaa"));
        assert!(valid_uuid("1INAAAAAA"));
        assert!(!valid_uuid("1INAAAAA"));
    }

    #[test]
    fn uids_are_sequential_and_well_formed() {
        let mut n = Network::new("2CH");
        let first = n.next_uid();
        let second = n.next_uid();
        assert_eq!(first, "AAAAAA");
        assert_eq!(second, "AAAAAB");
        assert!(valid_uid(&first) && valid_uid(&second));
    }

    #[test]
    fn uid_sequence_carries_across_the_alphabet() {
        let mut n = Network::new("2CH");
        for _ in 0..35 {
            n.next_uid();
        }
        assert_eq!(n.next_uid(), "AAAAA9", "last symbol before the carry");
        assert_eq!(n.next_uid(), "AAAABA", "carry into the next position");
    }

    #[test]
    fn a_local_connection_keeps_one_uuid() {
        let mut n = Network::new("2CH");
        let a = n.uuid_for_local(7);
        let b = n.uuid_for_local(7);
        assert_eq!(a, b, "a connection must not be re-identified mid-session");
        assert!(valid_uuid(&a));
        assert!(a.starts_with("2CH"));
        assert_ne!(a, n.uuid_for_local(8));
    }

    fn user(uuid: &str, sid: &str, nick: &str) -> RemoteUser {
        RemoteUser {
            uuid: uuid.into(),
            sid: sid.into(),
            nick: nick.into(),
            nick_key: nick.to_lowercase(),
            user: "u".into(),
            host: "h".into(),
            real_host: "h".into(),
            realname: "r".into(),
            ts: 1,
            modes: "+".into(),
            chans: BTreeSet::new(),
            away: None,
            oper: false,
        }
    }

    #[test]
    fn users_resolve_by_uuid_and_by_nick() {
        let mut n = Network::new("2CH");
        n.add_user(user("1INAAAAAA", "1IN", "alice"));
        assert_eq!(n.user("1INAAAAAA").map(|u| u.nick.as_str()), Some("alice"));
        assert_eq!(n.by_nick("alice").map(|u| u.uuid.as_str()), Some("1INAAAAAA"));
        assert!(n.by_nick("bob").is_none());
    }

    #[test]
    fn renaming_keeps_the_nick_index_consistent() {
        let mut n = Network::new("2CH");
        n.add_user(user("1INAAAAAA", "1IN", "alice"));
        n.rename_user("1INAAAAAA", "carol", "carol");
        assert!(n.by_nick("alice").is_none(), "the old nickname must be released");
        assert_eq!(n.by_nick("carol").map(|u| u.uuid.as_str()), Some("1INAAAAAA"));
        // The identity itself is unchanged, which is the entire point of a UUID.
        assert_eq!(n.user("1INAAAAAA").map(|u| u.uuid.as_str()), Some("1INAAAAAA"));
    }

    #[test]
    fn removing_a_user_does_not_steal_a_reassigned_nick() {
        let mut n = Network::new("2CH");
        n.add_user(user("1INAAAAAA", "1IN", "alice"));
        // A second user takes the nickname after a collision.
        n.add_user(user("1INAAAAAB", "1IN", "alice"));
        n.remove_user("1INAAAAAA");
        assert_eq!(
            n.by_nick("alice").map(|u| u.uuid.as_str()),
            Some("1INAAAAAB"),
            "removing the old holder must not unmap the new one"
        );
    }

    #[test]
    fn a_split_takes_the_whole_subtree() {
        let mut n = Network::new("2CH");
        n.add_server(RemoteServer { sid: "1IN".into(), name: "a".into(), desc: String::new(), hop: 1, via: "1IN".into(), bursting: false });
        // 2IN is reached through 1IN, so losing 1IN loses it too.
        n.add_server(RemoteServer { sid: "2IN".into(), name: "b".into(), desc: String::new(), hop: 2, via: "1IN".into(), bursting: false });
        n.add_server(RemoteServer { sid: "3IN".into(), name: "c".into(), desc: String::new(), hop: 1, via: "3IN".into(), bursting: false });
        n.add_user(user("1INAAAAAA", "1IN", "alice"));
        n.add_user(user("2INAAAAAA", "2IN", "bob"));
        n.add_user(user("3INAAAAAA", "3IN", "carol"));

        let lost = n.split_server("1IN");
        assert_eq!(lost.len(), 2, "users behind the split are lost as well: {lost:?}");
        assert!(n.user("3INAAAAAA").is_some(), "an unrelated branch survives");
        assert_eq!(n.server_count(), 1);
    }

    #[test]
    fn channel_routing_targets_only_servers_with_members() {
        let mut n = Network::new("2CH");
        let mut a = user("1INAAAAAA", "1IN", "alice");
        a.chans.insert("#test".into());
        let b = user("3INAAAAAA", "3IN", "bob"); // in no channel
        n.add_user(a);
        n.add_user(b);
        let sids = n.sids_in_channel("#test");
        assert!(sids.contains("1IN"));
        assert!(!sids.contains("3IN"), "a server with no member must not be sent the message");
    }
}
