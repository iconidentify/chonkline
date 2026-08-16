use std::fmt::Write as _;

pub const VERSION: &str = "chonkline-beta";
pub const MAX_LINE_WITH_CRLF: usize = 512; // RFC 2.3: incl. trailing CR-LF
pub const MAX_CONTENT_BYTES: usize = 510;
pub const MAX_PARAMS: usize = 15;         // RFC 2.3: up to 15 parameters

#[derive(Debug, Clone)]
pub struct Command {
    pub prefix: Option<String>,
    pub name: String,
    pub params: Vec<String>,
}


fn needs_trailing_marker(s: &str) -> bool {
    !s.is_empty() && s.contains(' ') && !s.starts_with(':')
}

/// Compose one message. `prefix` may be empty for no-prefix lines. `tail` is
/// everything after the keyword, composed verbatim by the caller so that each
/// reply matches its RFC format string exactly. Output ends with CR-LF.
pub fn line(prefix: &str, keyword: &str, tail: &str) -> String {
    let mut out = String::with_capacity(MAX_LINE_WITH_CRLF);
    if !prefix.is_empty() {
        out.push_str(prefix);
        out.push(' ');
    }
    out.push_str(keyword);
    if !tail.is_empty() {
        out.push(' ');
        out.push_str(tail);
    }
    format!("{}\r\n", out)
}

/// Compose one message from discrete parameters; marks the final parameter as
/// trailing when required (contains spaces or starts with ':'). Callers must
/// not pass empty strings. Output ends with CR-LF.
pub fn params(prefix: &str, keyword: &str, args: &[&str]) -> String {
    let mut body = String::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            body.push(' ');
        }
        if i == args.len() - 1 && needs_trailing_marker(a) {
            body.push(':');
        }
        write!(&mut body, "{}", a).unwrap();
    }
    line(prefix, keyword, &body)
}

/// Prefix for user-originated lines relayed to clients (RFC 2.3 note 6).
pub fn user_prefix(nick: &str, user: &str, host: &str) -> String {
    format!("{}!{}@{}", nick, user, host)
}

/// Civil date/time (UTC) from a Unix timestamp — Howard Hinnant's algorithm,
/// valid across the full proleptic Gregorian range without a calendar library.
fn civil_from_epoch(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86400) as i64;
    let rem = (secs % 86400) as u32;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, h, mi, s)
}

/// IRCv3 `server-time` timestamp: ISO-8601 UTC with milliseconds, e.g.
/// `2026-08-16T08:12:34.567Z`.
pub fn ircv3_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let (y, mo, d, h, mi, s) = civil_from_epoch(now.as_secs());
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, mo, d, h, mi, s, now.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_trailing() {
        let c = parse("NICK Wiz").unwrap();
        assert_eq!(c.name, "NICK");
        assert_eq!(c.params, vec!["Wiz"]);

        let c = parse("PRIVMSG #chan :hello world").unwrap();
        assert_eq!(c.params, vec!["#chan", "hello world"]);

        let c = parse(":WiZ PRIVMSG Angel :hi there").unwrap();
        assert_eq!(c.prefix.as_deref(), Some("WiZ"));
    }

    #[test]
    fn parses_trailing_after_command() {
        let c = parse("AWAY :gone").unwrap();
        assert_eq!(c.params, vec!["gone"]);
        // An empty trailing is preserved as a single empty parameter.
        let c = parse("AWAY :").unwrap();
        assert_eq!(c.params.len(), 1);
        assert!(c.params[0].is_empty());
    }

    #[test]
    fn rejects_bad_grammar() {
        assert!(parse(":badprefix").is_none()); // no space after prefix => malformed
        assert!(parse("").is_none());
        assert!(parse("   ").is_none());
        let nul = format!("NICK a\x00b");
        assert!(parse(&nul).is_none()); // NUL not allowed within messages
    }

    #[test]
    fn over_params_dropped() {
        let many: Vec<String> = (0..16).map(|i| format!("p{}", i)).collect();
        let cmd = format!("MODE {}", many.join(" "));
        assert!(parse(&cmd).is_none()); // more than 15 parameters
    }

    #[test]
    fn timestamp_civil_conversion() {
        // 1700000000 = 2023-11-14T22:13:20Z (known epoch).
        let (y, mo, d, h, mi, s) = super::civil_from_epoch(1_700_000_000);
        assert_eq!((y, mo, d, h, mi, s), (2023, 11, 14, 22, 13, 20));
        // epoch 0 = 1970-01-01T00:00:00Z
        assert_eq!(super::civil_from_epoch(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn serialize_marks_trailing() {
        assert_eq!(
            params("srv", "431", &["x", ":No nickname given"]),
            "srv 431 x :No nickname given\r\n"
        );
        assert_eq!(line("srv", "PONG", ":some token"), "srv PONG :some token\r\n");
    }
}
/// Parse one message per the RFC 2.3 grammar: optional `:<prefix>` then command name, then space-separated parameters with a token-boundary trailing marker. Lines over length, containing NULs, or missing commands are rejected silently.
/// Parse one message per the RFC 2.3 grammar: optional `:<prefix>` then command name, then space-separated parameters with a token-boundary trailing marker. Lines over length, containing NULs, or missing commands are rejected silently.
pub fn parse(line: &str) -> Option<Command> {
    if line.len() > MAX_CONTENT_BYTES || line.is_empty() || line.bytes().any(|b| b == 0x00) {
        return None;
    }

    let prefix_now: Option<String> = match line.find(':') {
        None => None,
        Some(0) => match line[1..].find(|c: char| c.is_ascii_whitespace()) {
            None => Some(line[1..].to_string()),
            Some(rel2) => Some(line.get(1..rel2 + 1).map(str::to_string)).flatten(),
        },
        Some(_) => None,
    };

    let rest_now: &str = match prefix_now.as_deref() {
        Some(p) => line.get(p.len() + 2..).unwrap_or(""),
        None => line,
    };

    let name_end_now: usize = rest_now.find(|c: char| c.is_ascii_whitespace()).unwrap_or(rest_now.len());
    if name_end_now == 0 || !rest_now[..name_end_now].chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    let mut params_now: Vec<String> = Vec::new();
    let chars_now: Vec<char> = rest_now[name_end_now..].chars().collect();
    let mut i_now: usize = 0;

    while i_now < chars_now.len() {
        if chars_now[i_now].is_ascii_whitespace() {
            i_now += 1;
            continue;
        }
        if chars_now[i_now] == ':' {
            params_now.push(chars_now[i_now + 1..].iter().collect());
            i_now = chars_now.len();
            continue;
        }
        let mut tok2: Vec<char> = vec![];
        while i_now < chars_now.len() && !chars_now[i_now].is_ascii_whitespace() {
            tok2.push(chars_now[i_now]);
            i_now += 1;
        }
        params_now.push(tok2.into_iter().collect());
    }

    if params_now.len() > MAX_PARAMS { return None; }

    let name_now: String = rest_now[..name_end_now].to_string();
    Some(Command { prefix: prefix_now, name: name_now.to_uppercase(), params: params_now })
}

