# Chonkline

A standalone IRC server written in Rust (async, `tokio`), implementing the client
protocol of RFC 1459 / RFC 2812 as it is practiced today. It is dependency-light:
`tokio` for the runtime and `rustls` for TLS.

## Features

- Connection registration (`PASS` / `NICK` / `USER`), MOTD, LUSERS
- Channels: `JOIN` / `PART` / `TOPIC` / `NAMES` / `LIST` / `INVITE` / `KICK`
- Channel and user `MODE` (invite-only, keys, limits, bans, ops, …)
- Messaging: `PRIVMSG` / `NOTICE` (CTCP passes through transparently)
- Queries: `WHO` / `WHOIS` / `WHOWAS` / `ISON` / `USERHOST`
- Server info: `VERSION` / `STATS` / `TIME` / `ADMIN` / `INFO` / `MOTD`
- `AWAY`, `OPER`, `WALLOPS`, `PING` / `PONG` keepalive
- **Accounts**: `NickServ` `REGISTER` / `IDENTIFY` / `SET PASSWORD` /
  `CERT LIST|ADD|DEL`, PBKDF2-hashed passwords and certificate fingerprints
  persisted to disk. `NickServ` and `ChanServ` cannot be taken as nicks
  or account names
- **Channels**: `ChanServ` `REGISTER` / `INFO` / `DROP` / `OP` — founders are
  auto-opped on join and again when they identify, and registered channels keep
  their topic across restarts
- **SASL** `PLAIN`, and `EXTERNAL` on TLS when the client presents a certificate.
  Both can be used on one NickServ account. `PLAIN` accepts the usual order of
  `NICK`/`USER` before `AUTHENTICATE`
- **IRCv3 capabilities**: `sasl`, `message-tags`, `server-time`, `account-tag`,
  `away-notify`, `extended-join`, `account-notify`, `multi-prefix`,
  `userhost-in-names`, `chghost`, `cap-notify`, `batch`, `labeled-response`
  (proper `CAP LS 302` negotiation). `labeled-response` is applied once `batch`
  is negotiated as well; the two may be requested in either order
- **ISUPPORT**: `SAFELIST` (a `LIST` reply is delivered whole) and `ELIST=M`
- **Host cloaking**: users' real addresses are hidden behind a stable HMAC cloak
  (revealed to operators via `WHOIS`)
- **TLS** terminated in-process, sharing the cloak and limit paths with plaintext
- **Operator tooling**: `KILL`, persistent `KLINE`/`UNKLINE` address bans
- **Admission control**: per-source connection caps and aggregate flood limits

Runtime dependencies are `tokio` and `rustls` (via `tokio-rustls`, built on the
`ring` provider so the image needs no C toolchain). Everything else — SHA-256,
HMAC, PBKDF2, base64, and the PEM parsing that loads the certificate — is
implemented in-tree and checked against published test vectors.

TLS was previously terminated by a ghostunnel sidecar. That sidecar could not
forward the original client address, so every TLS user reached the daemon as
`127.0.0.1` and shared one cloak. Terminating in-process is what lets a TLS
client's real address reach the cloak, ban and limit paths.

## Quick start

```bash
IRC_PORT=6667 cargo run --release
# then point a client at localhost:6667
```

## Configuration

All configuration is via environment variables.

| Env var             | Default          | Meaning                                       |
|---------------------|------------------|-----------------------------------------------|
| `IRC_PORT`          | `6697`           | TCP port the server listens on                |
| `IRC_SERVER_NAME`   | `chonkline`      | Server name reported in numerics              |
| `IRC_OPER_USER`     | `oper`           | `OPER` username                               |
| `IRC_OPER_PASS`     | `secret`         | `OPER` password                               |
| `IRC_ACCOUNTS_PATH` | *(unset)*        | Account store file; unset = in-memory only    |
| `IRC_CHANNELS_PATH` | *(unset)*        | Channel registry file; unset = in-memory only |
| `IRC_CLOAK_SECRET`  | *(built-in)*     | HMAC key for host cloaks (set in production)   |
| `IRC_CLOAK_SUFFIX`  | `chonkbase.net`  | Domain suffix appended to cloaked hosts       |
| `IRC_BANS_PATH`     | *(unset)*        | K-line store file; unset = in-memory only     |
| `IRC_LOG_LEVEL`     | `info`           | `error` / `warn` / `info` / `debug` / `silent` |

### TLS

| Env var         | Default          | Meaning                                  |
|-----------------|------------------|------------------------------------------|
| `IRC_TLS_PORT`  | *(off)*          | TLS listener port; unset or `0` disables |
| `IRC_TLS_CERT`  | `/certs/tls.crt` | PEM certificate (chain supported)        |
| `IRC_TLS_KEY`   | `/certs/tls.key` | PEM private key (PKCS#8, PKCS#1 or SEC1) |

A TLS bind or certificate failure is logged and leaves the plaintext port
running rather than taking the server down.

Where a proxy is also in front, the PROXY header arrives on the raw stream
*ahead of* the TLS handshake, so the real client address is known before
anything is decrypted and TLS clients are cloaked and limited exactly like
plaintext ones.

### Behind a proxy

| Env var                      | Default           | Meaning                                        |
|------------------------------|-------------------|------------------------------------------------|
| `IRC_PROXY_PROTOCOL`         | *(off)*           | `1`/`required`, `optional`, or off              |
| `IRC_TLS_PROXY_PROTOCOL`     | *(as above)*      | Same, for the TLS listener only                |
| `IRC_PROXY_PROTOCOL_EXEMPT`  | *(none)*          | Peers admitted without a header                |
| `IRC_PROXY_TRUSTED`          | *(any)*           | Peers whose PROXY header is trusted            |

A proxy terminates the client's connection and opens its own, so `peer_addr()`
reports the proxy rather than the client. Behind a single ingress that address
is identical for every client — which collapses cloaks, bans and per-source
limits onto one value for the entire network. With `IRC_PROXY_PROTOCOL=1` the
original address is read from the header the proxy prepends.

In `required` mode it **fails closed**: a missing or malformed header drops the
connection. Falling back would silently restore the shared-address behaviour,
which is precisely the failure this guards against. A peer that connects and
closes without sending anything — a TCP health probe — is closed silently rather
than counted as a rejection.

`optional` mode is for cutover only: a header is used when present and the peer
address is used when absent, with an aggregated `proxy.absent` counter making
the gap visible. Until the proxy prepends its own header a client can forge one
and choose its apparent address, so move to `required` as soon as the counter
reaches zero. Once the proxy sends the header first, a forged line arrives after
it and is parsed harmlessly as an IRC command.

The listener is **peeked** before any header is read, so a stream that turns out
to be a TLS ClientHello is never partially consumed. That is what allows the TLS
port to use the same code path, and each port to be cut over independently via
`IRC_TLS_PROXY_PROTOCOL`.

### Configuring the proxy

ingress-nginx does not forward client addresses by default. In its
`tcp-services` ConfigMap the entry needs a **second** `:PROXY`:

```
"6667": chonkline/chonkline:6667:PROXY:PROXY
```

The first controls decoding the inbound connection; the second controls sending
the header upstream. With only one, nginx decodes but does not forward, and
every client reaches the daemon wearing the ingress pod's address.

`IRC_PROXY_TRUSTED` matters more than it looks. A PROXY header is only as
trustworthy as the path it arrived on: anything that can open a connection to
the daemon can write its own and name any source it likes, which defeats
per-source limits and bans. On Kubernetes a `type: LoadBalancer` Service also
opens a NodePort on every node's public address, so the balancer can be bypassed
by anyone who scans for it. Set this to the address the balancer reaches the pod
from -- it appears as `peer=` on `conn.open` at debug level -- **and** restrict
the NodePort range at the firewall. Neither control is sufficient alone.

Rate-limit exemptions (`IRC_LIMIT_EXEMPT`) are matched against the TCP peer,
never against the address a header claims, for the same reason.

The exemption list is empty by default. It exists for deployments that still
front the daemon with a local terminator unable to emit a header; such peers
necessarily share one cloak, since their real address never arrives.

### Accounts, SASL PLAIN, and SASL EXTERNAL

A NickServ account has a password and up to eight certificate fingerprints.
Both stay valid together. EXTERNAL does not create a second account, and it
does not read the certificate subject. The account is whichever one enrolled
the fingerprint.

The fingerprint is the SHA-256 of the leaf certificate's DER, written as
lowercase hex. The TLS handshake proves the client holds the matching private
key. A fingerprint typed into a command, a certificate subject, or a PROXY
header is not that proof. `CERT ADD` enrolls only the certificate on the
current TLS connection.

Client certificates are usually self-signed. The IRC TLS listener asks for one
and accepts it without a CA and without checking its expiry. Connections that
present no certificate still complete, and they can use PLAIN. The HTTPS
listener does not ask for a client certificate at all.

`CAP LS 302` advertises `sasl=EXTERNAL,PLAIN` only when this connection
presented a certificate. Otherwise it advertises `sasl=PLAIN`. A failed
EXTERNAL attempt can be followed by PLAIN before `CAP END`.

**Where the certificate has to arrive.** The production listener is
`irc.chonkbase.net` port `6697`. The Linode NodeBalancer forwards that port as
TCP with a PROXY v1 header (`deploy/k8s/loadbalancer.yaml`). The pod reads the
header, then terminates TLS itself (`IRC_TLS_PORT`, `src/ops.rs`). PROXY v1
carries the client address, not a certificate. Clients must use a path that
does not terminate TLS in front of chonkline. The shared ingress, if it
terminates TLS, cannot do EXTERNAL unless some later design forwards a
certificate identity the daemon is willing to trust. Do not treat that header
as one.

**PLAIN, then enroll EXTERNAL.** Connect with the new client certificate,
identify with the password, enroll, reconnect, and check EXTERNAL. The password
remains the recovery credential.

```
/server add chonkbase irc.chonkbase.net/6697 -tls
/set irc.server.chonkbase.nicks "<nick>"
/set irc.server.chonkbase.tls_cert "<client.pem>"
/set irc.server.chonkbase.sasl_mechanism plain
/set irc.server.chonkbase.sasl_username <account>
/set irc.server.chonkbase.sasl_password <password>
/connect chonkbase
/msg NickServ CERT ADD
/set irc.server.chonkbase.sasl_mechanism external
/reconnect
```

`<client.pem>` holds both the private key and the certificate (WeeChat reads
them from `tls_cert`). `<nick>`, `<account>`, and `<password>` are the user's.
The server name in the commands is the WeeChat server, not the account.

**Rotate a certificate.** Enroll the new fingerprint while the old one still
works, connect once with EXTERNAL using the new certificate, then delete the
old fingerprint. Reissuing a certificate changes the fingerprint even when the
key stays the same. Replacing the key requires a new certificate. At least two
fingerprints fit on one account so the overlap is possible.

```
/msg NickServ CERT LIST
/msg NickServ CERT ADD
/msg NickServ CERT DEL <old-fingerprint>
```

`CERT LIST` prints the stored hex, which is what `CERT DEL` takes. Colons and
any letter case are accepted on input.

**Back to PLAIN.** The password is still there. Identify with it, or set SASL
back to `plain`. Deleting a certificate does not change the password hash.
`SET PASSWORD <current> <new>` does not change certificate bindings. `GHOST`
still takes the password when the caller is not identified; a certificate is
not a substitute for that.

**What a change does to a session that is already in.** Nothing. Password
rotation and certificate removal both apply to the next login. A session that
has already identified stays identified until it quits or `LOGOUT`s. Removing
the fingerprint used for this session does not disconnect it.

**Losing both.** There is no in-band command that replaces a password the user
cannot supply, and no way to enroll a certificate without an existing login.
That is deliberate: either one would be an account takeover for anyone who can
reach the server. Recovery is an operator with access to the account file
(`IRC_ACCOUNTS_PATH`, `/var/lib/chonkline/accounts.db` in the cluster). Stop
the process so it cannot write the old memory back over the file, replace that
account's password hash, and start it again. Leave the fingerprint field in
place unless those certificates are also lost. An account is not offered a
password-disable option; turning the password off with no remaining certificate
would make the account unreachable, and `SET PASSWORD` and the `GHOST`
fallback both require a password today.

### Anti-bot challenge

| Env var                     | Default   | Meaning                                  |
|-----------------------------|-----------|------------------------------------------|
| `CHONKLINE_REG_CHALLENGE`   | *(off)*   | Require a PONG before registration completes |
| `CHONKLINE_REG_TIMEOUT_SECS`| `60`      | Drop connections that never register     |

With the challenge on, the server sends a `PING` once `NICK` and `USER` are both
present and completes registration only after any `PONG`. Every mainstream
client answers automatically, so real users never see it, while a scripted flood
that blasts `NICK`/`USER`/`JOIN` without reading the socket never registers.

It is **opt-in** on purpose. A client that does not answer cannot connect at
all, and that failure mode is an outage for whoever runs it — enable it after
confirming the clients your users actually run. This repo's own scripted e2e
clients do not answer, which illustrates both the value and the risk.

Any `PONG` is accepted rather than a matching token: matching adds nothing
against a bot that reads the socket, and only risks breaking a client that
echoes the token oddly.

### Server linking

chonkline speaks the InspIRCd spanning-tree protocol and can join an InspIRCd
network as a peer. Off unless `IRC_SID` is set.

| Env var             | Default   | Meaning                                       |
|---------------------|-----------|-----------------------------------------------|
| `IRC_SID`           | *(off)*   | This server's id, `[0-9][A-Z0-9]{2}`          |
| `IRC_LINK_PORT`     | *(none)*  | Listen for inbound links                      |
| `IRC_LINK_PEERS`    | *(none)*  | `host:port[:fingerprint]`, comma separated    |
| `IRC_LINK_PASSWORD` | *(empty)* | Shared with the peer's `<link>` block         |
| `IRC_LINK_TLS`      | *(off)*   | TLS for links (use it off loopback)           |

Protocol 1205 is offered, which InspIRCd v3 and v4 both accept, so one build
links to either.

**Transport.** Set `IRC_LINK_TLS=1` for anything that is not loopback: a link
otherwise carries every user's traffic and the link password in the clear. Peers
are authenticated by pinning a SHA-256 certificate fingerprint rather than by a
CA chain, because certificates on server links are routinely self-signed and
there is no authority to appeal to. An outbound peer given no pin is refused --
an unauthenticated TLS link is encrypted against an observer and wide open to
whoever answers that address. The server logs its own fingerprint as
`link.fingerprint` at startup; that is what the other operator needs.

**Modes.** chonkline never advertises `CAPAB CHANMODES`, `USERMODES` or
`EXTBANS`. InspIRCd compares those only when a peer sends them, so staying quiet
is what lets a smaller mode set link at all; sending a set that differs is
refused. Modes it does not implement still arrive, and are stored per channel
and reported rather than dropped, because dropping one the peer believes is set
is a silent divergence.

**Interoperability testing** lives in `tests/interop/` and runs against a real
InspIRCd: handshake and refusal probes, a twenty-one check functional suite, a
three-server multi-hop topology, TLS links with a pinned fingerprint, and a load
and stress harness.

### Limits

| Env var                    | Default | Meaning                                          |
|----------------------------|---------|--------------------------------------------------|
| `IRC_MAX_CLONES_PER_IP`    | `5`     | Concurrent connections from one address          |
| `IRC_MAX_CLIENTS`          | `1024`  | Concurrent connections server-wide               |
| `IRC_MAX_CONNECTS_PER_MIN` | `30`    | New connections per minute from one address      |
| `IRC_MAX_MESSAGES_PER_10S` | `60`    | Aggregate messages per 10s from one address      |
| `IRC_MAX_FLOOD_VIOLATIONS` | `10`    | Budget violations tolerated before disconnect    |
| `IRC_LIMIT_EXEMPT`         | *(none)*| Comma-separated address patterns exempt from limits |

Per-source bounds key on the **network block**, not the exact address: an IPv6
/64 is the smallest block routinely assigned to one customer, so keying on the
full address would let one customer mint effectively unlimited distinct sources
and defeat every per-source bound. IPv4 keys on the whole address. Cloaks and
logs always use the exact address, so attribution is unaffected.

`PRIVMSG`/`NOTICE` accept at most 4 distinct targets per line (`TARGMAX`), and
duplicate targets collapse to one delivery. Both flood tiers charge per input
line, so an uncapped target list was a large amplifier that cost the sender a
single unit of budget.

`IRC_LIMIT_EXEMPT` accepts glob patterns (`10.2.*`), because the addresses that
need exempting are infrastructure — load-balancer health checks and cluster
gateways — whose exact values change when those resources are recreated.
Exempt sources are also excluded from `IRC_MAX_CLIENTS`, so a health-check
cadence can never consume the global ceiling.

The per-source bounds default to **off** unless `IRC_PROXY_PROTOCOL` is enabled.
A per-source cap applied to a shared address is not a per-user limit, it is a
global one — enabling it in that state would be an outage rather than a
protection. The server-wide ceiling always applies.

Flood control runs in two tiers: a per-connection burst window, then the
aggregate per-source budget above. Without the second tier, spreading traffic
across N connections multiplies the allowance by N. Persistent offenders are
disconnected with `ERROR :Excess flood` rather than throttled indefinitely.

## Operator commands

| Command                                | Effect                                        |
|----------------------------------------|-----------------------------------------------|
| `KILL <nick> [:reason]`                | Disconnect a user                             |
| `KLINE <mask> [secs] [:reason]`        | Persistent address ban; `0`/omitted = forever |
| `KILL <pattern> [:reason]`             | Mass kill by nick glob; never matches operators |
| `UNKLINE <mask>`                       | Remove a ban by exact mask                    |
| `STATS K`                              | List active K-lines                           |
| `STATS I`                              | Live admission limits                         |
| `STATS L`                              | Busiest sources by connection count           |
| `MODE <nick> +s`                       | Receive server notices                        |

K-line masks are globs (`*`, `?`) matched against the client's **real address**,
never the cloak — a cloak match would ban every user at once behind a proxy that
does not forward client addresses. Bans persist to `IRC_BANS_PATH` and survive a
restart. Setting one also kills anyone already connected from a matching address.

Operators are exempt from both flood tiers: incident response is bursty by
nature, and being throttled to roughly three commands a second with no feedback
made the response tools unusable at the moment they were needed.

**Server notices** (`+s`) report operator actions, failed `OPER` attempts, and
thresholded totals from each tick — connection refusals, flood disconnects,
registration bursts, ban hits. They are aggregated rather than per-event, for
the same reason the log is: a flood must not become a notice flood.

Channel mode `+R` restricts a channel to clients authenticated to a services
account. It is the one admission control that does not depend on trustworthy
addresses, which makes it the usable lever when cloaking or proxy handling is
misconfigured.

## Test

```bash
cargo test
```

The suite runs scripted end-to-end scenarios over real TCP sockets against the
server, plus unit tests.

## Container

```bash
docker build -t chonkline .
docker run -p 6667:6667 -e IRC_PORT=6667 chonkline
```

## Deploy (Kubernetes)

The `deploy/k8s` overlay swaps only the workload and service; the surrounding
namespace, ingress, TLS certificate and config are reused as-is.

1. Push to `main` — the **Image** workflow builds `ghcr.io/iconidentify/chonkline`.
2. Run the **Deploy** workflow (manual) with the image tag to ship.

Plaintext IRC is served on `6667` and TLS on `6697`, both by the daemon itself,
using the cert-manager certificate mounted at `/certs`.

## License

GPL-3.0-or-later.
