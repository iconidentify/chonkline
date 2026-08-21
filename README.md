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
- **Accounts**: `NickServ` `REGISTER` / `IDENTIFY`, PBKDF2-hashed passwords
  persisted to disk
- **Channels**: `ChanServ` `REGISTER` / `INFO` / `DROP` — founders are
  auto-opped and registered channels keep their topic across restarts
- **SASL** `PLAIN` authentication at connection time
- **IRCv3 capabilities**: `sasl`, `server-time`, `away-notify`, `extended-join`,
  `account-notify`, `multi-prefix` (proper `CAP LS 302` negotiation)
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

The exemption list is empty by default. It exists for deployments that still
front the daemon with a local terminator unable to emit a header; such peers
necessarily share one cloak, since their real address never arrives.

### Limits

| Env var                    | Default | Meaning                                          |
|----------------------------|---------|--------------------------------------------------|
| `IRC_MAX_CLONES_PER_IP`    | `5`     | Concurrent connections from one address          |
| `IRC_MAX_CLIENTS`          | `1024`  | Concurrent connections server-wide               |
| `IRC_MAX_CONNECTS_PER_MIN` | `30`    | New connections per minute from one address      |
| `IRC_MAX_MESSAGES_PER_10S` | `60`    | Aggregate messages per 10s from one address      |
| `IRC_MAX_FLOOD_VIOLATIONS` | `10`    | Budget violations tolerated before disconnect    |
| `IRC_LIMIT_EXEMPT`         | *(none)*| Comma-separated address patterns exempt from limits |

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
| `UNKLINE <mask>`                       | Remove a ban by exact mask                    |

K-line masks are globs (`*`, `?`) matched against the client's **real address**,
never the cloak — a cloak match would ban every user at once behind a proxy that
does not forward client addresses. Bans persist to `IRC_BANS_PATH` and survive a
restart. Setting one also kills anyone already connected from a matching address.

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
