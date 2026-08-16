# Chonkline

A standalone IRC server written in Rust (async, `tokio`), implementing the client
protocol of RFC 1459 / RFC 2812 as it is practiced today. It is dependency-light:
the only runtime dependency is `tokio`.

## Features

- Connection registration (`PASS` / `NICK` / `USER`), MOTD, LUSERS
- Channels: `JOIN` / `PART` / `TOPIC` / `NAMES` / `LIST` / `INVITE` / `KICK`
- Channel and user `MODE` (invite-only, keys, limits, bans, ops, …)
- Messaging: `PRIVMSG` / `NOTICE`
- Queries: `WHO` / `WHOIS` / `WHOWAS` / `ISON` / `USERHOST`
- Server info: `VERSION` / `STATS` / `TIME` / `ADMIN` / `INFO` / `MOTD`
- `AWAY`, `OPER`, `WALLOPS`, `PING` / `PONG` keepalive

## Quick start

```bash
IRC_PORT=6667 cargo run --release
# then point a client at localhost:6667
```

## Configuration

All configuration is via environment variables.

| Env var           | Default     | Meaning                           |
|-------------------|-------------|-----------------------------------|
| `IRC_PORT`        | `6697`      | TCP port the server listens on    |
| `IRC_SERVER_NAME` | `chonkline` | Server name reported in numerics  |
| `IRC_OPER_USER`   | `oper`      | `OPER` username                   |
| `IRC_OPER_PASS`   | `secret`    | `OPER` password                   |

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

Plaintext IRC is served on `6667`. TLS on `6697` is terminated by a sidecar using
the cluster certificate and forwarded to the daemon.

## License

GPL-3.0-or-later.
