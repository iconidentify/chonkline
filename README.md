# Chonkline

A standalone IRC server written in **Rust** (async, `tokio`), implementing the client
protocol of RFC 1459 / RFC 2812 as practiced today. This is the Rust rewrite that
replaces the original Go implementation.

Production target: `irc.chonkbase.net` — classic IRC on **6667** (non-TLS for the
initial launch).

> The previous Go version's WebSocket web client and HTTP interface have been
> retired. Chonkline is now a focused, dependency-light IRC daemon — the only
> dependency is `tokio`.

## Features

- Connection registration (`PASS` / `NICK` / `USER`), MOTD, LUSERS
- Channels: `JOIN` / `PART` / `TOPIC` / `NAMES` / `LIST` / `INVITE` / `KICK`
- Channel and user `MODE` (invite-only, keys, limits, bans, ops, …)
- Messaging: `PRIVMSG` / `NOTICE`
- Queries: `WHO` / `WHOIS` / `WHOWAS` / `ISON` / `USERHOST`
- Server info: `VERSION` / `STATS` / `TIME` / `ADMIN` / `INFO` / `MOTD`
- `AWAY`, `OPER`, `WALLOPS`, `PING` / `PONG` keepalive
- ~3,300 lines of Rust, 9 unit tests + 6 end-to-end tests

## Quick start

```bash
IRC_PORT=6667 cargo run --release
# then point a client at localhost:6667
```

| Env var    | Default | Meaning                        |
|------------|---------|--------------------------------|
| `IRC_PORT` | `6697`  | TCP port the server listens on |

## Test

```bash
cargo test --release   # 9 unit + 6 end-to-end
```

## Container

```bash
docker build -t chonkline .
docker run -p 6667:6667 chonkline
```

## Deploy (Linode LKE, namespace `chonkline`)

The `deploy/k8s` overlay swaps only the workload + service; the existing namespace,
ingress, TLS certificate, config and PVC are reused as-is.

1. Push to `main` → the **Image** workflow builds `ghcr.io/iconidentify/chonkline`.
2. Run the **Deploy** workflow (manual) with the tag to ship.

## How this was built

Chonkline was written end-to-end by a **local large language model running on home
hardware** — no cloud inference, no hosted API. The entire server, including its
test suite, was produced by an agentic coding loop driving a self-hosted model.

**Model**

- [`Blackfrost-AI/Qwen3.8-27B-ABLITERATED`](https://huggingface.co/Blackfrost-AI/Qwen3.8-27B-ABLITERATED-GGUF)
  — Qwen 3.8-27B (dense, hybrid gated-DeltaNet / attention architecture),
  abliterated, in **Q8_0** GGUF (28.6 GB) plus the F16 multimodal projector.
- Pulled and brought online on **2026-08-14**, the day the base model released.

**Runtime**

- Inference engine: **llama.cpp** (`llama-server`).
- Hardware: **2 × NVIDIA RTX 3090** (48 GB VRAM total), layer-split across both GPUs.
- 262,144-token context, `q8_0` KV cache, ~14 tokens/sec generation.
- Agent harness: **opencode**.

**Effort (measured from the local inference proxy logs)**

- Written over **≈ 9 hours of active model inference** (~13 h wall-clock, evening of
  2026-08-14 into the morning of 2026-08-15, including an overnight pause).
- **~801 model requests** across 8 agentic sessions.
- **~486,000 tokens generated**; ~150M tokens of context processed.
- Result: 3,325 lines of Rust, compiling clean, 15/15 tests passing.

No hosted models were used at any point. Everything here came off two consumer
graphics cards in a home lab.

## License

GPL-3.0-or-later.
