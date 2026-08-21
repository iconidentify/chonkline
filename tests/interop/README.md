# InspIRCd interoperability harness

Drives a real InspIRCd server over the spanning-tree protocol, by hand, to
establish what it actually accepts. Written before implementing linking, because
the published documentation does not answer the question that decides the
approach: what happens when the two sides' modes do not match.

Verified against **InspIRCd 4.11.0** (`brew install inspircd`).

## Running

```
brew install inspircd
cd tests/interop
inspircd --config conf/inspircd.conf --nofork --nolog &
python3 handshake.py 1205     # minimal CAPAB -> does it link?
python3 traffic.py            # end-to-end, both directions
python3 refusals.py           # negative controls
```

## What it establishes

`handshake.py` sends the **minimal** CAPAB: no `CHANMODES`, no `USERMODES`, no
`EXTBANS`, no `CASEMAPPING`. Every mode comparison in InspIRCd's `capab.cpp` is
guarded by `if (!capab->ChanModes.empty())`, so a peer that stays quiet about
modes is never checked against them. This is how Anope and Atheme link without
implementing InspIRCd's mode set, and there is no services-specific relaxation
in the negotiation path — they simply omit the sub-commands.

`traffic.py` proves the link is functional rather than merely established:
InspIRCd's `WHOIS` resolves a user we introduced over the link, a local client's
`JOIN` reaches us as `FJOIN`, and messages cross in both directions.

`refusals.py` is the negative control. It confirms the checks we avoid are real,
so the omissions above are load-bearing rather than coincidental:

| Case | Result |
|---|---|
| Omit all mode capabs | **links** |
| Send non-matching `CHANMODES` | refused |
| Send non-matching `USERMODES` | refused |
| `CASEMAPPING` differing from theirs | refused |
| Wrong link password | refused |
| Protocol 1206 | links |
| Protocol 1204 | refused (too old) |

Protocol 1205 and 1206 both link to a 4.11 server (`PROTO_OLDEST = 1205`,
`PROTO_NEWEST = 1206`), so a single implementation speaking 1205 reaches both
InspIRCd v3 and v4.

## Live linking

`live_link.py` and `live_link_full.py` run a real chonkline against a real
InspIRCd and exercise the whole surface: channel traffic both ways, private
messages both ways, NAMES and WHOIS resolving remote users, nick change, part,
rejoin, quit, and a netsplit. Sixteen checks.

```
IRC_SID=2CH IRC_SERVER_NAME=chonk.test IRC_LINK_PASSWORD=linkpass \
  IRC_LINK_PEERS=127.0.0.1:7001 target/release/irc-server
python3 live_link_full.py
```

Two things these caught that no unit test would have:

* **FJOIN versus IJOIN.** FJOIN introduces channel state and is what a burst
  uses; a single user joining a channel the network already knows is an
  incremental join and must be IJOIN. A peer merges a post-burst FJOIN silently
  rather than announcing it, so the join simply never appeared on the other
  side. IJOIN also takes `<chan> <membid>` -- sending only the channel fails the
  peer's arity check and is dropped without a word either way.

* **The join relay was wired into only one of the two join paths**, so a user
  joining a channel that already existed was never announced. A peer routes
  channel traffic only to servers it believes hold a member, so the channel
  worked in exactly one direction.

Worth knowing when reading a failure here: chonkline's own tier-1 flood control
drops the seventh message in a two-second window silently. A test that fires
commands back to back trips it and the symptom -- a join that never reaches the
peer -- looks identical to a protocol bug. The harness paces itself for that
reason.

## Load and stress

`stress.py` escalates: local load, connect/disconnect churn, the same load
crossing the link, then a split under load. It reports measurements rather than
pass/fail, because the interesting failures here are partial.

```
python3 stress.py --clients 80 --msgs 5 --link-clients 20
```

Last run, 80 local clients and 20 each side of the link:

| | |
|---|---|
| local delivery | 31,600 of 31,600 (100%) |
| cross-link delivery | 2,000 of 2,000 (100%) |
| send rate sustained | ~46,000 messages/sec |
| memory | 3.3 MB -> 9.3 MB peak |
| churn | 240 connect/disconnect cycles, 0 failures, +0.6 MB |
| after peer killed | survives, still usable |
| server error lines | 0 |

Two traps this harness fell into, both worth knowing before trusting a number
from it:

* **Verify preconditions before measuring.** An early run reported 0% cross-link
  delivery, which read as a serious linking bug. The clients had never
  registered. A stress test that does not check its own setup produces a
  confident zero.
* **Count what IRC actually sends.** A channel message is not echoed back to its
  sender, so expecting every member to receive it makes a perfect run look like
  a 1.7% loss.

## Environment notes

Both cost real time, and neither is a server fault:

* **macOS Control Center listens on port 7000** (AirPlay Receiver). The InspIRCd
  client port is 7010 here for that reason.
* **Connection limits belong on `<connect>`, not `<class>`.** `<class>` is for
  OPER classes. With the limits in the wrong block InspIRCd silently fell back to
  its small defaults and reset every client after the first, which looked
  exactly like a concurrency bug in the harness.

## The obligation this creates

Skipping mode validation does not make the modes go away. InspIRCd still sends
`FJOIN #chan <ts> +nt` and `FMODE` carrying modes chonkline does not implement.
Those must be stored and echoed back verbatim: dropping a mode the other side
believes is set is a silent desync, and desync is the characteristic failure of
server linking.
