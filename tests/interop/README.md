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

## The obligation this creates

Skipping mode validation does not make the modes go away. InspIRCd still sends
`FJOIN #chan <ts> +nt` and `FMODE` carrying modes chonkline does not implement.
Those must be stored and echoed back verbatim: dropping a mode the other side
believes is set is a silent desync, and desync is the characteristic failure of
server linking.
