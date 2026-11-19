# The splice helper: CCB connectivity inside a cluster

A carrier's far end does not have to be a CCB broker. This note describes the
alternative — a **splice helper**, a byte relay that holds no keys and parses
nothing — what an experiment proved about it, and the three constraints that
decide whether it can ship.

It is a companion to `TRANSPORTS.md` (the carriers themselves) and to the C++
tree's `CCB_TUNNELING_DESIGN.md` (the inside/outside broker pair). It does not
replace either: the inside-CCB model remains the one the C++ side implements.

## 1. Two models

Today's tunneling puts a **second broker** on the restricted side. It
authenticates local daemons, allocates its own CCBIDs, holds each target's
registration stream, and registers upstream — so it needs HTCondor
configuration, credentials, and an authorization policy on the far host.

The splice helper puts an **address** there instead:

```
   inside-CCB model              splice-helper model

   EP ──CEDAR──▶ inside CCB      EP ──────CEDAR (end to end)──────▶ outside CCB
                     │                      ╲                          ▲
                  CEDAR                      ╲ bytes                   │
                     ▼                        ▼                        │
                outside CCB              helper ───────── carrier ─────┘
                                      (accept, copy, copy)
```

The helper accepts TCP on the restricted side and copies each connection onto a
stream of the carrier. It terminates nothing. Every daemon that reaches it is
running one end-to-end CEDAR session with the outside broker, which is where
authentication and authorization happen.

What that buys:

| | inside CCB | splice helper |
|---|---|---|
| staged payload | 11.7 MB | ~2 MB |
| credentials on the far host | yes | **none** |
| HTCondor config on the far host | required | none |
| authorization | far host | outside broker |

The second row is the point. A helper that holds no keys and authorizes nothing
is a pipe if it is compromised, not a broker identity — which matters when the
binary was staged onto a host you do not administer.

## 2. What was proved

`TestSpliceHelperInboundRendezvous` stands up an outside broker, a helper that
is `net.Listen` plus two `io.Copy`s, and an EP walled off by `DialControl` from
every destination but the helper. A client then reaches that EP and dispatches
an end-to-end CEDAR `DC_NOP` through it.

It passes. The data path is sound: **an inbound rendezvous completes with a
byte relay at the far end.**

The walling matters. Without it the EP can reach the broker directly on
loopback and the test passes for the wrong reason, proving nothing.

## 3. The three constraints

### 3.1 Registration is already transparent

The EP cannot tell a spliced broker from a local one, and does not need to. It
dials a TCP address and speaks CEDAR to whatever answers. No change is required
anywhere for this half.

### 3.2 The return address must be minted on the far side

This is the constraint that decides the model.

CCB's inbound rendezvous works by telling the target to reverse-connect to
`MyAddress`. In streaming mode that is **the broker's own address**
(`proxy.go`, `proxyAddrSinful`), and cedar's registrant side says so outright:

> The reverse-connect target is usually the requester's own (directly dialable)
> address, but in streaming/proxy mode it is the broker's own address so the
> broker can splice us to the requester.

A restricted node can dial exactly one address: the helper on its own side of
the carrier. So the broker has to mint an address **in a space it does not
own**, and the helper is the only party that knows what that space looks like.

The helper cannot patch the address in flight. That control ad rides inside the
EP↔broker CEDAR session, which is authenticated and usually encrypted. A byte
relay cannot rewrite what it is designed to be unable to read — and should not
be able to.

Two consequences:

- The helper **announces its reachable address up the carrier** when the pipe
  comes up. One message, no CEDAR, no ClassAds. This is the only protocol the
  helper needs, and it is what keeps it a byte relay everywhere else.
- A target reached this way is **always proxied**. Standard mode would send it
  to the requester, which is further away than the broker it already cannot
  reach, so the standard path can never succeed for such a target.

### 3.3 The requester picks the mode, and the broker cannot upgrade it

`dialOne` chooses streaming only when the contact is CCB-routed (nested) or the
caller supplied `ProxyReturnAddr`. A direct client holding a **flat** contact
takes `dialStandard`, opens its own listener, and waits for a connection the
walled EP can never make. The broker's decision to proxy arrives too late: the
client is no longer reading the broker socket as a data path.

So a flat contact cannot express "this target needs proxying", and this is the
open question, not a detail. The honest reading is that **nested contacts are
not an artifact of having two brokers — they are the wire signal that tells a
client to stream.**

That suggests the resolution is to keep the nested contact and drop only the
second broker: present `<outside>#P#T` where `P` identifies the carrier and `T`
the target, with the outside broker owning and resolving both. A client needs no
change, because it already recurses on a nested contact; the outside broker
collapses the hop internally instead of forwarding it to a peer. The helper
still registers nothing — the broker allocates `P` locally when the pipe comes
up.

This is the part to design next, and it has to be settled before anything else
is built. `ProxyReturnAddr` is forced in the test purely to isolate the data
path from this question.

## 4. Determining the internal address

Two separate things, easily conflated:

- **what the helper binds** — `0.0.0.0:9618`, or loopback when the only clients
  are on the same host;
- **what is minted into `MyAddress`** — what the EP will actually dial.

Only the second is protocol-visible. Autodetection alone is not safe for it: the
host you reached over the carrier is often not the name the worker network knows
it by, and a login node has several interfaces with no local way to tell which
one the cluster uses. Precedence:

```
explicit configuration  >  helper autodetect  >  loopback
```

with the outside broker able to override, since whoever configured it often
knows the topology better than the node does. The same-host case needs no
configuration and falls through to loopback.

## 5. What this does not solve

- **Authorization moves off the execute host.** The outbound allowlist (the
  SSRF guard) and the registration policy are enforced at the outside broker.
  That is arguably the better place, but it is a change in where the boundary
  sits and should be stated plainly rather than discovered.
- **It is not the "inside CCB" role** the C++ design specifies, so the Stage C
  interop story does not cover it. It is a second model that lives alongside.
- **One broker, many helpers.** `Config.ReverseConnectAddress` is per server
  today, which is the experiment's scaffolding. Production needs it per carrier,
  carried on the target from the pipe its registration arrived on.

## 6. Status

Proven: the data path, and the return-address constraint.
Unresolved: how a client learns to stream (§3.3), and per-carrier address state.
Not started: everything else.
