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

### 3.2 The return address is a name, not a destination

The first reading of this was wrong, and the correction is the most useful
result here.

CCB's inbound rendezvous tells the target to reverse-connect to `MyAddress`,
and in streaming mode that is the broker's own address. It looks as though a
restricted node therefore needs the broker to mint an address *it* can reach --
which would mean the helper announcing its address up the carrier, and the
broker holding one per pipe.

It does not. **The broker already knows, from the CCBID, which carrier a target
is behind, and the EP already knows the one address it can reach, because it
registered through it.** "Reverse-connect to MyAddress" only has to mean "come
back to your broker". The address is a name for the peer, not a destination to
resolve, and nothing has to agree on its value.

`TestSpliceHelperExternalReturnAddress` proves it: the broker mints its own
external address, which the EP cannot route to, the EP dials through its
carrier instead, and the rendezvous completes. cedar already has the hook --
`ListenerConfig.Dial` receives the address and is free to ignore it, which is
what its own doc comment describes for a carrier-dialing EP:

> It is used for BOTH the persistent registration dial and the reverse-connect
> dials the broker asks for (in streaming mode those target the broker's own
> address, i.e. the same carrier peer).

So `Config.ReverseConnectAddress` is scaffolding to delete, and §4 below is
moot, **provided the EP goes back through its carrier**.

#### What this costs instead

The requirement moves to the EP rather than vanishing. An EP that resolves
`MyAddress` literally -- a plain TCP dial, no carrier hook -- still dials an
address it cannot reach.

That matters for exactly one question: whether an **unmodified C++ HTCondor EP**
is a target for this model. Today's inside-CCB model works with one, but only
because the address it is handed happens to be locally reachable -- the inside
broker is next door. Under the carrier convention, a C++ EP would dial the
broker's external address and fail.

- EPs that dial through a carrier (any golang EP, and the staged case): the
  external address is enough. Nothing to configure.
- Unmodified C++ EPs: still need a reachable address. It need not be announced
  up the pipe, though -- the operator configuring the carrier can state it once,
  which is configuration rather than protocol.

Settle that question first; it decides whether any of §4 survives.

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

## 4. Determining the internal address (only if §3.2's EP question says yes)

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

Proven: the data path (§2), and that an external return address suffices for a
carrier-dialing EP (§3.2).
Unresolved: how a client learns to stream (§3.3), and whether unmodified C++ EPs
are a target -- which decides whether any address needs configuring at all.
Not started: everything else.
