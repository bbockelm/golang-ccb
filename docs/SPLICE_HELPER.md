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

#### The strong form: no address is needed by anyone

The first correction still assumed a carrier-aware EP. It does not need one.

For an incoming reversal the first hop out is **always the target's own
broker** -- the one it registered through, whose address is already in its
configuration. In proxy mode the broker mints its own address
(`proxyAddrSinful`), so `MyAddress` is by construction always "me". It is pure
redundancy: the target can ignore it and reconnect to its configured broker.

Verified against a patched cedar with a **plain TCP EP** -- no carrier hook, no
dialer that knows anything about the helper -- walled off from every
destination but the helper, with the broker minting its own unreachable
external address. The rendezvous completes and the EP never resolves an
address at all.

The production change is six lines across two repos:

```go
// golang-ccb, proxy.go: mark the request
fwd := ccb.NewAd(map[string]any{
    ccb.AttrCommand: ccb.CommandRequest,
    "CCBProxyMode":  true,
    ...
})

// cedar, ccb/listener.go handleRequest: a proxy request goes back to my broker
if b, ok := AdBool(ad, "CCBProxyMode"); ok && b {
    myAddr = r.addr   // the address this registrant registered through
}
```

It is held out of this branch because the cedar half is not landed, so the
committed tests use `ListenerConfig.Dial` to stand in for it.

This also means `Config.ReverseConnectAddress` is dead, the announcement
protocol is unnecessary, §4 below is moot, and the question of whether an
unmodified C++ EP is a target becomes much narrower: proxy mode is a golang
extension that no C++ EP implements today, so that side needs a change either
way -- and the change to make is "go back to your broker", which needs no
address and no configuration.

### 3.3 The requester picks the mode, so the contact has to tell it

`dialOne` chooses streaming only when the contact is CCB-routed (nested) or the
caller supplied `ProxyReturnAddr`. A direct client holding a **flat** contact
takes `dialStandard`, opens its own listener, and waits for a connection a
carrier-attached EP can never make. The broker's decision to proxy arrives too
late: the client is no longer reading the broker socket as a data path, so the
broker splices into a socket nobody reads. Observed, before this was fixed:

```
INFO  proxy splice established ccbid=1 request=1
WARN  proxy splice failed  bytes_to_target=0 bytes_to_requester=0 duration=10.001s
```

So the mode is negotiated by the requester before the broker gets a say, and
the signal has to be in the contact. **Nested contacts are not an artifact of
having two brokers -- they are that signal.**

#### Resolved: nest through the carrier, collapse the hop

A carrier-attached target advertises `<public>#P#T`: `P` the carrier, `T` the
target. An ordinary client already recurses on that shape, so nothing about it
needs to change or to know a helper exists.

The difference from a nested contact today is that **both ids belong to this
broker**. There is no peer behind `P` to forward to, so `handleRequest`
collapses the hop instead: a request naming a carrier, with the real target at
the head of the route, becomes an ordinary single-hop proxy request for `T`.
`P` exists only to make the contact nest.

Implemented in `carrier_target.go`:

- `ServeCarrier(ctx, ln)` serves one carrier's listener -- in production the
  yamux listener over a pipe -- allocating a carrier id and tagging every
  connection accepted from it.
- A target registering over a tagged connection records its carrier, advertises
  the nested contact, and is always proxied (standard mode would send it to the
  requester, which is further away than the broker it reached us through).
- `resolveCarrierHop` requires the route's head to be a target **of the carrier
  named**. Without that check any carrier id would serve as a prefix for
  reaching any target on the broker; `TestCarrierHopWillNotReachAnotherCarriersTarget`
  holds the line, and fails when the check is removed.

`TestCarrierContactMakesAnOrdinaryClientStream` drives it end to end with a
client that sets no `ProxyReturnAddr` and is told nothing. Both tests were
mutation-checked: flattening the contact fails the first by name, dropping the
ownership check fails the second.

#### What "ordinary client" means, precisely

A **Go** client needs no change: `dialOne` recurses on a nested contact.

A **C++ v26 client does not work unmodified**, and the reason is not the one
`CCB_TUNNELING_DESIGN.md` 4.7 anticipated. Both changes that section called for
have already landed in v26:

- `CCBServer::CCBIDFromString` parses strictly, rejecting `"42#17"` outright
  (`ccb_server.cpp:112`);
- `CCBClient::SplitCCBContact` takes a `peel_innermost` flag and splits on the
  last or first `#` as the caller needs (`ccb_client.cpp:1171`), and
  `establishStreamingPipe` peels a whole id chain into `ccbid` + route
  (`ccb_client.cpp:199`).

The parsing half is done. What is missing is the **trigger**. v26 chooses
streaming from a property of the *client*, never from the shape of the contact.
Both gate sites ask the same question:

```cpp
// ccb_client.cpp:884 (blocking) and :1391 (non-blocking)
Sinful sinful_return( daemonCore->publicNetworkIpAddr() );
if( sinful_return.getCCBContact() ) {       // am I behind a CCB?
    ... ProxyConnect ...
}
```

and `streamingReturnAddr` says so outright: *"Streaming/proxy mode only applies
when this client is itself behind a CCB."* The third call site
(`ccb_client.cpp:977`) is the same kind of test -- `TOOLS_ASSUME_FIREWALLS` for
a tool that cannot open a listen socket.

So a v26 client reaches a carrier-attached target only when it is *itself*
unable to accept a reverse connection. A publicly reachable client -- a schedd
with a real address, the common case -- takes the plain reverse-connect path and
offers an address the target cannot dial.

**This is a pre-existing gap in C++ Stage D, not one this model introduces.**
The same public client reaching a tunneled EP through a nested contact hits the
same wall. The fix mirrors Go's `dialOne`: stream when the contact is nested,
whatever the client's own reachability. A few lines at the two gate sites.

An un-upgraded client fails cleanly either way. Peeling innermost it gets broker
`<public>#P` and ccbid `T`, and `<public>#P` is not a dialable address, so it
never reaches a broker to misroute at. A client that split the other way asks
for CCBID `"P#T"`, which the Go broker refuses --
`TestOldClientMisparseOfACarrierContactFailsCleanly` pins that, and v26's own
strict parse does the same.

No wire format avoids the trigger problem. Reaching a target that cannot dial
out requires the client to stop expecting to be dialed, and that is client-side
behaviour: it cannot be signalled to a client that does not implement it. The
contact shape only decides whether a client that *can* stream knows that it
should.

## 4. Determining the internal address (SUPERSEDED by §3.2; kept for the record)

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

Proven: the data path (§2); that no reverse-connect address is needed by anyone,
including a plain TCP EP (§3.2); that an ordinary client reaches a
carrier-attached target with no knowledge of any of this (§3.3).

Open design questions: none. What remains is engineering:

- land the cedar half of §3.2 (six lines) so the EP needs no carrier hook;
- the C++ streaming trigger (§3.3): v26 streams only when the client is itself
  behind a CCB, so a public client cannot reach a carrier-attached target. Needed
  for Stage D regardless of this model;
- drive `ServeCarrier` from a real carrier's yamux listener rather than a TCP
  one, and tie carrier lifetime to the pipe;
- build the helper itself -- a listener, a yamux client, and `io.Copy`;
- decide where the outbound allowlist and registration policy live now that
  they are enforced only at the outside broker (§5).
