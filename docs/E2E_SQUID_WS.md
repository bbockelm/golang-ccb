# End-to-end test: a tunneled EP behind an HTTP proxy

A site-shaped demonstration that an HTCondor execution point on an HPC worker
node with **no direct outbound TCP** — only a squid HTTP proxy, and only to
approved destinations — can join and be fully driven by an offsite pool, with
its entire network footprint collapsed to **one** proxied TLS connection.

The pieces exist: the WebSocket carrier (`transport/wscarrier`), yamux muxing
(`transport/carrier`), the inside/outside CCB pair, nested contacts, and the
outbound `CCB_PROXY_CONNECT` chain are all implemented and Go↔Go tested (see
[TRANSPORTS.md](TRANSPORTS.md) §3 and the C++ tree's `CCB_TUNNELING_DESIGN.md`).
What is missing is the proxy itself — §2 — and the tests that would catch a
deployment regressing to a direct dial.

---

## 1. The claim being demonstrated

> A glidein launched on a worker node brings its own `golang-ccb`. That broker
> opens **one** `wss://` connection, outbound, through the site squid, to an
> approved host on port 443. Every connection the EP makes or receives
> thereafter — collector updates, the schedd's claim, shadow↔starter file
> transfer — rides that one connection. Offsite, `golang-ccb` unwraps the
> WebSocket back into ordinary CEDAR and relays to the rest of the pool, which
> is unmodified. End-to-end CEDAR authentication and encryption are preserved;
> neither broker holds the keys.

Each clause in that paragraph is one assertion in §5. A test that does not
falsify the sentence "the EP could have reached the pool directly" proves
nothing, so §6 is as load-bearing as §5.

---

## 2. Prerequisites

Status: §2.1-§2.6 are **implemented**; tiers 0 and 1 of §7 ship with them. The
container tier (§7, tier 2) is the remaining work.

### 2.1 The carrier ignores HTTP proxy configuration — including the environment (done)

`wscarrier.Dial` builds its HTTP client with no `Proxy` at all:

```go
httpClient := &http.Client{}
if cfg.TLS != nil {
    httpClient.Transport = &http.Transport{TLSClientConfig: cfg.TLS}
}
```

For `wss://` — the only scheme usable through squid — `cfg.TLS` is set, so that
hand-built `Transport` is used and it has no `Proxy` field, meaning
`HTTPS_PROXY` in the environment is **silently ignored** and the dial goes
direct. On a worker node with no route out, that is a connection timeout with no
hint that a configured proxy was skipped.

Done: `DialConfig.Proxy` is applied to a Transport built for every dial. Go's
`http.Transport` issues a `CONNECT` for an `https` target and returns the 101
response body as an `io.ReadWriteCloser`, which is exactly what
`coder/websocket` consumes, so the tunnel works with no other change.

One wrinkle found while testing: the default is **not**
`http.ProxyFromEnvironment`, which resolves `HTTPS_PROXY` / `NO_PROXY` once per
process and caches the answer forever. A glidein that sets the proxy after
something else has already consulted the environment would keep a stale route
with nothing in the logs to show for it. The environment is read per dial
instead, through `x/net/http/httpproxy`, with the same matching rules.

`ws://` through a proxy is *not* supported and should be rejected with a clear
error: a plaintext proxied request is an absolute-URI `GET` that squid will not
relay as an `Upgrade`. Production is `wss://` regardless.

### 2.2 The daemon has no proxy knob (done)

`buildCarrierSettings` in `cmd/golang-ccb/main.go` resolved `CCB_CARRIER_TOKEN`
and `CCB_CARRIER_CA_FILE` but nothing for a proxy. Added:

| Knob | Meaning |
|---|---|
| `CCB_CARRIER_PROXY` | Proxy URL (`http://squid.site:3128`). Unset = `HTTPS_PROXY`/`NO_PROXY` from the environment. The literal `none` disables proxying even if the environment sets one. |
| `CCB_CARRIER_PROXY_CREDENTIAL_FILE` | File holding `user:password` for a squid with `proxy_auth REQUIRED`. Read at dial time (so rotation works), injected as the proxy URL's userinfo so Go emits `Proxy-Authorization`. Kept out of the config file because config is world-readable. |

### 2.3 A proxied dial is indistinguishable from a direct one in the log (done)

`carrierClient.session` logs `"carrier session established"` with the carrier
URL only. A test (or an operator) cannot tell whether squid was used. Add the
resolved route to that log line — `via=http://squid.site:3128` or `via=direct` —
and emit it on failure too. Without this, §6's negative controls cannot be
written honestly, and a site that misconfigures the proxy looks healthy right up
until the first worker node that actually lacks a route.

### 2.4 An inside CCB stamps contacts before it is tunnel-ready (done)

`Server.contactString` returns the inside CCB's own *private* `PublicAddress`
until upstream registration completes; `handleRegister` calls it with no wait.
An EP daemon that registers during the carrier handshake — easily seconds over a
proxy — therefore receives a flat, unroutable contact and is advertised to the
collector as unreachable, permanently. The C++ off-host inside CCB avoids this
by deferring each registration reply until it is tunnel-ready.

Done: `handleRegister` waits on `tunnelReady` (bounded by `RequestTimeout`) when
`Config.Upstream` is set, and refuses the registration rather than answering with
a flat contact. Refusing matters more than it looks: a registrant's CCBListener
retries, but it never re-registers a contact it has already accepted. A wrapper may *also*
gate `condor_master` on `CCB_TUNNEL_READY_FILE`, but belt-and-braces: the
deferral is what makes a restarting EP safe.

### 2.5 No outbound test over the WebSocket carrier (done)

`carrier_e2e_test.go` covers inbound over `ws://`
(`TestInboundTunnel2CCBOverWSCarrier`) and both directions over the filesystem
carrier, but the outbound `CCB_PROXY_CONNECT` chain has no WebSocket variant.
The outbound direction is the one the EP uses most (every collector update), so
it needs the same coverage. Added in tier 1, with and without a proxy.

### 2.6 A carrier has no health check (done)

A carrier dial crosses four things a site's network policy can break
independently — reaching the proxy, the proxy's willingness to tunnel here, TLS,
and the token — and a bare "dial failed" distinguishes none of them. Worse, none
of them says anything about whether the thing at the far end is the broker we
think it is, or whether the two agree on credentials.

`Server.CheckCarrier` walks the stages in order and reports each separately, with
advice naming the site policy that usually causes it (see
[TRANSPORTS.md](TRANSPORTS.md) §3.2 for the stage table). The daemon runs it at
startup and logs the report, never fatally; `golang-ccb -carrier-check` runs it
and exits non-zero, for an administrator diagnosing a node by hand.

The final stage is the one the transport cannot imply: a CEDAR handshake to the
far broker. A peer that completes the handshake and then reports it has no
`DC_NOP` handler counts as a **pass** — identity and policy agreement are what
the stage checks, and a broker is not obliged to answer `DC_NOP`.

---

## 3. Topology

Three network zones. The restriction must be **structural**, not configured: the
EP is placed on a container network with no gateway, so "cannot dial out" is a
property of the network rather than a knob a passing test could be ignoring.

```
   ┌─ net_hpc (internal: true, no gateway) ──┐   ┌─ net_pub ─────────────────┐
   │                                          │   │                          │
   │  ep                          squid ──────┼───┼──── offsite              │
   │  ├ golang-ccb (inside)       :3128       │   │     ├ golang-ccb (outside)
   │  │   CCB_OUTBOUND_NEXT_HOP =             │   │     │   :9618  CEDAR (pool)
   │  │     wss://ccb.offsite.test/ccb/tunnel │   │     │   :443   wss carrier
   │  │   CCB_CARRIER_PROXY = http://squid:3128   │     ├ condor_collector
   │  ├ condor_master                         │   │     ├ condor_negotiator
   │  └ condor_startd                         │   │     └ condor_schedd
   │      CCB_ADDRESS = <local inside ccb>    │   │                          │
   │      OUTBOUND_CCB_ADDRESS = <same>       │   │                          │
   └──────────────────────────────────────────┘   └──────────────────────────┘
          squid is the only container on both networks
```

- `ep` has **no DNS record** for `ccb.offsite.test` and no route to `net_pub`.
  Name resolution happens at squid, inside the `CONNECT`, which is how a real
  HPC node behaves and is itself worth asserting.
- Port **443** is not cosmetic. Stock `squid.conf` carries
  `http_access deny CONNECT !SSL_ports` with `acl SSL_ports port 443`, so a
  carrier on 9618 is refused by an unmodified site proxy. The outside CCB
  therefore serves CEDAR on 9618 and the carrier on 443; §6 proves the 9618 case
  is denied.
- The pool runs with `SEC_DEFAULT_ENCRYPTION = REQUIRED` and
  `SEC_DEFAULT_INTEGRITY = REQUIRED` while both brokers run their own sessions
  in plaintext. A job that completes is then a proof that end-to-end CEDAR
  survived three splices, with no extra assertion needed.

### squid.conf (the enforcing part)

```squid
acl localnet src 10.0.0.0/8
acl SSL_ports port 443
acl CONNECT method CONNECT
acl approved_dst dstdomain ccb.offsite.test

http_access deny CONNECT !SSL_ports        # 9618 is refused (§6.3)
http_access deny CONNECT !approved_dst     # "specific outbound destinations"
http_access allow CONNECT approved_dst localnet
http_access deny all

read_timeout 1 minute                      # short on purpose; see §5.F
http_port 3128
access_log /var/log/squid/access.log
```

---

## 4. The EP side: what the glidein does

This is the shape a glidein takes, and the part the site will read most closely.

A glidein runs `condor_master`, so there is no hand-rolled startup sequence: the
broker is one of the master's daemons, listed first, and the ordering problem is
solved inside the broker rather than by a wrapper script.

```condor
DAEMON_LIST = MASTER, CCB, STARTD
CCB = /usr/sbin/golang-ccb
CCB_ARGS = -listen 127.0.0.1:9700 -public 127.0.0.1:9700
USE_SHARED_PORT = FALSE

CCB_OUTBOUND_PROXY = TRUE
CCB_OUTBOUND_NEXT_HOP = wss://ccb.offsite.test/ccb/tunnel
CCB_CARRIER_PROXY = http://squid.site:3128
CCB_CARRIER_CA_FILE = $(LOCAL_DIR)/ca.pem
CCB_CARRIER_TOKEN = <IDTOKEN or SciToken>   # or discovery, see below
CCB_TUNNEL_READY_FILE = $(LOCAL_DIR)/ccb_tunnel_ready
CCB_OUTBOUND_TARGET_ALLOWLIST = <pool CIDRs>

# The startd reaches the pool through the local broker, and is reached through it.
CCB_ADDRESS = 127.0.0.1:9700
OUTBOUND_CCB_ADDRESS = 127.0.0.1:9700
```

The broker verifies its carrier and waits for upstream registration before
reporting ready (§2.6), so readiness means it can do its job. A startd that
starts first is handled by §2.4 rather than by ordering: the broker refuses to
register it instead of handing out an address the pool cannot reach, and its
`CCBListener` retries. `-carrier-check` is a diagnostic an administrator runs by
hand, not a gate in a script — what turns "the glidein did nothing" into a line
naming the proxy, the ACL, the certificate or the token.

The bearer token authenticating the carrier is discovered the way a glidein
already carries credentials: `DiscoverBearerToken` reads `BEARER_TOKEN`,
`BEARER_TOKEN_FILE`, `$XDG_RUNTIME_DIR/bt_u<uid>`, then an HTCondor IDTOKEN from
the token directory. The offsite CCB verifies either kind
(`BearerTokenVerifier`); a SciToken additionally requires a `SCITOKENS` mapping.
The test should use a SciToken in one variant and an IDTOKEN in another, because
sites differ.

`USE_OUTBOUND_CCB` is deliberately not used: it auto-injects the *collector* as
the local inside CCB, and here the inside CCB is a standalone `golang-ccb` with
no collector role. Setting the two knobs explicitly is what a glidein does anyway.

---

## 5. Assertions

Each is a separate test, ordered so a failure localizes.

**A — the carrier establishes through squid.**
Inside CCB logs `carrier session established ... via=http://squid:3128`; squid's
`access.log` contains `CONNECT ccb.offsite.test:443` with `TCP_TUNNEL/200`; the
outside CCB logs the accepted upgrade with the verified token identity.

**B — exactly one TCP connection leaves the node.**
While a job runs, `ss -tn state established` in the `ep` container shows exactly
one connection from the inside CCB, and its peer is squid:3128. This is the
headline property for a site that throttles socket counts, and the only
assertion that catches a regression to one-TCP-per-request.

**C — the EP's advertised contact is nested.**
`condor_status -l` from the offsite pool shows the startd's `MyAddress` carrying
a `CCBID` of the form `<outside-public>#<inside-id>#<startd-id>` — two `#`
separators, i.e. a two-hop source route. (A flat contact here means §2.4
regressed.)

**D — inbound works: offsite → EP, over the carrier.**
`condor_status -direct <startd contact>` from the offsite side succeeds. Both
brokers log a splice. Squid's `CONNECT` count does **not** increase: the request
rode the existing tunnel.

**E — outbound works: EP → offsite, multi-hop.**
The startd's collector updates and the claim exchange traverse
EP → inside CCB (`CCB_PROXY_CONNECT`) → [wss/squid] → outside CCB → dial. Count
`proxy-connect splice established` in both brokers' logs before and after, and
assert both strictly increased — an absolute count would be satisfied by an
earlier, unrelated setup connection.

**F — a real job, with file transfer.**
Submit from the offsite schedd with a sentinel input file and
`cat`-the-sentinel as the executable; wait for completion; assert the output
matches. This exercises the shadow↔starter connection in both directions
through both brokers, under `SEC_DEFAULT_ENCRYPTION = REQUIRED`.

**G — the tunnel survives an idle period longer than squid's timeout.**
With `read_timeout 1 minute` in squid, idle the pool for three minutes, then run
a second job. yamux keepalives should keep the `CONNECT` tunnel alive; if they
do not, this is the failure every long-lived glidein would hit at 3am, and the
fix is a carrier-level WebSocket ping interval shorter than the site timeout.

**H — the carrier recovers.**
`docker restart squid` (or disconnect it from `net_hpc` and reconnect) mid-run.
The inside CCB must re-dial through squid — `carrierClient.session` already
re-establishes a dead pipe — the EP must re-register, and a third job must run
to completion. Assert the nested contact after recovery is still nested.

---

## 6. Negative controls

These must **fail**, and the test asserts the failure. Without them §5 is
satisfiable by an EP that quietly took a direct route.

1. **No direct path.** From `ep`, a TCP connect to `ccb.offsite.test:443` and to
   the outside CCB's 9618 both fail (no route). Run this *first*; if it
   succeeds, the test environment is broken and everything after it is vacuous.
2. **No local DNS.** Resolving `ccb.offsite.test` from `ep` fails, proving the
   name was resolved by squid inside the `CONNECT`.
3. **Stock squid refuses a non-443 carrier.** Point `CCB_CARRIER_LISTEN` at
   `wss://ccb.offsite.test:9618/ccb/tunnel`; squid logs `TCP_DENIED/403` and the
   inside CCB never becomes tunnel-ready. This is the single most likely first
   failure at a real site.
4. **Destination allow-list.** Point the next hop at an unapproved host that
   *is* routable from squid; `TCP_DENIED/403`, no carrier.
5. **Bad bearer token.** The upgrade is refused with 401 and the error names the
   cause; no carrier, no partially-registered EP.
6. **Outbound target allow-list.** An EP-side connect to a target outside
   `CCB_OUTBOUND_TARGET_ALLOWLIST` is refused by the exit CCB — the tunnel is
   not an open proxy into the public network.
7. **Proxy ignored.** With `CCB_CARRIER_PROXY` unset and no environment proxy,
   the EP fails to establish. If it succeeds, §6.1 is broken.

---

## 7. Tiers

**Tier 0 — unit (`transport/wscarrier/proxy_test.go`), seconds, every PR. Shipped.**
A ~40-line in-process `CONNECT` proxy: accept, parse `CONNECT host:port`, either
dial and splice or return `403`. Assert (a) a `wss://` dial with `Proxy` set
reaches the carrier and the proxy recorded the `CONNECT`; (b) a denied `CONNECT`
surfaces a clear error; (c) `Proxy-Authorization` is sent when the proxy URL has
userinfo; (d) `ws://` with a proxy is rejected up front. The proxy and its TLS material are
`internal/proxytest`, shared with tier 1 so there is one implementation rather
than a copy per package. It also covers the staged health check: each stage is
asserted to fail on its own cause, including a certificate from an untrusted CA
standing in for an intercepting proxy.

**Tier 1 — package e2e (`carrier_proxy_e2e_test.go`), seconds, every PR.
Shipped.** `TestInboundTunnel2CCBOverWSCarrierViaProxy`,
`TestOutboundProxyTwoCCBOverWSCarrierViaProxy` (§2.5),
`TestCarrierFootprintIsOneConnection`, the two health-check tests, and
`TestRegisterRefusedUntilTunnelReady` (§2.4). Each asserts the proxy saw exactly
one `CONNECT` for the whole test — the cheap form of §5.B, and the assertion that
catches the failure mode this work started from: removing the proxy wiring leaves
every one of these tests passing except the `CONNECT` count, because on a
developer's machine the direct dial simply works.

This tier proves the protocol; it cannot prove the deployment.

**Tier 2 — real squid (`test/e2e-squid/`, docker compose), minutes, nightly or
on the `squid-e2e` label. Built; see that directory's README.** The pool and the
job are not in it yet, so it covers the network story and not §5.F. The §3 topology with an unmodified squid package, a
real HTCondor pool offsite, a real job, and §6's controls. This is the tier that
catches `SSL_ports`, idle timeouts, proxy auth and DNS — the things that
actually decide whether a site deployment works, and none of which tier 1 can
see. It is also the artifact to hand to the site: a compose file they can read
and compare against their own squid.

**Tier 3 — the site itself, manual.** Same glidein configuration, their squid, their
token. The only new information is their squid's ACLs and whether it bumps TLS.

---

## 8. What a real squid adds that an in-process proxy cannot

- **`SSL_ports`** — the 443 constraint (§6.3). Shapes the deployment: the
  outside CCB needs a real 443, which means it needs a real certificate and
  probably a hostname the site will approve by name.
- **Idle timeouts** — §5.G. `read_timeout` / `client_lifetime` govern an
  established `CONNECT` tunnel; a glidein idles for hours.
- **`proxy_auth`** — many HPC squids require Basic auth. Covered by §2.2's
  credential file; a variant of tier 2 turns on `basic_ncsa_auth`.
- **TLS interception (`ssl_bump`)** — if the site bumps, the carrier's server
  certificate is replaced by the site CA, so `CCB_CARRIER_CA_FILE` must carry
  that CA or the dial fails closed (correctly). Worth stating plainly to the
  site: CEDAR's end-to-end encryption means a bumping proxy still sees only
  opaque bytes, but it *does* see the bearer token presented in the upgrade
  request, so a bumped deployment wants a short-lived, audience-scoped token
  rather than a long-lived pool IDTOKEN. A tier-2 variant with a bumping squid
  is optional; the honest default is to document it and fail closed.
- **Request logging** — `access.log` is the independent observer. Every
  assertion that counts `CONNECT`s depends on a proxy that logs like squid does.

---

## 9. Remaining work

§2 and tiers 0-1 are done. What is left:

1. §5.F — a real HTCondor pool and a real job inside the compose topology. The
   network story is covered; what is not is a shadow and a starter talking
   through the tunnel under `SEC_DEFAULT_ENCRYPTION = REQUIRED`, which is the
   assertion a site will actually ask for.
2. §5.G/H — idle survival past squid's `read_timeout`, and recovery after the
   proxy restarts. These are the two that decide whether a glidein survives a
   night, and neither can be tested without a real proxy. The topology now has
   one, so both are reachable; `read_timeout` is already set to one minute in
   `test/e2e-squid/squid.conf` so an idle test has something to survive.
3. A `proxy_auth` variant and a TLS-intercepting (`ssl_bump`) variant. The
   health check classifies both refusals already (§2.6); only a real squid can
   confirm the classification matches what it sends.

Done: §6.1-§6.4 against a real `squid.conf`, including that the advice names the
`SSL_ports` rule when a carrier is put on 9618.

### A defect found on the way, not fixed here

The relay tears down without draining: when a target closes as soon as its
command handler returns, that close races the handshake reply still in flight
back through the splices, and the requester reads EOF instead of the reply. It
reproduces on `main` with no carrier involved — `TestOutboundProxyTwoCCB` and
`TestOutboundProxyTwoCCBOverFSCarrier` fail this way about one run in three, as
does `TestOutboundProxyStageA`, which is a single-broker outbound test.

It is in the relay's teardown, not in any carrier, so it is out of scope here and
wants its own fix. The tier-1 tests use a target that lets the reply drain, and
say so, rather than papering over it: they are asking whether a proxied carrier
relays faithfully, which is a different question.
