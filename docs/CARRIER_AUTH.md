# Carrier authentication

How the inside CCB proves who it is when it opens a carrier, and what a
TLS-intercepting proxy on the path can learn from watching.

This document is design-facing; §8 below is written for administrators and is
the operational reference until the administrator guide carries it.

---

## 1. The problem

The WebSocket carrier dials `wss://host:443/ccb/tunnel` and presents an
HTCondor IDTOKEN (or a SciToken) in an `Authorization: Bearer` header. Many HPC
sites run a TLS-intercepting ("bumping") proxy: it terminates the outer TLS,
inspects, and re-encrypts to the origin. Such a proxy reads the upgrade request
in plaintext, bearer header included.

An IDTOKEN is a bearer credential. The whole of it — header, payload *and
signature* — is in that header. Whoever holds those three parts can
authenticate to any daemon in the pool as the node named in `sub`, for as long
as the token is valid. A pool IDTOKEN is commonly long-lived.

So the bumping proxy is handed a reusable pool credential. That is the problem
this document addresses.

---

## 2. Threat model

Three positions on the path, in increasing order of capability:

**T1 — Passive off-path observer.** Sees ciphertext only. Defeated by the outer
TLS; not interesting here.

**T2 — Passive bumping proxy.** Terminates the outer TLS and logs or archives
what it decrypts, but relays it faithfully. This is the common case: a site
appliance doing malware inspection, with logs retained and readable by site
staff or by anyone who later compromises the appliance.

What it reads is the outer envelope: the HTTP upgrade request and its headers,
and then the bytes of the CEDAR handshake that follows. It does **not** read
the CEDAR session those bytes establish. That session is keyed from the ECDH
exchange both peers offer, which `setupStreamEncryption`
(`security/auth.go:2309`) installs as the stream key, and a session that
enacted encryption without being keyed is refused outright rather than carried
in the clear (`requireEnactedKey`, `security/auth.go:2403-2409`). There is no
weaker fallback to drop to.

So the exposure at T2 is exactly what the upgrade itself carries — which today
is a bearer token, and which is the whole of what this document is about.

**T3 — Active bumping proxy.** The same position, but modifies, injects or
splices traffic. Either a malicious operator or a compromised appliance. Every
bumping proxy *is* positioned to do this; whether it does is a matter of
intent, not capability. It can disrupt or deny the carrier at will. It cannot
read or forge the CEDAR session inside it, for the same reason T2 cannot.

Out of scope: a compromised outside broker, a compromised worker node, and
anything the site can do by virtue of running the node's operating system. A
site that owns the node can read its token off the filesystem; no wire protocol
helps with that. What we can control is whether the *proxy*, a different
component with a different blast radius and a different retention policy, ends
up holding a pool credential.

---

## 3. What is actually on the wire today

These are the findings that drive the recommendation. Each is cited.

### 3.1 The upgrade header carries the complete token

`transport/wscarrier/ws.go:200-203` sets `Authorization: Bearer <token>` from
the full token string that `DiscoverBearerToken` read from disk, signature
included. `ws.go:239-246` reads it back. T2 reads it. **This is the leak.**

### 3.2 CEDAR's TOKEN method never transmits the token's secret

The CEDAR handshake that follows — the one that authenticates `CCB_REGISTER` at
`DAEMON` — does *not* put the token on the wire. CEDAR's TOKEN/IDTOKENS method
is HTCondor's AKEP2 (`condor_auth_passwd.cpp`), and it splits the JWT:

> `security/token_auth.go:476` — `authData.Token = parts[0] + "." + parts[1]`
> `security/token_auth.go:480` — `authData.Signature = signature` *(parts[2], kept locally)*

Only `header.payload` is sent (`sendClientTokenStep1`,
`security/token_auth.go:620-627`). The signature — the only part that is
secret — is used as HKDF input material to derive the AKEP2 keys K and K'
(`deriveTokenKeys`, `security/token_auth.go:1016-1040`). The server never
receives it either: it *recomputes* it from the pool signing key
(`validateTokenAndDeriveKeys`, `security/token_auth.go:974` calling
`computeTokenSignature`).

Both sides then prove possession. The server MACs `hK(A,B,rA,rB)`
(`sendServerTokenStep2`); the client verifies it
(`security/token_auth.go:720-723`) and MACs `hK(A,rB)` back
(`sendClientTokenStep3`), which the server verifies.

**CEDAR TOKEN authentication is already a mutually-authenticating
proof-of-possession protocol that is safe to run over a plaintext channel.** An
observer who records the entire handshake learns the token's claims (`sub`,
`iss`, `kid`, expiry — identity metadata, not secrets) and cannot replay it,
because producing the next session's MAC requires the signature they do not
have.

This is the fact that makes the bearer header redundant for *identity*.

### 3.3 The carrier's upgrade identity is computed and then discarded

`transport/wscarrier/ws.go:116` is the entire use of the verified identity:

```go
if _, err := l.verify(r.Context(), token); err != nil {
```

The identity is dropped on the floor. Nothing downstream consults it. Every
authorization decision on a carrier connection is made later, per command, by
`Server.authorize` (`server.go:463-474`) against the HTCondor `ALLOW_`/`DENY_`
policy, using the identity CEDAR established — not the one the upgrade
established. The two are never compared.

So the upgrade token is doing **admission control only**. It is not, and never
was, the basis of any authorization decision.

### 3.4 Carrier connections are authorized, on the same policy as TCP

Worth stating because it bounds what an unauthenticated upgrade could reach.
`startCarrierListener` (`carrier.go:210`) serves `s.srv`, the same cedar
command server as the TCP path, and `New` sets `s.srv.Authorizer =
cfg.Authorizer` (`server.go:320`). Authorization is enforced inside cedar for
every command regardless of listener.

The TCP path additionally wraps with `daemon.Authz.Serve`, which is only a
denial-logging and panic-recovery wrapper (golang-htcondor
`daemon/authz.go:258-287`) — it makes no authorization decision. The carrier
path therefore enforces the same policy but logs denials less visibly and lacks
the panic recovery. That is a pre-existing gap, noted in §7.

### 3.5 Carrier peers have no usable network address

`websocket.NetConn` reports a placeholder address: `RemoteAddr().String()` is
the constant `"websocket/unknown-addr"` (coder/websocket `netconn.go:191-199`).
That string reaches `Policy.Authorize`, where `net.ParseIP` on it yields nil
(golang-htcondor `authz/policy.go:278-284`), and a nil IP matches no host rule.

So over a WebSocket carrier:

- Host- and netblock-based `ALLOW_DAEMON` entries never match. They fail
  **closed**: a pool whose policy is purely host-based will refuse carrier
  registrations outright.
- Only identity-based entries (`ALLOW_DAEMON = condor_pool@...`) work.
- `peerIP` (`server.go:506`) is nil for carrier registrants, so reconnect IP
  pinning does not apply to them.

This is worth knowing before removing the upgrade check: at a pool that leans
on host-based `ALLOW_` lists, the host term was already not protecting the
carrier.

### 3.6 DoS baseline of the current accept path

What an unauthenticated peer can already make the outside broker do, today,
before `Verify` is even called:

| Resource | Current state |
|---|---|
| TCP accept | unbounded; no concurrent-connection cap anywhere |
| TLS handshake | full handshake, server key operation, before any token is seen |
| HTTP request parse | `http.Server` is built with no `ReadTimeout`, `ReadHeaderTimeout` or `IdleTimeout` (`ws.go:93-97`) — **Slowloris is open today** |
| Token verification | an IDTOKEN is HMAC-only and cheap. A SciToken may trigger outbound OIDC discovery + JWKS fetch — but `SciTokenVerifier` consults the local mapping *before* fetching (`wscarrier_auth.go:115-122`), so an unmapped issuer is never contacted |
| Post-upgrade read limit | `SetReadLimit(-1)` — unlimited (`ws.go:128`) |
| Idle pipes | a pipe that opens no yamux stream is held indefinitely |
| yamux streams | `AcceptBacklog` 256 bounds unaccepted streams per pipe; accepted streams are unbounded, but each must authenticate as a CEDAR connection |

The honest summary: the bearer token is *not* currently buying much DoS
protection, because the expensive parts (accept, TLS, header parse) all happen
before it is checked, and the cheap part after it is unbounded. Several of the
gaps above should be closed whether or not the token stays.

---

## 4. Options

### A. Unauthenticated upgrade, identity from CEDAR

Drop the `Authorization` header. Let the upgrade succeed for anyone, and let
the CEDAR handshake on the first command establish identity as it already does
(§3.2, §3.3). Add DoS controls to compensate (§6).

*Proxy sees:* an upgrade request with no credential. Then CEDAR's AKEP2:
`header.payload`, nonces, MACs. **No bearer credential, anywhere.**

*Attacker who observes it:* learns which node is registering and when. Cannot
replay, cannot impersonate, and cannot obtain a credential usable anywhere
else.

*At a bumping site:* works. Nothing in the scheme depends on the proxy not
being there.

*Complexity:* removes code. One configuration knob plus DoS limits.

*Operational burden:* none. No CA, no rotation, no revocation, no clock skew.
Revocation is already whatever the pool does with IDTOKENs.

*Backward compatibility:* trivially opt-in — a broker that keeps
`CCB_CARRIER_AUTH = token` behaves exactly as today.

*What it does not stop:* anonymous resource consumption at the WebSocket layer
(mitigated, not eliminated, by §6), and an in-path proxy disrupting the carrier,
which no credential scheme can prevent.

### B. Unauthenticated upgrade + inner TLS with a short-lived client certificate

Bootstrap a certificate over a CEDAR-authenticated exchange on the carrier,
then run an inner TLS 1.3 session inside the WebSocket using it.

The brief is right that this can only work as an *inner* session: mTLS on the
outer `wss://` cannot survive interception, because the proxy terminates the
handshake and cannot prove possession of the client's private key to the
origin. Presenting the cert on the outer connection fails at exactly the sites
it is meant to protect.

But as an inner session it is **largely already built, and not by us**. Cedar's
SSL and SCITOKENS methods already run a complete TLS session nested inside the
CEDAR stream: `tlsPipe` (`security/ssl_auth.go:484-602`) carries TLS records as
CEDAR messages, `createTLSConfig` configures both ends including `ClientCAs`
and `ClientAuth` (`ssl_auth.go:139-187`), and `PerformSSLHandshake` drives it.
So the machinery option B calls for mostly exists, and is reached by
configuration rather than by building anything: a pool that wants the carrier's
peer authentication to rest on certificates can negotiate cedar's SSL method,
using the credentials it already has.

What building the design *as specified* would add is the bootstrap: a new CA, a
CSR protocol, issuance, renewal before expiry, revocation, and clock-skew
tolerance on nodes whose clocks are not always good. That is a substantial
lifecycle to own.

And it would buy nothing over option A against the threat in §1. The reason the
bearer token is a problem is that it is *replayable* — the proxy can take it and
use it. CEDAR's AKEP2 already authenticates the broker without putting anything
replayable on the wire (§3.2), so a certificate would be replacing one
non-replayable proof with another.

*Recommendation:* reject the bespoke build. Option A gets there with no
lifecycle at all.

*(One detail if it were built: cedar's inner TLS is `MinVersion: TLS 1.2`
(`ssl_auth.go:144`). Under TLS 1.2 the client Certificate message is in the
clear, so the proxy would see the certificate. That is not a credential leak —
a certificate is public and possession of the private key is what authenticates
— but it does mean the "TLS 1.3 encrypts the client certificate" premise in the
brief would need `MinVersion` raised to hold.)*

### C. Keep the bearer token, make it non-replayable

Bind the token to a proof of possession — DPoP-style, or a short-lived
audience-scoped token.

Two sub-cases, and they differ sharply:

**C1 — short-lived, audience-scoped token.** This is today's documented advice.
It does not meet the stated goal: a bearer credential is still visible to the
proxy. It narrows the window and the blast radius, which is real, but a token
valid for minutes is still replayable for minutes, and "audience-scoped" scopes
it to *this broker* — which is the thing the attacker wants to reach anyway. It
is mitigation, not a fix.

**C2 — proof-of-possession binding.** This does meet the goal: the proxy sees a
public key and a signature over a nonce, never a replayable secret. Honest
assessment: it works. The objection is not security, it is duplication. CEDAR's
AKEP2 already *is* a proof-of-possession protocol for exactly this credential,
already runs on this carrier, and is already the basis of every authorization
decision (§3.2, §3.3). C2 adds a second, bespoke, HTTP-layer PoP protocol
proving the same possession of the same key to the same peer, seconds before
CEDAR proves it properly — plus a nonce cache, a replay window, and clock-skew
tolerance.

It would be the right answer if the upgrade check had to be cryptographic *and*
could not wait for CEDAR. §5 argues it does not have to.

*Backward compatibility:* C2 needs both ends upgraded, same as A.

### D. Keep the token, but out of the proxy's view

Noted and rejected for completeness: tunnel the token in a payload rather than
a header. It is in the same TLS session the proxy terminated. Encoding does not
help. Mentioned only because "move it out of the header" is a tempting
non-answer.

---

## 5. Recommendation

**Adopt option A, opt-in.**

Reasoning:

1. It is the only option that removes the credential rather than shrinking the
   window on it, at no protocol cost.
2. The thing being removed is redundant. The upgrade identity is computed and
   discarded (§3.3); CEDAR independently establishes the same identity by
   proof of possession (§3.2) and is the sole basis of authorization (§3.4).
3. The admission control it provided is weaker than it looks: the expensive
   work all happens before the check, and the cheap work after it is unbounded
   (§3.6). Explicit limits are a better answer than a token check, and are
   worth adding in both modes.
4. Options B and C both work, and both cost a new protocol with a new
   lifecycle, to arrive at the same place: a non-replayable proof of the same
   possession CEDAR already proves.

**What this does stop:** a bumping proxy acquiring a reusable pool credential.
That is the stated goal, and it is met completely.

**What this does not stop, stated plainly:**

- An active bumping proxy is in-path and can disrupt or deny the carrier
  regardless. Nothing at this layer prevents that.
- A bumping proxy still sees *that* a node is registering, and when, from the
  handshake metadata — claims such as `sub`, `iss` and expiry. Identity
  metadata, not secrets.
- An anonymous peer can consume resources at the WebSocket layer. Bounded by
  §6, not eliminated.
- A site that owns the worker node can still read its tokens off disk. Nothing
  here changes that, and nothing could.

---

## 6. DoS controls for an unauthenticated upgrade

Each limit, and why its default is what it is.

**Server-side read timeouts.** `ReadHeaderTimeout` 10s, `ReadTimeout` 30s,
`IdleTimeout` 120s. Closes the Slowloris hole that exists today (§3.6). Ten
seconds is far beyond any legitimate header write and short enough that holding
a slot costs an attacker a connection per ten seconds. Applied in **both**
modes — this is a bug fix, not a new-mode control.

**Maximum concurrent carrier pipes.** Default 1024. One pipe per inside broker,
so the cap is a node count: a site tunnelling more than 1024 nodes through one
outside broker must raise it, and the error says so. This is a backstop against
unbounded accept, not a precision instrument.

**Per-source limits — deliberately off by default.** The obvious control is a
per-source-IP connection cap and rate limit. It is the wrong default *here*,
and the reason is specific to this deployment: at a bumping site **every
legitimate node arrives from the proxy's address**. A per-source cap would be
enforced against the one source that must not be capped, and would fail exactly
the deployment this work targets. Offered as a knob, defaulting to off, with
that caveat documented. An operator whose brokers are reached directly should
turn it on.

**Pipe probation.** A carrier pipe that opens no yamux stream within 60s is
closed. A legitimate inside broker registers immediately, so this is invisible
to real traffic while bounding the cost of an idle anonymous pipe to one minute.
This is the control that most directly replaces the token: it keeps the
unauthenticated endpoint from being a place to park connections.

**Bounded WebSocket read limit.** 1 MiB when the upgrade is unauthenticated
(unchanged — unlimited — when a token is required, preserving today's
behavior). yamux's default `MaxStreamWindowSize` is 256 KiB, and a frame
payload cannot exceed the receive window, so 1 MiB is ~4x headroom over the
largest legitimate message while bounding per-connection buffer growth.

---

## 7. Known gaps, not addressed here

- **Carrier denials are logged less visibly than TCP ones,** and the carrier
  path lacks the per-connection panic recovery the TCP path has, because
  `startCarrierListener` serves `s.srv` directly rather than through
  `daemon.Authz.Serve` (§3.4).
- **Host-based `ALLOW_` entries silently never match carrier peers** (§3.5).
  This surprises operators and deserves a startup warning.

---

## 8. For administrators

### 8.1 Which mode to run

| | `CCB_CARRIER_AUTH = token` (default) | `CCB_CARRIER_AUTH = none` |
|---|---|---|
| Credential on the upgrade | IDTOKEN or SciToken | none |
| What a bumping proxy gets | **a reusable pool credential** | nothing reusable |
| Who authenticates the node | CEDAR, on the first command | CEDAR, on the first command |
| Upgrade endpoint | closed | open, with the limits in §8.3 |

Run `none` wherever the path crosses a proxy that intercepts TLS. Run the
default everywhere else, or where the open endpoint is unacceptable for reasons
of its own. Both ends must agree: an inside broker set to `none` cannot reach an
outside broker still requiring a token, and the dial fails with
`unauthorized (bad or missing token)`.

### 8.2 Turning it on

On **both** the outside broker and every inside broker:

```
CCB_CARRIER_AUTH = none
```

Nothing else changes. `CCB_CARRIER_TOKEN` may stay in the configuration — it is
ignored in this mode and no token is discovered from the environment, so a node
with no token still starts.

Then check two things:

1. **`ALLOW_DAEMON` must admit the node by identity, not by host.** A carrier
   peer has no network address (§3.5), so host and netblock terms never match
   it. If your policy is purely host-based, carrier registrations were already
   failing; add the pool identity:

   ```
   ALLOW_DAEMON = $(ALLOW_DAEMON), condor_pool@$(UID_DOMAIN)
   ```

2. **`CCB_OUTBOUND_TARGET_ALLOWLIST` is now the only thing bounding where a
   tunnel can reach.** It always was the thing that mattered, but with an open
   upgrade there is no second gate in front of it. Set it to your pool and
   nothing more.

### 8.3 The limits on an open endpoint

| Knob | Default | What it does |
|---|---|---|
| `CCB_CARRIER_MAX_SESSIONS` | 1024 | Concurrent carrier pipes. One per inside broker, so this is a node count — raise it if you tunnel more nodes than this through one broker. |
| `CCB_CARRIER_MAX_PER_SOURCE` | 0 (off) | Concurrent pipes from one address. **Leave this off behind an intercepting proxy**, where every node arrives from the proxy's address and this limit would fall on the one source that must not be limited. Useful only for brokers reached directly. |
| `CCB_CARRIER_PIPE_PROBATION` | 60 (seconds) | Closes a pipe that opens no connection in this long. A real inside broker registers immediately, so this is invisible to working traffic. Set it to `0` to turn the check off. |

HTTP read timeouts (10s for headers, 30s for the request, 120s idle) apply in
**both** modes and are not configurable. They close a gap that existed before
this change: the request was parsed before any credential was checked, with no
deadline, so a peer could hold a slot indefinitely while sending nothing.

### 8.4 Diagnosing it

The broker logs the mode at startup:

```
CCB carrier listener enabled  carrier=wss://... upgrade_auth=none
carrier upgrades accept no bearer token; peers are authenticated by the
CEDAR handshake on their first command
```

**A bad credential now fails later.** With a token on the upgrade, a wrong
credential failed the dial with a clear 401. With `none`, the upgrade always
succeeds and the credential is checked at `CCB_REGISTER` instead — so a
misconfigured pool credential shows up as *a carrier that connects but never
registers*, not as a refused dial. If `CCB_TUNNEL_READY_FILE` never appears,
look for an authentication or authorization failure in the outside broker's log
rather than at the carrier.

This also shifts where a startup barrier blocks. A broker that waits for
upstream registration before reporting ready will, on a credential error, now
wait out that timeout instead of failing fast at the dial — the tunnel is
genuinely not ready, so the barrier is behaving correctly, but the *reason* is
one hop further in than it used to be and is recorded on the outside broker.

### 8.5 What this does and does not protect

It stops a TLS-intercepting proxy from acquiring a credential it can reuse.
That is the whole of its claim, and it is met completely.

It does not change what such a proxy can do *to* the connection. A proxy that
terminates the outer TLS sits in the path and can slow, drop or deny the
carrier whenever it likes. No credential scheme prevents that; the broker's
reconnect handling is what limits the damage.

It does not hide *that* a node is tunnelling. The proxy sees the upgrade and
the handshake that follows, including the identity claims in it — who is
registering and when, though nothing it can reuse.

And it changes nothing about a site that owns the worker node. Such a site can
read the node's tokens off its filesystem; no wire protocol helps with that.
