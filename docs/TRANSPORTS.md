# CCB tunneling: pluggable carriers (non-TCP transports)

CCB tunneling (see the C++ tree's `CCB_TUNNELING_DESIGN.md`) routes all of a
restricted node's traffic through an **inside CCB → outside CCB** pair. The
default inside↔outside link is TCP. This document describes the alternative
*carriers* for that one link, so a site that forbids outbound TCP entirely (or
throttles live socket counts to ~1) can still tunnel:

1. **WebSocket** — a single long-lived TCP connection to an HTTPS port on the
   outside CCB, token-authenticated, optionally through a site HTTP proxy. (§3.)
2. **Filesystem tunnel** — no sockets at all between the brokers: they rendezvous
   through a shared (NFS-like) directory. (§4. The fun one.)
3. **Command and stdio** — the pipe is a child process's stdin and stdout, so the
   transport is whatever the operator runs: `ssh`, `kubectl exec`, a site gateway
   wrapper. (§5.)
4. **Raw TCP pipes** — where a relayed carrier lands. (§5.4.)

Only the inside↔outside link changes. The outside CCB still faces the pool over
normal TCP CEDAR; clients reaching a tunneled EP are unchanged. End-to-end CEDAR
is preserved throughout — carriers move opaque bytes and never hold the keys.

---

## 1. The seam

Everything the inside CCB does to the outside CCB funnels through cedar's
`dialBroker(ctx, addr, name) (*stream.Stream, error)`:

- the **persistent upstream registration** (`ccb.Listener` → `dialBroker`), over
  which forwarded inbound reverse-connects arrive; and
- each **outbound proxy** (`ccb.OutboundConnect` → `dialBrokerAuthCmd` →
  `dialBroker`), one dial per `CCB_PROXY_CONNECT`.

The outside CCB, symmetrically, just serves its cedar command loop on a
`net.Listener` (`srv.Serve(ctx, ln)`) — it already accepts *any* listener.

So a carrier is exactly a **point-to-point, connection-oriented transport that
looks like TCP `Dial`/`Listen`**:

```
inside CCB (client)                         outside CCB (server)
  fstun.Dial(cfg) ──── one byte-pipe ────── fstun.Listen(cfg).Accept()
       │                                              │
  yamux.Client(pipe)                          yamux.Server(pipe)
       │                                              │
  session.Open()  ── stream (a "dial") ──►  session.Accept() ─► srv.Serve(conn)
  session.Open()  ── stream ─────────────►  session.Accept() ─► srv.Serve(conn)
        ...
```

**yamux** ([hashicorp/yamux](https://github.com/hashicorp/yamux)) multiplexes the
many logical connections (the registration stream + one per proxy-connect) over
the *single* carrier byte-pipe. This is what lets the whole node live on one TCP
connection (WebSocket) or zero (filesystem). yamux gives us stream framing, flow
control per stream, and keepalives for free; the carrier only has to deliver one
reliable, ordered, bidirectional byte stream.

### Wiring (both carriers share this)

- **cedar** (small, carrier-agnostic addition): an optional dialer hook on
  `ccb.ListenerConfig` and `ccb.OutboundOptions`:
  `Dial func(ctx, brokerAddr string) (net.Conn, error)`. When set, `dialBroker`
  uses it instead of TCP/shared-port; when nil, behaviour is unchanged. The inside
  CCB sets this to `func(...) { return yamuxSession.Open() }`.
- **htc-ccb** (outside CCB): when configured with a carrier, build the carrier
  `net.Listener`, wrap each accepted byte-pipe in a `yamux.Server`, and run a
  goroutine that `Accept()`s streams and hands each to `srv.Serve` — identical to
  the TCP accept loop.

The carrier is selected by the scheme of the broker address, and the **role** by
which knob that address appears in — `CCB_OUTBOUND_NEXT_HOP` (and
`Upstream.BrokerAddr`) for the inside broker, `CCB_CARRIER_LISTEN` for the
outside one. A bare `host:port` is not a carrier and keeps the default TCP path.

| Address | Carrier | |
|---|---|---|
| `fs:/gpfs/ccb/outbound` | filesystem rendezvous | §4 |
| `wss://cm.example.org/ccb/tunnel` | WebSocket over TLS | §3 |
| `ws://cm.example.org/ccb/tunnel` | WebSocket, plaintext (test/dev) | §3 |
| `tcp://host:9700` | raw carrier pipe over TCP | §5.4 |
| `cmd:ssh bastion htc-ccb -carrier-stdio` | the command's stdin/stdout | §5 |
| `stdio:` | this process's own stdin/stdout | §5.3 |

Obtaining a pipe and playing a role are separate choices (§5.5): a `cmd:` carrier
in `CCB_CARRIER_LISTEN` lets the **outside** broker reach into a network it
cannot dial into, and the broker it starts there plays the inside role over the
same pipe.

---

## 2. Common carrier contract

A carrier provides:

```go
// Acceptor side (outside CCB).
type Listener interface {
    Accept() (net.Conn, error) // one byte-pipe per inside CCB
    Close() error
    Addr() net.Addr
}
// Initiator side (inside CCB).
func Dial(ctx, cfg) (net.Conn, error) // one byte-pipe to the outside CCB
```

The returned `net.Conn` must be a reliable, ordered, full-duplex byte stream with
a clean `Close`. yamux is layered on top by the caller. The carrier need not
multiplex — that is yamux's job — so a carrier is "just" one good pipe.

Deadlines are expected but not required. Nothing in the stack sets one on the
pipe: yamux implements deadlines on its own streams, which is where the CEDAR
command loop runs, and never touches the underlying conn. A carrier whose
descriptors cannot take a deadline — an inherited stdin that could not be made
non-blocking (§5.3) — is therefore fully functional.

Since §5, a carrier is reached through `carrier.PipeSource` rather than directly,
which is what lets either role dial or accept (§5.5). `Dial`/`Listen` above are
still how each transport is written; the source is the thin wrapper that says
which one this broker uses.

---

## 3. Carrier A — WebSocket carrier (`transport/wscarrier`, implemented)

Goal: collapse the node to **one** outbound TCP connection to a public HTTPS
endpoint, which many networks permit even when arbitrary outbound TCP is blocked.
Because the inside CCB opens exactly one WebSocket and yamux-muxes everything over
it, one connection already carries the node's entire CCB footprint — so a plain
HTTP/1.1 `Upgrade` suffices; HTTP/2 (RFC 8441) is an optional future refinement,
not a requirement.

- **Server** (`wscarrier.Listen`): the outside CCB serves an HTTP(S) endpoint
  (`wss://host:port/ccb/tunnel`) on a port distinct from its CEDAR port. Each
  authenticated WebSocket upgrade becomes one carrier byte-pipe (`websocket.NetConn`
  over binary messages), presented via a `net.Listener` so `carrier.MuxListener`
  and the cedar command loop run over it unchanged.
- **Client** (`wscarrier.Dial`): the inside CCB dials the URL with a bearer token,
  holds the socket open, and `carrier.MuxDialer` runs a yamux client over it;
  `Open()` per `dialBroker`. Selected by a `ws://`/`wss://` scheme on
  `Upstream.BrokerAddr` / `OutboundNextHop`.
- **Auth**: selected by `CCB_CARRIER_AUTH` (`token`, the default, or `none`).
  See [CARRIER_AUTH.md](CARRIER_AUTH.md) for the threat model and the evidence
  behind the two modes.

  With `none` the upgrade carries no credential in either direction, and the
  peer's identity comes from the CEDAR handshake on its first command — which
  never puts a credential on the wire, because CEDAR's TOKEN method transmits
  only `header.payload` and keeps the JWT signature as the AKEP2 shared secret.
  That is the identity every authorization decision already used: the identity
  the upgrade verified was computed and discarded. The mode exists because a
  TLS-intercepting proxy reads the `Authorization` header in plaintext, and an
  IDTOKEN there is a reusable pool credential in the proxy's hands.

  Two consequences of removing the upgrade check, both covered by §6 and §8.4
  of CARRIER_AUTH.md: the endpoint is open, so the accept path carries explicit
  limits (`CCB_CARRIER_MAX_SESSIONS`, `CCB_CARRIER_MAX_PER_SOURCE`,
  `CCB_CARRIER_PIPE_PROBATION`, plus HTTP read timeouts that apply in both
  modes); and a credential that is wrong now fails at `CCB_REGISTER` rather
  than at the dial, so the symptom of a misconfiguration moves from a 401 to a
  carrier that comes up but never registers.

  With `token` (the default — existing deployments are unaffected) a bearer
  token rides the `Authorization` header of the upgrade request. The transport
  is credential-agnostic — a `TokenVerifier` (server) and token string /
  `TokenSource` (client) are supplied by the CCB layer. `ccbserver` ships:
  - `DiscoverBearerToken` (client): WLCG discovery — `BEARER_TOKEN`,
    `BEARER_TOKEN_FILE`, `$XDG_RUNTIME_DIR/bt_u<uid>`, `/tmp/bt_u<uid>` — then an
    HTCondor IDTOKEN from the token directory.
  - `BearerTokenVerifier(sec)` (server): accepts **either** an HTCondor IDTOKEN
    (verified against the pool signing key via cedar `security.VerifyIDToken` —
    HKDF+HMAC over `header.payload`) **or** a SciToken, dispatching on the token.
    `IDTokenVerifier(sec)` / `SciTokenVerifier(sec)` are the single-type variants.
  - A SciToken is accepted only as an HTCondor server accepts SCITOKENS
    authentication: `sec.SciTokensMapper` must map its `issuer,subject`, its
    audience must satisfy `sec.SciTokensServerAudience`, it must be current, and
    its https issuer must publish the signing key. An issuer no mapping names is
    never contacted. With no mapper, every SciToken is refused. The identity is
    the mapped user, with the UID domain appended when it has no `@`.
  The daemon wires `BearerTokenVerifier` for a `ws(s)://` `CarrierListen`,
  reading the SciToken settings as HTCondor does: the `SCITOKENS` lines of
  `CERTIFICATE_MAPFILE` (principals are regular expressions unless
  `CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS` is true; reloaded on reconfig),
  `SCITOKENS_SERVER_AUDIENCE`, `SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES` and
  `SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS`. Without a map file only IDTOKENs are
  accepted.
- **Framing**: WebSocket binary messages carry raw yamux bytes; WebSocket
  ping/pong + yamux keepalive detect a dead peer. The keepalive interval
  (`CCB_CARRIER_KEEPALIVE`, default `carrier.DefaultKeepalive` = 20s) does
  double duty: on a carrier it is also the only traffic a quiet tunnel
  produces, so it is what keeps a site proxy from reclaiming it as idle. Too
  slow fails silently -- the pipe is dropped and re-established on next use, so
  every connection still succeeds while the node spends a fresh proxy
  connection each time it goes quiet. The message read limit is lifted when a
  token is required (authenticated peer; yamux bounds its own windows) and
  bounded at 1 MiB when it is not — yamux's default stream window is 256 KiB,
  so that is ample headroom while still bounding per-connection buffers.
- **TLS**: `wss://` requires a server `CarrierTLS` and (client) `CarrierClientTLS`
  for CA roots; `ws://` is plaintext, for test/dev only.

Config knobs on the CCB `Config`: `CarrierListen` (`wss://…`), `CarrierTLS`,
`CarrierTokenVerify`, `CarrierUnauthenticated`, `CarrierMaxSessions`,
`CarrierMaxPerSource`, `CarrierPipeProbation` (server); `CarrierClientTLS`,
`CarrierToken` / `CarrierTokenSource`, `CarrierUnauthenticated`,
`CarrierProxy` (client).

A WebSocket peer has no network address of its own — `websocket.NetConn`
reports a placeholder — so host and netblock terms in `ALLOW_DAEMON` match no
carrier peer and fail closed. Carrier registrants must be admitted by an
identity term, and `peerIP` is nil for them, so reconnect IP pinning does not
apply. This is true of both auth modes.

### 3.1 Through an HTTP proxy

Many of the sites this carrier exists for permit no outbound TCP at all except
through a squid-style HTTP proxy, and only to approved destinations. The carrier
reaches such a proxy with `CONNECT`, which `http.Transport` issues only for a TLS
target -- so **a proxied carrier must be `wss://`**. A `ws://` endpoint with a
proxy configured is rejected up front rather than left to fail when the proxy
declines to relay the `Upgrade`.

| Knob | Meaning |
|---|---|
| `CCB_CARRIER_PROXY` | Proxy URL (`http://squid.site:3128`, or the bare `squid.site:3128`). Unset honours `HTTPS_PROXY` / `NO_PROXY`; the literal `none` forces a direct dial. |
| `CCB_CARRIER_PROXY_CREDENTIAL_FILE` | File holding one `user:password` line, for a proxy with `proxy_auth REQUIRED`. Re-read per dial so a rotated credential is picked up; refused if world-readable. |

**The configuration wins over the environment.** A set `CCB_CARRIER_PROXY`
overrides a site `https_proxy`, and `CCB_CARRIER_PROXY = none` overrides it with
a direct dial — which is the only way to opt out of a site proxy without editing
the daemon's environment. The environment is consulted only when the knob is
unset, and is re-read per dial rather than cached for the life of the process.
Both knobs take the usual `CCB.` / `<local-name>.` prefixes.

Note that every other `*PROXY*` setting in HTCondor names an X.509 credential.
These two are an HTTP forward proxy, and nothing else in the pool reads them.

Startup logs which of the two the setting came from
(`"CCB carrier proxy configuration" source=...`), because an operator reading a
log otherwise cannot tell a deliberate override from a site environment leaking
in, and those are corrected in different files.

Two deployment constraints are worth knowing before the first attempt, because
both present as an unexplained dial failure:

- A stock `squid.conf` carries `http_access deny CONNECT !SSL_ports` with
  `acl SSL_ports port 443`, so **the outside CCB's carrier must listen on 443**
  (its CEDAR port for the pool is separate and unaffected).
- A proxy that intercepts TLS replaces the carrier's server certificate with one
  from the site CA, so `CCB_CARRIER_CA_FILE` must carry that CA. Note that an
  intercepting proxy also sees the bearer token in the upgrade request, so such a
  deployment wants a short-lived, audience-scoped token rather than a long-lived
  pool IDTOKEN.

The route taken is logged with the carrier session (`route="via
http://squid.site:3128"` or `route=direct`) and repeated in any dial error. A
carrier that silently ignored a configured proxy and went direct is otherwise
indistinguishable from a working one -- until it runs on a node that really has
no route out.

### 3.2 Health check

A carrier dial crosses four things a site's network policy can break
independently, and "dial failed" distinguishes none of them. `Server.CheckCarrier`
walks them in order and reports each separately:

| Stage | What a failure means |
|---|---|
| `tcp-reachable` | the proxy (or, direct, the endpoint) cannot be reached at all |
| `proxy-connect` | the proxy refuses to tunnel here: destination ACL, port policy (403), or required authentication (407) |
| `tls` | the handshake failed; the reported issuer tells an intercepting proxy apart from a misconfiguration |
| `websocket-upgrade` | the far broker rejected the bearer token |
| `far-broker-cedar` | the far end answered but is not the expected broker, or the two disagree on credentials |

The last stage is the one no amount of WebSocket success implies: it runs a CEDAR
handshake to the broker at the far end. A peer that completes the handshake and
then reports it has no `DC_NOP` handler counts as a pass -- identity and policy
are what the stage checks.

The broker runs the check at startup, before reporting itself ready, and logs
the report; it is never fatal, since the proxy may be transiently down and the
broker retries anyway. What protects an EP meanwhile is that an inside CCB
refuses to register one until it is tunnel-ready, rather than handing out an
address the pool cannot reach. `htc-ccb -carrier-check` prints the same
per-stage report and exits non-zero, as a diagnostic to run by hand.

---

## 4. Carrier B — Filesystem tunnel (detailed)

No sockets between the brokers. They rendezvous through a shared directory with
**NFS-like semantics**: reliable eventual visibility of appended bytes and created
files, *no* cross-client atomic append, *no* reliable change notification (so we
poll), and possibly *partial* visibility of a just-appended tail. The protocol is
designed around exactly those constraints.

### 4.1 Directory layout

```
<root>/                       # owned by the outside CCB (acceptor)
  .doorbell                   # single file; initiators bump its mtime on arrival
  inbox/                      # small: one empty marker per not-yet-engaged tunnel
    <conn-id>                 #   named after the conn-id; acceptor removes on pickup
  <ab>/                       # hashed fan-out: first 2 hex chars of the conn-id
    <cdef...>/                # rest of the conn-id -> one byte-pipe (one tunnel)
      c2s/                    # initiator→acceptor direction (client→server)
        000000.seg            # append-only segment, rolled at SegmentSize (128MiB)
        000001.seg
      s2c/                    # acceptor→initiator direction (server→client)
        000000.seg
```

The conn-id is a random unguessable token; hashing it into `<ab>/<cdef…>` fans the
work tree over up to 256 directories so none accumulates every tunnel (some
filesystems degrade with huge single-directory entry counts). The acceptor never
lists the work tree except once at startup (§4.1.1), so the fan-out exists purely
to bound per-directory size, not to speed a scan.

**Single writer per file.** The initiator only ever appends to `c2s/`; the
acceptor only ever appends to `s2c/`. This sidesteps NFS's lack of atomic
concurrent append — no file ever has two writers. ACKs for a direction are
*piggybacked* into the opposite direction's file (the reader of `c2s` is the
writer of `s2c`), so control still flows both ways with single-writer files.

#### 4.1.1 Arrival signalling — the doorbell

Listing the work tree on NFS is expensive, and doing it on a tight loop to spot
new initiators does not scale. Discovery is therefore two cheap levels — a
doorbell and an inbox — and the work tree is listed **only once, at startup**.

After creating its subtree and writing its SYN, the initiator (1) drops an empty
marker `<root>/inbox/<conn-id>` (O_TRUNC create, then fsync the inbox directory so
the entry reaches the server), and (2) **rings the doorbell** — bumps the mtime of
a single `<root>/.doorbell` file with one atomic `Chtimes` (`SETATTR`). The
acceptor watches only that one doorbell file's mtime with a cheap `stat`
aggressively (data-path poll interval); a change triggers a `readdir` of the
**inbox** — which is small, holding only markers not yet engaged. For each marker
the acceptor resolves the hashed work path `connPath(<conn-id>)`, and once the
initiator's `c2s` SYN segment is visible it engages the tunnel and removes the
marker (the acceptor owns inbox cleanup). A slow inbox scan every **30 s** is the
guaranteed backstop; the work tree itself is read only by the one-time startup
scan that re-engages tunnels that predate a restart.

*Does this race?* Yes, benignly. NFS may surface metadata **out of order** — the
acceptor can see the inbox marker before the initiator's work subtree (or before
its `c2s` SYN segment) is visible, since close-to-open only guarantees freshness
at open and the directory attribute cache may not have expired. So the acceptor
does **not** assume the work subtree is present when a marker appears: if
`connPath(<conn-id>)/c2s/000000.seg` does not yet resolve, the marker is left in
place and retried on the next scan. A ring triggers several **follow-up rescans**,
and the 30 s inbox scan is the hard backstop, so a marker whose subtree is briefly
invisible is *retried*, never lost. The marker is removed only once the tunnel is
engaged (or by the initiator's own cleanup on a failed dial, or the age-sweep for
orphans). Prompt detection also depends on the mount's attribute-cache timeouts
(`actimeo`); the backstop makes correctness independent of them. The acceptor
never prunes its "seen" set from a listing (a transiently-stale view could
otherwise cause a double-accept); entries are forgotten only when a tunnel is
reaped or fails its handshake.

*Why `Chtimes`, not append or `truncate`?* The doorbell is shared by *many*
initiators (one outside CCB serves many inside CCBs), so the ring op must be safe
under concurrent writers. `O_APPEND` on NFS is **TOCTOU** — the client reads the
size then writes at that offset, so concurrent appenders clobber each other and a
stale-small cached size can even make a write land mid-file, so size is *not*
reliably monotonic. `truncate` only signals via a size change, so it must either
grow monotonically (append with extra steps, same race) or return to a prior size
(the `SETATTR` may be elided and is undetectable between samples). `Chtimes` is a
single atomic `SETATTR`: no read-modify-write, no growth, no torn content. Its
weaknesses are benign because the doorbell is only a *hint* — correctness is the
authoritative `readdir` plus the 30 s backstop: coarse server mtime granularity
can merge closely-spaced rings (adds latency, never loses a tunnel), and clock
skew / backward stamps still register because the acceptor compares to the *last
mtime it observed*, not to its own clock. A dedicated file is also chosen over
watching the root directory's own mtime because file attributes refresh faster by
default (`acregmin` ~3 s vs `acdirmin` ~30 s).

### 4.2 Frame format (TLV + sequence)

Every segment is a sequence of self-delimiting frames:

```
 offset  size  field
   0      1    type        (see 4.3)
   1      1    flags       (reserved, 0)
   2      8    seq         uint64, per-direction monotonic frame index (from 0)
  10      8    dataOff     uint64, cumulative DATA payload bytes BEFORE this frame
  18      4    length      uint32, payload length
  22      L    payload
 22+L     4    crc32c      over bytes [0, 22+L)
```

Header is 22 bytes; trailer is a 4-byte CRC32C (Castagnoli). The CRC + length let
the reader **detect a partial/torn tail**: if fewer than `22+length+4` bytes are
available, or the CRC fails, the frame is "not yet complete" — the reader waits
and re-reads (NFS may expose the append in pieces). Only a CRC mismatch on a frame
whose bytes are *fully* present and followed by a later valid frame is treated as
corruption (fatal).

`dataOff` makes ACK/backpressure/reaping arithmetic exact: an ACK names a
cumulative DATA byte count, independent of how frames were chunked or rolled.

### 4.3 Frame types

| type       | dir writer emits | payload                     | meaning |
|------------|------------------|-----------------------------|---------|
| `SYN`      | first frame      | version + params (seg size, window) | open this direction; params negotiated by min() |
| `DATA`     | as needed        | stream bytes                | ordered stream payload |
| `ACK`      | as needed        | uint64 cumulative DATA bytes consumed *in the opposite direction* | flow control + reap trigger |
| `HEARTBEAT`| periodic         | uint64 wall-clock nanos (debug) | liveness; also carries a fresh ACK |
| `FIN`      | last data frame  | —                           | half-close: writer will send no more DATA |
| `ERROR`    | terminal         | UTF-8 message               | abort the whole pipe with a reason |
| `ROLL`     | last in a segment| uint32 next segment index   | "continue reading in NNNNNN.seg" |

Every non-DATA frame still advances `seq`; `ACK`/`HEARTBEAT` do not advance
`dataOff`. `HEARTBEAT` and `ACK` are written opportunistically by the same single
writer, so the reader sees a single ordered stream per direction.

### 4.4 Establishment (SYN)

1. Initiator creates `root/<conn-id>/c2s/` and appends `SYN` to `c2s/000000.seg`.
2. Acceptor's `Listen` loop polls `root/` for new subdirectories. On seeing
   `<conn-id>/`, it opens `c2s` for reading, reads the `SYN`, creates
   `<conn-id>/s2c/` and appends its own `SYN` to `s2c/000000.seg`.
3. Initiator polls `s2c/000000.seg`, reads the acceptor's `SYN`.
4. Both sides have exchanged `SYN` ⇒ the pipe is **ESTABLISHED**; params are the
   element-wise `min` of the two SYNs. If either side sees no peer `SYN` within
   `HandshakeTimeout`, it `ERROR`s / abandons the subdir.

### 4.5 Flow control & backpressure

Sliding window, TCP-like, in DATA bytes:

- Writer tracks `sent` (cumulative DATA bytes written) and `peerAck` (highest ACK
  received from the reader). It **blocks** a `Write` when
  `sent - peerAck >= Window` (default 8 MiB), until an ACK advances `peerAck` or
  the write deadline fires. This is the "refuse to write when more than a threshold
  of unacked data is outstanding" requirement.
- Reader emits an `ACK` (piggybacked into its own write direction) at least every
  `Window/4` bytes consumed, and on a timer, and on FIN. The ACK's value is the
  reader's cumulative consumed `dataOff`.

This bounds on-disk backlog to ≈`Window` per direction plus one segment, so a slow
or stalled reader cannot make the writer fill the filesystem.

### 4.6 Segment rotation & reaping

- **Rotate**: when the current segment would exceed `SegmentSize` (128 MiB), the
  writer appends a `ROLL{next}` frame and starts `NNNNNN+1.seg`. `ROLL` is the
  only way the reader advances files — it never guesses from size, so a
  mid-rotation NFS view is unambiguous.
- **Reap**: the writer records each *closed* segment's ending `dataOff`. When a
  received ACK ≥ that value (the reader has consumed the whole segment) the writer
  `unlink`s it. Single-owner deletion (the writer removes only its own direction's
  files) avoids racing the reader. The current segment is never reaped.
- **Teardown / GC**: the acceptor owns the root, so it is responsible for reaping
  a tunnel's subtree. Each pipe exposes `Done()`, closed when the pipe is terminal
  for *any* reason — a clean `Close` (both sides finished), a peer `ERROR`, or an
  idle/heartbeat/ACK timeout (a FIN half-close is **not** terminal). The acceptor
  removes the `<conn-id>/` subtree as soon as its pipe's `Done()` fires. The
  *initiator* cleans up its own subtree if a dial never establishes (handshake
  timeout / error) — the acceptor never engaged it, so ownership stays with the
  initiator for that case. A re-dial always uses a fresh random conn-id, so a
  reaped-then-reconnecting client never collides.
- **Age-sweep** (crash residue): the two cases the above does not cover are an
  orphaned inbox marker (a client that died after dropping the marker but before
  its work subtree became visible, so it is never engaged) and a stale work
  subtree (a partial/abandoned handshake, or one both of whose peers died). An
  infrequent acceptor sweep (`AgeSweepInterval`, default 10 m — the *only* routine
  walk of the work tree) removes any inbox marker or work subtree that is not
  engaged (not in `seen`) and has had no activity for `AgeSweepThreshold`
  (default 15 m). The threshold comfortably exceeds how idle a live tunnel can
  look, and an engaged tunnel is skipped (it is reaped via `Done()` instead), so
  neither an in-flight nor a live-but-quiet tunnel is ever swept. Last activity is
  the newest mtime among a subtree's segment files and direction directories (the
  directories are the fallback so a freshly-created empty subtree reads as recent).

### 4.7 Reader loop (polling)

Read frames from the current segment at the last read offset while a *complete*
frame is available (4.2). On a partial tail or EOF, wait and retry with an
**adaptive backoff**: `PollInterval` after the last new data (default 10 ms),
doubling on each empty check (20, 40, … ms) up to `PollMax` (default 320 ms),
then holding at `PollMax`; any new frame snaps the wait back to `PollInterval`.
On `ROLL`, open the next segment (waiting for it to appear) and continue. On
`FIN`, mark the recv side closed. On `ERROR`, fail the pipe.

On a **network filesystem** (§4.8) each empty check first reopens the segment
**close-to-open** — closing and re-opening forces a fresh `GETATTR`, so the
subsequent `stat`/`read` observe the server's current size and bytes rather than a
stale client attribute/data cache. On a local FS the fd is kept open (the page
cache is already coherent), so the backoff is pure sleeping.

### 4.8 Filesystem-mode detection

The fsync-batching (below) and close-to-open reads matter only on a filesystem
without coherent cross-host caching. fstun detects this once, on the root: on
Linux via `statfs` f_type against a set of network magics (NFS, Lustre, CephFS,
SMB/CIFS, GFS2, OCFS2, GPFS, AFS, FUSE); on other OSes it assumes local.
`Config.NetworkFS` (a `*bool`) overrides detection either way. On a local FS the
carrier skips all of the fsync/reopen overhead.

### 4.9 `net.Conn` semantics

- `Read`: returns reassembled DATA payload; blocks until data, FIN (→ `io.EOF`),
  ERROR (→ that error), or the read deadline (→ timeout error).
- `Write`: frames payload as one or more `DATA` frames (chunked to a max frame
  size), appends, applies the §4.5 backpressure; respects the write deadline.
- `Close`: writes `FIN`, flushes, stops the loops; idempotent. Full close after
  both FINs lets the acceptor reap the subdir.
- `SetDeadline`/`Set{Read,Write}Deadline`: drive the loop selects.
- `LocalAddr`/`RemoteAddr`: synthetic `fstunAddr{root, connID, role}`.

Durability / visibility note: on a network FS the writer coalesces appends and
`Fsync`s them within `FlushInterval` (default 5 ms) — a Nagle-like batch, so a
burst becomes one round-trip to the server instead of one per frame — and also
fsyncs on a segment `ROLL`, on `Close` (flushing the `FIN`), and immediately for
the `SYN` (`syncNow`). On a local FS it does not fsync at all (a peer sees writes
through the shared page cache; `Sync` opts into per-append fsync only for crash
durability). A frame is only "real" to the reader once its bytes (and CRC) are
visible, and torn tails are tolerated (4.2), so no cross-host locking or atomic
rename is required on the data path — only the append-only + single-writer
discipline.

### 4.10 Failure modes

- **Slow/dead reader**: backpressure stalls the writer (bounded backlog); heartbeat
  gap → the writer `ERROR`s/closes after `IdleTimeout`.
- **Partial NFS visibility**: tolerated by the CRC/length framing (4.2).
- **Crash**: stale subdir reaped by age; yamux keepalive tears down half-open
  logical streams above.
- **Clock skew**: heartbeat payload timestamps are debug-only; liveness is measured
  locally (time since last frame observed), not by comparing peer clocks.

---

## 5. Carrier C — command and stdio carriers (`transport/cmdcarrier`, implemented)

The carriers above each speak a protocol of their own. This one speaks none: it
runs a command and takes the child's **stdin and stdout** as the pipe. What the
command is, is the operator's business.

```
CCB_OUTBOUND_NEXT_HOP = cmd:ssh -W outside-ccb.example.org:9700 bastion.site.edu
CCB_OUTBOUND_NEXT_HOP = cmd:ssh bastion.site.edu htc-ccb -carrier-stdio
CCB_OUTBOUND_NEXT_HOP = cmd:kubectl exec -i ccb-relay -- htc-ccb -carrier-stdio
```

The point is not SSH specifically. It is that an SSH carrier implemented against
`golang.org/x/crypto/ssh` would reimplement `ssh_config` badly — no `ProxyJump`,
no `ControlMaster`, no GSSAPI, no certificates, no agent, no `Match` blocks — and
sites want exactly those. Running the system `ssh` gets all of it for free, from
people who already know how to configure it, and the same mechanism reaches a
container or a site's bespoke gateway wrapper without another transport package.

Two properties come with SSH that no other carrier here has. A site middlebox
cannot transparently interpose on it: host-key pinning is the whole point of the
protocol, where a TLS-intercepting proxy reads a WebSocket carrier's bearer token
in plaintext (§3, and `CARRIER_AUTH.md` §6). And the credentials already exist at
the sites that need this. What it costs in exchange is a Unix account and an
`authorized_keys` entry per inside broker, where a WebSocket carrier needs only a
URL and a token the node already had.

### 5.1 The command is not run through a shell

The command line is everything after `cmd:` in `CCB_OUTBOUND_NEXT_HOP` or
`CCB_CARRIER_LISTEN`. It is split with shell-like quoting — single quotes
literal, double quotes literal but for `\"` and `\\`, backslash escapes outside
quotes — and then executed directly. There is no shell, so no variable
expansion, no globbing, no pipelines, no redirection.

An **unquoted** shell metacharacter is refused rather than passed through as a
literal argument, because treating it as one is never what the operator meant:

```
cmd:ssh host htc-ccb | tee log
                     ^ refused: the command is executed directly, not through a
                       shell, so shell syntax does not work here
```

Quote it and it is kept, so a genuine argument containing one is still
expressible: `cmd:ssh -o 'ProxyCommand=nc -X 5 -x proxy:1080 %h %p' host`.

`argv[0]` is resolved against `PATH` when it names no directory, and the resolved
absolute path is logged. On a broker running as root that makes `PATH` part of a
security decision, so prefer an absolute path.

### 5.2 Why the child's stderr is kept

Starting the child is not the same as the carrier working. `ssh` takes seconds
to authenticate and, when it fails, says so on stderr and exits — so the carrier
dies as a bare EOF on a pipe, which says nothing at all. The carrier therefore
retains the child's most recent stderr lines and attaches them, with its exit
status, to the error:

```
carrier command "ssh bastion htc-ccb -carrier-stdio" exited (exit status 255);
its last output was: Permission denied (publickey).: EOF
```

Each line is also logged at debug level as it arrives, so a chatty-but-working
`ssh` ("Warning: Permanently added …") leaves steady state quiet while remaining
available. The staged carrier check (`-carrier-check`) reports it the same way.

### 5.3 The far end: `stdio:`

```
CCB_OUTBOUND_NEXT_HOP = stdio:        equivalently, htc-ccb -carrier-stdio
CCB_CARRIER_LISTEN    = stdio:
```

A broker started as the far end of a `cmd:` carrier takes **its own** stdin and
stdout as the pipe. Three things happen when it does, each closing a way the
carrier would otherwise break:

- The descriptors are duplicated and **fd 1 is pointed at fd 2**. The pipe carries
  a framed protocol, so one stray write to stdout — a library's `fmt.Println`, a
  panic trace — would corrupt it, surfacing as an unintelligible yamux error at
  the other end. After the redirect a stray write lands in the log instead. The
  daemon claims the descriptors before it loads config or starts logging, so the
  window in which anything could write is as close to empty as it can be.
- fd 0 is pointed at `/dev/null`, so nothing that reads stdin can steal carrier
  bytes.
- The duplicates are made non-blocking when they are pipes or sockets, which makes
  them pollable and so able to take deadlines. A terminal is left alone:
  `O_NONBLOCK` lives on the open file description, shared with everything else
  that has the terminal open. Nothing in the stack requires pipe deadlines —
  yamux implements deadlines on its own streams and never sets one on the
  underlying pipe — so this is a nicety, not a requirement.

A stdio carrier has **exactly one** pipe and can never obtain another. When it
closes, the broker has no route to the pool and the pool has no route to it, so
it shuts down rather than idling unreachably (`Server.CarrierExhausted`). Every
other carrier is re-established on demand, so only this one can reach that state.

### 5.4 Raw TCP pipes (`transport/tcpcarrier`)

A relayed carrier needs somewhere to land. `ssh -W broker:9700 bastion` hands the
inside broker a byte stream with nothing of ours on the bastion — but the outside
broker's CEDAR port cannot accept it, because that port expects one CEDAR
connection per socket, not a multiplexed carrier. Hence:

```
CCB_CARRIER_LISTEN = tcp://:9700          outside broker
```

`tcp://host:port` is a **raw carrier pipe**, not the broker's CEDAR port; a bare
`host:port` still means ordinary CEDAR and is not a carrier at all. The same
endpoint is what `ssh -L`, `kubectl port-forward` and `socat` deliver, and it is
the simplest fixture for testing everything layered above a pipe.

It authenticates nobody. That is the posture of `CCB_CARRIER_AUTH = none` and
rests on the same argument (`CARRIER_AUTH.md` §6): the identity behind every
authorization decision comes from the CEDAR handshake on the first command, not
from the transport. What the transport must still do is bound what an
unauthenticated peer can consume — `carrier.LimitListener`
(`CCB_CARRIER_MAX_SESSIONS`, `CCB_CARRIER_MAX_PER_SOURCE`) plus `MuxListener`'s
first-stream probation. Unlike the WebSocket carrier there is no TLS, so this
endpoint belongs inside something that provides confidentiality — an SSH tunnel,
a VPN, a loopback address. `Listen` says so when the bind address is not
loopback.

### 5.5 Direction is not role

Every carrier before this one welded two choices together: the inside broker
dialed, the outside broker accepted. A command carrier separates them, because
the useful topologies need both halves of the cross-product.

```
                       obtains its pipe by …
                   dialing / spawning        accepting
inside broker   │ ws, fs, tcp, cmd        │ stdio                    │
outside broker  │ cmd                     │ ws, fs, tcp, stdio       │
```

The new cell is the bottom-left, and it is the one the restrictive sites need:
the **outside** broker reaches into a network it cannot dial into by running
`ssh login-node htc-ccb -carrier-stdio`, and the broker that starts there plays
the **inside** role over the very same pipe. Nobody dials the inside broker and
the inside broker dials nobody; the carrier is a process the outside broker
started. (It is also the shape that lets the outside broker stage the binary and
control its startup, once an embedded SSH client replaces the system one.)

`transport/carrier` carries the split:

- `PipeSource` yields pipes — `Dialing` (a fresh pipe per call), `Accepting` (from
  a `net.Listener`), `OnePipe` (the inherited one).
- `SourceListener` presents any source as a `net.Listener`, so the outside role
  runs over a dialing source unchanged.

Which role a broker plays is still decided by **which knob** the address appears
in — `Upstream.BrokerAddr`/`CCB_OUTBOUND_NEXT_HOP` for inside, `CCB_CARRIER_LISTEN`
for outside — so no new knob was needed for any of this.

Two details `SourceListener` has to get right:

- **One pipe at a time.** `MuxListener` accepts pipes in a loop, so an outside
  broker on `cmd:ssh node htc-ccb` would spawn a second `ssh` the instant the
  first pipe was handed over, and keep going. A listener over a *dialing* source
  holds one pipe and obtains the next only once that one closes. A listener over
  an accepting source must not do this: there, many pipes at once is the point.
- **Retry inside `Accept`.** `MuxListener` stops accepting on the first error its
  inner listener returns, so a bastion that is briefly unreachable must not
  surface as one — the outside broker would give up permanently on the first
  blip. `Accept` retries with backoff (default 1s → 60s, jittered) and returns an
  error only once closed or exhausted.

### 5.6 Configuration

| Knob | Meaning |
|---|---|
| `CCB_CARRIER_COMMAND_ENV` | `NAME=VALUE` entries added to the child's environment. Unset, the child inherits the broker's — which is what lets `ssh` find `HOME` (and so `~/.ssh/config` and known-hosts), `SSH_AUTH_SOCK` and `KRB5CCNAME`. |
| `CCB_CARRIER_COMMAND_DIR` | The child's working directory; unset means the broker's own. |
| `CCB_CARRIER_COMMAND_GRACE` | Seconds a closing carrier gives the child after `SIGTERM` before `SIGKILL` (default 2). The pipes are closed first, so a well-behaved `ssh` already has EOF on stdin and is leaving anyway. |
| `CCB_CARRIER_RETRY_INITIAL` | Seconds before an outside broker retries a carrier it obtains by reaching out (default 1). |
| `CCB_CARRIER_RETRY_MAX` | Ceiling on that backoff, in seconds (default 60). A carrier that is failing is usually failing for a reason that will not clear in a second, and a broker spawning an `ssh` per second against a site's bastion looks like an attack. |

The child runs in its own process group, so a terminate aimed at the group
reaches whatever `ssh` itself spawned (an askpass helper, a `ProxyCommand`), and
a Ctrl-C in the broker's terminal does not race the broker to kill the carrier.

A command or stdio peer has no network address of its own, so — exactly as for a
WebSocket peer (§3) — host and netblock terms in `ALLOW_DAEMON` match no such
registrant and fail closed. Carrier registrants must be admitted by an identity
term, and reconnect IP pinning does not apply to them.

---

### 5.7 The far end need not be a broker

Everything above assumes the inside end of a carrier is a second CCB: it
authenticates local daemons, allocates its own CCBIDs, and registers upstream,
so it needs HTCondor configuration, credentials and an authorization policy on
the far host.

It can instead be a **splice helper** (`transport/splice`,
`cmd/htc-ccb-splice`): a byte relay that accepts local connections and copies
each onto its own stream of the carrier. It terminates nothing.

```
   inside CCB                                 splice helper

 EP --CEDAR--> inside CCB                EP ------CEDAR (end to end)------> outside CCB
                    |                       \                                  ^
                 CEDAR                       \ bytes                           |
                    v                         v                                |
               outside CCB               helper ------------ carrier ----------+
                                       (accept, copy, copy)

 contact: <outside>#42#17                contact: <outside>#P#T
          two hops, two brokers                   two ids, ONE broker
```

A client cannot tell the two apart: both give it a nested contact, both put it
on the streaming path, and in both the EP reverse-connects to whatever is on
its own side of the pipe. What differs is entirely server-side — with a helper
the outside broker owns both ids and collapses the hop locally instead of
forwarding it to a peer.

| | inside CCB | splice helper |
|---|---|---|
| far host runs | a broker: CEDAR, authz, credentials, config | `io.Copy` |
| staged payload (linux/amd64, gz) | 4.71 MiB | **1.43 MiB** |
| authorization | on the far host | at the outside broker |

Use it where the far host is one you are staging onto rather than
administering, and the inside CCB where you want the authorization boundary
near the daemons. See `SPLICE_HELPER.md` for the model, what it costs, and the
experiments behind each decision.

## 6. Package layout (`transport/fstun`)

- `frame.go` — types, header/CRC encode+decode, partial-frame detection.
- `seglog.go` — segment writer (append/rotate/reap) and reader (sequential across
  segments, partial-tail tolerant, `ROLL`-following).
- `conn.go` — the `net.Conn`: SYN handshake, DATA read/write, window backpressure,
  ACK/heartbeat emission, FIN/ERROR/close, deadlines.
- `listen.go` / `dial.go` — subdirectory discovery + `Listener`/`Dial`.
- `fstun_test.go` — loopback (same root, both roles in one process): duplex data,
  large transfer forcing rotation+reap, half-close, backpressure stall, torn-tail
  injection, deadline behaviour.

The yamux layer and the cedar dialer hook live outside this package (a thin
`carrier` adapter in htc-ccb) so `fstun` stays a self-contained,
independently-testable FS transport.

## 7. Testing plan

1. **fstun unit** — §6 loopback tests, incl. an injected torn tail and a simulated
   slow reader proving the writer stalls at ≈`Window`.
2. **yamux-over-fstun** — many concurrent streams over one pipe; bulk + ping/pong.
3. **CCB e2e** — the existing tunneling tests (inbound chain/tree, outbound,
   bandwidth, binary-chain) re-run with `CCB_OUTBOUND_NEXT_HOP = fs:<dir>`, proving
   the carrier is transparent to the relay.
4. **NFS soak** (manual) — run the e2e suite with `<root>` on a real NFS mount.
