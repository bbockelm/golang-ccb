# CCB tunneling: pluggable carriers (non-TCP transports)

CCB tunneling (see the C++ tree's `CCB_TUNNELING_DESIGN.md`) routes all of a
restricted node's traffic through an **inside CCB → outside CCB** pair. Today the
inside↔outside link is TCP. This document designs two alternative *carriers* for
that one link, so a site that forbids outbound TCP entirely (or throttles live
socket counts to ~1) can still tunnel:

1. **WebSocket over HTTP/2** — a single long-lived TCP connection to an HTTPS port
   on the outside CCB, token-authenticated. (Sketch; §3.)
2. **Filesystem tunnel** — no sockets at all between the brokers: they rendezvous
   through a shared (NFS-like) directory. (Detailed; §4. The fun one.)

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
- **golang-ccb** (outside CCB): when configured with a carrier, build the carrier
  `net.Listener`, wrap each accepted byte-pipe in a `yamux.Server`, and run a
  goroutine that `Accept()`s streams and hands each to `srv.Serve` — identical to
  the TCP accept loop.

The carrier is selected by the scheme of the broker address:
`CCB_OUTBOUND_NEXT_HOP = fs:/gpfs/ccb/outbound` (filesystem) or `wss://cm.example`
(websocket). A bare `host:port` keeps TCP.

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
working deadlines and a clean `Close`. yamux is layered on top by the caller. The
carrier need not multiplex — that is yamux's job — so a carrier is "just" one
good pipe.

---

## 3. Carrier A — WebSocket over HTTP/2 (sketch)

Goal: collapse the node to **one** outbound TCP connection to a public HTTPS
endpoint, which many networks permit even when arbitrary outbound TCP is blocked.

- **Server**: the outside CCB listens on a *separate* HTTPS port (distinct from its
  CEDAR port) with a normal TLS cert. A single HTTP/2 origin means the browser/h2
  client coalesces requests onto one TCP connection; a WebSocket upgrade
  (RFC 8441 `:protocol = websocket` over h2, or h1 `Upgrade` if h2 unavailable)
  gives a bidirectional binary frame stream. Each accepted WebSocket = one carrier
  byte-pipe → `yamux.Server`.
- **Client (inside CCB)**: dial `wss://host:port/ccb/tunnel`, authenticate, hold
  the socket open; `yamux.Client` over it. `session.Open()` per `dialBroker`.
- **Auth**: bearer token in the `Authorization` header of the upgrade request.
  Reuse HTCondor token discovery — prefer an **IDTOKEN** (the pool's, via the
  existing `htcondor` token-discovery path used for `IDTOKENS` auth), else a
  **SciToken** from the standard discovery (`BEARER_TOKEN`, `BEARER_TOKEN_FILE`,
  `$XDG_RUNTIME_DIR/bt_u<uid>`, ...). The server validates the token exactly as
  CEDAR's token auth does and maps it to a DAEMON authorization decision before
  accepting the tunnel.
- **Framing**: WebSocket binary messages carry raw yamux bytes; no extra framing.
  WebSocket ping/pong + yamux keepalive detect a dead peer.
- **Why h2/single-connection matters**: the point is the *socket-count* limit, not
  bandwidth. Forcing one TCP connection means the node's entire CCB footprint —
  registration and every proxied connection — rides that one socket via yamux.

Deferred until the filesystem carrier lands; the yamux + cedar-dialer seam it
needs is shared, so it becomes mostly "implement `Dial`/`Listen` over gorilla or
`x/net/websocket` + token discovery."

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
  <conn-id>/                  # one subdirectory == one byte-pipe, created by an
                              #   inside CCB (initiator). <conn-id> is a random
                              #   unguessable token.
    c2s/                      # initiator→acceptor direction (client→server)
      000000.seg              # append-only segment, rolled at SegmentSize (128MiB)
      000001.seg
    s2c/                      # acceptor→initiator direction (server→client)
      000000.seg
```

**Single writer per file.** The initiator only ever appends to `c2s/`; the
acceptor only ever appends to `s2c/`. This sidesteps NFS's lack of atomic
concurrent append — no file ever has two writers. ACKs for a direction are
*piggybacked* into the opposite direction's file (the reader of `c2s` is the
writer of `s2c`), so control still flows both ways with single-writer files.

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
- **Teardown**: after both directions are FIN'd and drained (or on `ERROR` /
  idle-timeout), the acceptor removes the whole `<conn-id>/` subtree. A crash
  leaves at most one stale subdir, reaped by an age sweep on the root.

### 4.7 Reader loop (polling)

Open the current segment at the last read offset. Read frames while a *complete*
frame is available (4.2). On a partial tail or EOF, sleep `PollInterval`
(default 25 ms, adaptive: back off toward 100 ms when idle, snap to fast on data)
and retry. On `ROLL`, open the next segment (waiting for it to appear) and
continue. On `FIN`, mark the recv side closed. On `ERROR`, fail the pipe.
`fsnotify` is used as an *optimization* where the FS is local (snap out of the
poll sleep early); correctness never depends on it.

### 4.8 `net.Conn` semantics

- `Read`: returns reassembled DATA payload; blocks until data, FIN (→ `io.EOF`),
  ERROR (→ that error), or the read deadline (→ timeout error).
- `Write`: frames payload as one or more `DATA` frames (chunked to a max frame
  size), appends, applies the §4.5 backpressure; respects the write deadline.
- `Close`: writes `FIN`, flushes, stops the loops; idempotent. Full close after
  both FINs lets the acceptor reap the subdir.
- `SetDeadline`/`Set{Read,Write}Deadline`: drive the loop selects.
- `LocalAddr`/`RemoteAddr`: synthetic `fstunAddr{root, connID, role}`.

Durability note: the writer `Write`s and periodically `Fsync`s; a frame is only
"real" to the reader once its bytes (and CRC) are visible, and torn tails are
tolerated (4.2), so no cross-host locking or atomic rename is required on the data
path — only the append-only + single-writer discipline.

### 4.9 Failure modes

- **Slow/dead reader**: backpressure stalls the writer (bounded backlog); heartbeat
  gap → the writer `ERROR`s/closes after `IdleTimeout`.
- **Partial NFS visibility**: tolerated by the CRC/length framing (4.2).
- **Crash**: stale subdir reaped by age; yamux keepalive tears down half-open
  logical streams above.
- **Clock skew**: heartbeat payload timestamps are debug-only; liveness is measured
  locally (time since last frame observed), not by comparing peer clocks.

---

## 5. Package layout (`transport/fstun`)

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
`carrier` adapter in golang-ccb) so `fstun` stays a self-contained,
independently-testable FS transport.

## 6. Testing plan

1. **fstun unit** — §5 loopback tests, incl. an injected torn tail and a simulated
   slow reader proving the writer stalls at ≈`Window`.
2. **yamux-over-fstun** — many concurrent streams over one pipe; bulk + ping/pong.
3. **CCB e2e** — the existing tunneling tests (inbound chain/tree, outbound,
   bandwidth, binary-chain) re-run with `CCB_OUTBOUND_NEXT_HOP = fs:<dir>`, proving
   the carrier is transparent to the relay.
4. **NFS soak** (manual) — run the e2e suite with `<root>` on a real NFS mount.
