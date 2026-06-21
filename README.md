# golang-ccb

A standalone [HTCondor](https://htcondor.org) **Condor Connection Broker (CCB)**
server, written in Go on top of [`golang-cedar`](https://github.com/bbockelm/cedar).

CCB enables connection reversal: a daemon behind a private IP / NAT keeps a
persistent connection to a public broker; when a client wants to reach that
daemon, the broker tells the daemon to dial *back* to the client. This server is
wire-compatible with the C++ CCB protocol and additionally implements a
**streaming/proxy mode** for private↔private connections.

## Running

```sh
go run ./cmd/golang-ccb -listen :9618 -public <public-host>:9618
```

Point HTCondor daemons at it with `CCB_ADDRESS = <public-host>:9618` (and a
shared `SEC_*` configuration). They will register and become reachable through
their advertised ccb contact (`<public-host>:9618#<id>`).

## Protocol

Commands (`condor_commands.h`): `CCB_REGISTER=67`, `CCB_REQUEST=68`,
`CCB_REVERSE_CONNECT=69`, `ALIVE=441`. All control messages are a single CEDAR
message carrying one ClassAd; the reverse-connect hello is a raw command int +
ClassAd (no security handshake).

### Standard flow (public requester → private target)

1. **Register** — target authenticates (`CCB_REGISTER`) and is assigned a
   ccbid; the socket stays open. The reply also advertises `CCBStreaming=true`.
2. **Request** — client authenticates (`CCB_REQUEST`) and sends
   `{CCBID, ClaimId=<connect-id>, MyAddress=<client listen addr>}`.
3. **Forward** — broker relays the request to the target's persistent socket.
4. **Reverse-connect** — target dials `MyAddress` and sends the raw
   `CCB_REVERSE_CONNECT` hello; normal CEDAR (client = original requester) follows.
5. **Result** — target reports success/failure to the broker, which relays it.

### Streaming / proxy flow (private requester → private target)

When the requester is *also* private it cannot accept a direct reverse
connection, so it sends a CCB-routed `MyAddress` (its own ccb sinful) and
`CCBStreamingRequired=true`. The broker then:

1. registers a rendezvous keyed by the connect id and replies
   `{Result=true, ProxyMode=true}` to the requester;
2. forwards the request to the target with `MyAddress` set to the **broker's
   own** rendezvous address;
3. the target reverse-connects to the broker and sends its `CCB_REVERSE_CONNECT`
   hello;
4. the broker re-emits a hello to the requester and then **splices** the two
   sockets, acting as a transparent TCP proxy.

The end-to-end `DC_AUTHENTICATE` between the two real peers rides opaquely over
the splice, so CCB-session encryption is intentionally disabled on the proxy
data path; security is preserved end-to-end.

### Compatibility

A streaming-capable requester confirms broker support **before** sending a proxy
request — the broker's `$CondorVersion$` (exchanged in the security handshake)
must be ≥ the streaming threshold, and/or the broker advertises
`CCBStreaming=true`. If streaming is required but unsupported, the requester
fails fast (`StreamingUnsupportedError`) instead of sending a request an older
broker would mishandle. Standard CCB is unchanged in every direction.
