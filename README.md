# htc-ccb

A connection broker (CCB) for [HTCondor](https://htcondor.org): it makes
daemons behind NAT or a private network reachable from the rest of the pool. It
speaks the same wire protocol as the CCB built into `condor_collector`, runs as
a daemon under `condor_master`, and ships as a single static binary with no
dependencies of its own.

It also does something the built-in CCB does not: tunnel an execution point
that has **no outbound network at all** through one proxied connection
([below](#7-execution-points-with-no-outbound-network)).

---

## 1. Do you want this?

CCB solves one problem: a daemon on a private address cannot be dialed, so
instead it holds a connection open to a broker on a public address, and when
someone wants to reach it the broker tells it to dial *back*.

| Situation | Use |
|---|---|
| Execute nodes behind NAT, submit hosts public | a CCB — the collector's built-in one is fine |
| The same, but you want the broker off the collector's host, or scaled separately | **this** |
| Both ends private (an EP and a submit host that cannot reach each other) | the collector's CCB does this from HTCondor 26.0.0; **this** if you also want the broker off the collector's host |
| Worker nodes that may open only one or two sockets, or reach only an HTTP proxy | **this** — see [§7](#7-execution-points-with-no-outbound-network) |
| Worker nodes with no network path at all, but a shared filesystem | **this** — see [docs/TRANSPORTS.md](docs/TRANSPORTS.md) |

If the collector's built-in CCB already works for you, there is no reason to
change. What you get here is a broker you can put on its own host, restart
without restarting the collector, and point at the cases the built-in one does
not cover.

---

## 2. Install

### RPM (EL8, EL9, EL10)

Packages are attached to each [release](https://github.com/bbockelm/golang-ccb/releases).
Download the one for your architecture and install it:

```sh
VERSION=0.4.1    # the release you want; the releases page lists them
curl -LO "https://github.com/bbockelm/golang-ccb/releases/download/v${VERSION}/htc-ccb-${VERSION}-1.x86_64.rpm"
sudo dnf install ./htc-ccb-${VERSION}-1.x86_64.rpm
```

It requires the `condor` package, installs

| File | |
|---|---|
| `/usr/sbin/htc-ccb` | the daemon |
| `/etc/condor/config.d/50-htc-ccb.conf` | a sample configuration, every line commented out |
| `/usr/share/doc/htc-ccb/` | this file and the tunneling guide |

and starts nothing. Installing it changes no behaviour until you edit that
configuration file and reconfigure — a package that started a broker on install
would change the pool it was added to.

The configuration file is `%config(noreplace)`: your edits survive an upgrade,
and the new version arrives beside them as `.rpmnew`.

Verify a download against the release's `SHA256SUMS.txt`:

```sh
curl -LO "https://github.com/bbockelm/golang-ccb/releases/download/v${VERSION}/SHA256SUMS.txt"
sha256sum -c --ignore-missing SHA256SUMS.txt
```

### Prebuilt binary

For hosts you do not manage with RPMs, and for macOS. The same releases carry a
tarball per platform (`linux` and `darwin`, `amd64` and `arm64`):

```sh
VERSION=0.4.1
curl -LO "https://github.com/bbockelm/golang-ccb/releases/download/v${VERSION}/htc-ccb_v${VERSION}_linux_amd64.tar.gz"
tar xzf htc-ccb_v${VERSION}_linux_amd64.tar.gz
sudo install -m 0755 htc-ccb_v${VERSION}_linux_amd64/htc-ccb /usr/sbin/htc-ccb
```

The binary is static, so it runs on anything with a compatible
kernel regardless of the host's libc — which is the point, since the inside
broker in [§7](#7-execution-points-with-no-outbound-network) lands on worker
nodes you do not control. Each tarball also carries the sample configuration as
`htc-ccb.conf.example`.

### Container

```sh
docker build -t htc-ccb .
docker run --rm -p 9618:9618 \
  -e CONDOR_CONFIG=/etc/condor/condor_config \
  -v /etc/condor:/etc/condor:ro \
  htc-ccb -listen :9618 -public ccb.example.org:9618
```

### From source

See [docs/DEVELOPING.md](docs/DEVELOPING.md).

---

## 3. Quickstart: a broker for your pool

Three edits: the broker's own configuration, the collector's, and the private
machines'. Everything below is ordinary HTCondor configuration; there is no
second place to configure this daemon.

### 3.1 On the broker host

A public address and an open port — 9618 by default. Put this in
`/etc/condor/config.d/50-htc-ccb.conf`:

```
CCB            = /usr/sbin/htc-ccb
DAEMON_LIST    = $(DAEMON_LIST), CCB
DC_DAEMON_LIST = $(DC_DAEMON_LIST) +CCB

# -public is the address peers put in their contacts, so it must be the one
# they can reach. Not a wildcard, and not a private address.
CCB_ARGS = -listen :9618 -public ccb.example.org:9618

CCB_LOG     = $(LOG)/CcbLog
MAX_CCB_LOG = 10000000

# Registered targets keep their ccbid, and clients keep their security
# sessions, across a restart of this daemon. Without it every EP re-registers
# under a new contact after a restart.
CCB_SESSION_CACHE_FILE = $(SPOOL)/htc-ccb-sessions.db
VALID_SPOOL_FILES      = $(VALID_SPOOL_FILES) htc-ccb-sessions.db*
```

`DC_DAEMON_LIST` is what makes it a DaemonCore daemon to the master, so
`condor_reconfig` and `condor_off` reach it like any other.

The broker needs the pool's security configuration and credentials — the same
`SEC_*` settings, `SEC_PASSWORD_DIRECTORY` / `SEC_TOKEN_POOL_SIGNING_KEY_FILE`
and `TRUST_DOMAIN` as the rest of the pool. It authenticates every registration
and every request against them.

Then:

```sh
sudo condor_reconfig
```

### 3.2 On the collector

A pool wants one broker, not two. If this is now the pool's CCB, turn the
collector's own off:

```
ENABLE_CCB_SERVER = False
```

(Leave it on if you are adding this broker for a subset of machines only, and
point just those machines at it.)

### 3.3 On the private machines

Each daemon that needs to be reachable names the broker. That is the whole of
it: the daemon registers at startup and advertises a contact through it.

```
CCB_ADDRESS = ccb.example.org:9618
```

If several of these machines share a private network and should reach *each
other* directly rather than through the broker, give them a common
`PRIVATE_NETWORK_NAME`; daemons that agree on it use their private addresses
and leave the broker for everyone else.

```
PRIVATE_NETWORK_NAME = NET_EXEC
```

On the public side, the collector, negotiator and submit hosts need no CCB
configuration at all. They learn each machine's contact from its ad.

---

## 4. Check that it is working

**The daemon is up.** `CcbLog` opens with:

```
htc-ccb starting  public=ccb.example.org:9618 listen=[::]:9618 listeners=2 under_master=true
CCB server started  address=ccb.example.org:9618 listen=[::]:9618
```

If `public` is a wildcard (`0.0.0.0:9618`) there is a warning right beside it:
peers cannot dial that, and you want `-public`.

**Daemons are registering.** One line per target:

```
target registered  ccbid="ccb.example.org:9618#42" name=slot1@node042.hpc.example
```

A `register denied` warning, carrying the remote address and the reason, means
security policy rather than reachability — compare the broker's `SEC_*` and
credentials with the registering daemon's.

**The pool is routing through it.** Private machines advertise a contact naming
the broker:

```sh
condor_status -af Name MyAddress
```

A CCB-routed address carries a `ccbid=` parameter:

```
<10.4.2.19:9618?addrs=...&ccbid=ccb.example.org:9618%2342&noUDP>
```

If `ccbid=` is missing, the daemon did not register — look at *its* log, not
the broker's.

**End to end.** Run a job on a private execute node. `condor_q` reaching
completion is the whole proof; the shadow could not have reached the starter
any other way.

```sh
condor_status            # the private startd appears
condor_submit test.sub   # ... and runs something
```

---

## 5. Configuration

Every knob takes the usual HTCondor prefixes, so `CCB.CCB_SESSION_CACHE_FILE`
and `<local-name>.CCB_SESSION_CACHE_FILE` beat the bare name.

### Running it

| Knob | Default | Meaning |
|---|---|---|
| `CCB` | — | path to the binary, for `condor_master` |
| `CCB_ARGS` | — | `-listen <addr>` and `-public <host:port>` (see below) |
| `CCB_LOG`, `CCB_DEBUG`, `MAX_CCB_LOG` | `$(LOG)/CcbLog` | the usual DaemonCore logging knobs |
| `ENABLE_CCB_SERVER` | `True` | set `False` on the collector so the pool has one broker |

| Flag | Meaning |
|---|---|
| `-listen <addr>` | the public TCP port peers connect to. Under `condor_master` this is bound *in addition* to the inherited command socket |
| `-public <host:port>` | the address advertised in contacts. Defaults to the listen address, which is wrong whenever that is a wildcard or behind a NAT |
| `-carrier-check` | run the tunnel diagnostic and exit; starts no daemon ([§7](#7-execution-points-with-no-outbound-network)) |

### State and policy

| Knob | Default | Meaning |
|---|---|---|
| `CCB_SESSION_CACHE_FILE` | unset | SQLite file holding registrations and security sessions, encrypted at rest under the pool signing key. Without it both are lost on restart |
| `CCB_DIAL_REFUSE_LOCAL_ADDRESSES` | `false` | refuse reverse connects to loopback and link-local addresses. The address comes from the requester, so this is worth setting wherever the brokered daemons are not all trusted |
| `CCB_RECONNECT_ALLOWED_FROM_ANY_IP` | `false` | let a target reconnect from an address other than the one it registered from. Needed where targets legitimately move — and where they only appear to: behind a load-balanced NAT a host's source address can change between connections without the host going anywhere |

### Authorization

The broker uses the pool's own authorization levels, as the collector's CCB
does: `CCB_REGISTER` is authorized at `DAEMON`, `CCB_REQUEST` at `READ`, and
`condor_reconfig` of this daemon at `ADMINISTRATOR`
(`ALLOW_ADMINISTRATOR_CCB`). The pool's existing `ALLOW_*` settings usually
need no change.

---

## 6. Security

The broker relays bytes; it does not terminate anything. The two real peers run
their own CEDAR handshake straight through it, so authentication, integrity and
encryption are end to end and `SEC_DEFAULT_ENCRYPTION = REQUIRED` works
unchanged. A broker that is compromised can disrupt traffic. It cannot read or
forge it, and it holds no daemon's keys.

The one thing it *does* authenticate is registration and requests, against the
pool's own credentials — which is why it needs the signing key and `SEC_*`
configuration in §3.1. A rotated key or renewed certificate is picked up on
`condor_reconfig`; no restart.

---

## 7. Execution points with no outbound network

Worker nodes that cannot open outbound TCP — or may open only one or two
sockets — can still join a pool, by pairing a broker **on the node** with a
broker **beside the pool** and tunneling everything between them over a single
connection. Where the site runs an HTTP proxy, that connection is a `wss://`
tunnel through it; where it runs no network path at all, a shared filesystem
will do.

**Start here: [docs/ADMIN_TUNNELING.md](docs/ADMIN_TUNNELING.md)** — what to ask
the site for, the configuration for both brokers and the execution point, how to
verify it with `htc-ccb -carrier-check`, and what each failure means.

That diagnostic is worth knowing about before you need it. It walks the path one
layer at a time and names the layer that broke:

```sh
htc-ccb -listen 127.0.0.1:0 -carrier-check
```

```
carrier wss://ccb.example.org/ccb/tunnel (via http://squid.site.example:3128)
  ok   tcp-reachable      connected to squid.site.example:3128 (4ms)
  ok   proxy-connect      proxy tunneled to ccb.example.org:443 (31ms)
  ok   tls                TLS 1.3, subject "ccb.example.org", issuer "Example CA", expires 2027-01-04T00:00:00Z
  ok   websocket-upgrade  upgrade accepted and authenticated (44ms)
  ok   far-broker-cedar   handshake completed with ep@example.org (auth TOKEN)
```

---

## 8. Further reading

- [docs/ADMIN_TUNNELING.md](docs/ADMIN_TUNNELING.md) — running an execution
  point behind a site HTTP proxy, end to end. For administrators.
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) — how the carriers work, including
  the filesystem carrier for sites with no network path at all.
- [docs/DEVELOPING.md](docs/DEVELOPING.md) — the CCB protocol as implemented,
  building, testing, packaging. For developers.
- [docs/E2E_SQUID_WS.md](docs/E2E_SQUID_WS.md) — how the tunneled path is
  tested against a real squid. For developers.
