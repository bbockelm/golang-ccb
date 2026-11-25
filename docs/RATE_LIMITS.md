# Rate limits

htc-ccb limits how often each network may use the broker, how much it may
hold at once, and how much bandwidth relayed connections may use. Limits are
on by default with per-host values that a well-behaved host does not reach;
everything that depends on the size and shape of your pool is off until you
set it.

## What is limited

Every limit applies at one point in a connection's life. The earlier it
applies, the less a refused client costs the broker.

| Stage | What | Refused how |
|---|---|---|
| Accept, before anything is read | **Connections** per source, and connections still in their security handshake (**pending**) per source | Closed unread. No handshake is spent on it. |
| After the handshake, per command | **CCB_REGISTER**, **CCB_REQUEST** and **CCB_PROXY_CONNECT** rates | Queued up to `CCB_LIMIT_MAX_WAIT`; past that a request gets a failure reply that says which limit refused it, and a registration is closed. |
| While held | **Registrations** and **relayed connections** (streaming mode and outbound proxy) at once | As above. Checked before the target is asked to connect, so a refused relay costs the target nothing. |
| Per registered daemon | **Requests forwarded to it**, and requests it has not yet answered | Failure reply to the requester. This protects the daemon, not the broker. |
| Per registered daemon | **Control messages** it sends (heartbeats, results) | Never refused. The broker reads from it more slowly and TCP pushes back. |
| While relaying | **Bandwidth**, both directions together | Paced, never cut. |

Refusals are logged once as they start (`rate limit refusing`), then
summarised every minute with a count and the busiest sources
(`rate limit refusals`). A flood fills neither the log nor the disk.

## Sources, classes and scopes

A **source** is a peer address. An IPv6 source is its /64 by default, since
one host or site usually holds a whole /64 and could otherwise get a new
bucket with every address. `CCB_LIMIT_SOURCE_PREFIX_V4` and `_V6` change the
masks, for example to treat a whole NAT pool as one source.

A **network class** is a named set of networks with its own limits. A source
belongs to the class with the most specific network containing it. A source
in no class is in the default class, `DEFAULT`.

Most rates and caps exist in three scopes:

- **per source**: every source gets its own allowance;
- **per class** (`..._CLASS_...`): one allowance shared by every source in
  the class, which bounds a network however many addresses it spreads over;
- **broker-wide** (`..._TOTAL_...`): one allowance for everyone.

An operation must fit in every scope that applies to it.

A rate is a token bucket. `_RATE` is the sustained rate per second, and
`_BURST` is how many may go at once after a quiet spell. Setting a `_RATE`
without its `_BURST` gives a burst of one second's worth, not the burst it
replaced. 0 means no limit, for rates and caps alike.

## Defaults

| Limit | Default | Why |
|---|---|---|
| Connections per source | 50/s, burst 500 | An access point asking for dozens of execute points a second stays under it. A client stuck reconnecting in a loop does not. |
| Pending handshakes per source | 256 | Without it one source can take all 4096 of the broker's pending slots and lock everyone else out. |
| Registrations per source | 5/s, burst 100 | A host registers a handful of daemons. A NAT with a thousand behind it gets through a broker restart in a few minutes rather than all at once. |
| Requests per source | 50/s, burst 500 | Same reasoning as connections; every request is one. |
| Outbound proxy requests per source | 20/s, burst 200 | |
| Requests forwarded to one daemon | 20/s, burst 200 | Higher than any startd's legitimate rate of incoming connections. |
| Unanswered requests to one daemon | 100 | |
| Control messages from one daemon | 50/s, burst 500 | Heartbeats come every 20 minutes and results one per request, so only a broken daemon reaches it. |
| Relayed connections, broker-wide | descriptor limit ÷ 4 | A relay holds two descriptors. This leaves half the descriptors for registrations and new connections, so a relay flood cannot stop the broker accepting. |
| Queue wait | 5 s | Smooths a burst into the configured rate instead of refusing most of it. |
| Everything else | unlimited | Class-wide and broker-wide rates, registration and relay caps, and bandwidth all depend on your pool. Thousands of daemons behind one NAT, or a private schedd whose every shadow is relayed, are both legitimate. |

Loopback sources are exempt, as the local `condor_master` and tools are; set
`CCB_LIMIT_LOOPBACK = true` to limit them too. Connections that arrive over a
carrier (`CCB_CARRIER_LISTEN`) count against their class and the broker-wide
limits but not a per-source one, because one carrier fronts a whole cluster.
Connections an inside broker receives through its own upstream registration
are exempt: the outside broker already limited whoever made them. On the
outside broker, the per-daemon (`TARGET_*`) limits do not apply to requests
routed through an inside broker; the inside broker applies them to the daemon
it relays to.

An inside broker that registers with the outside one over plain TCP rather
than a carrier is an ordinary source there, and it reverse-connects to the
outside broker once for every connection into its cluster. Put its address in
a class with connection, pending and relay limits sized for the whole cluster.

`htc-ccb` logs the policy in force at startup and after every reconfig, one
line per class. A reconfig whose limits do not parse keeps the previous
policy and logs why.

## Examples

### Offsite clients get less

```
CCB_LIMIT_CLASSES = OFFSITE CAMPUS

# Everything that is not campus.
CCB_LIMIT_OFFSITE_NETWORKS = 0.0.0.0/0, ::/0
CCB_LIMIT_OFFSITE_CONNECT_RATE = 10
CCB_LIMIT_OFFSITE_CONNECT_BURST = 100
CCB_LIMIT_OFFSITE_REGISTER_RATE = 1
CCB_LIMIT_OFFSITE_REGISTER_BURST = 20
CCB_LIMIT_OFFSITE_REQUEST_RATE = 5
CCB_LIMIT_OFFSITE_REQUEST_BURST = 50
CCB_LIMIT_OFFSITE_MAX_PENDING = 32
# All offsite sources together.
CCB_LIMIT_OFFSITE_REGISTER_CLASS_RATE = 50
CCB_LIMIT_OFFSITE_REGISTER_CLASS_BURST = 500
CCB_LIMIT_OFFSITE_MAX_REGISTRATIONS_CLASS = 20000

# Campus, including the access points, is not limited per source.
CCB_LIMIT_CAMPUS_NETWORKS = 10.0.0.0/8, 192.0.2.0/24, 2001:db8::/32
CCB_LIMIT_CAMPUS_CONNECT_RATE = 0
CCB_LIMIT_CAMPUS_REQUEST_RATE = 0
CCB_LIMIT_CAMPUS_MAX_PENDING = 0
```

`OFFSITE` covers everything, but `CAMPUS` is more specific, so campus
addresses land in `CAMPUS`. Every limit a class does not set comes from the
default class.

### Streaming: a bandwidth budget for the broker and for one site

```
# The broker relays at most 2 GB/s in all.
CCB_LIMIT_BANDWIDTH_TOTAL_RATE = 2G

CCB_LIMIT_CLASSES = REMOTE_SITE
CCB_LIMIT_REMOTE_SITE_NETWORKS = 198.51.100.0/24
# The site's whole link: 100 MB/s across all its relays.
CCB_LIMIT_REMOTE_SITE_BANDWIDTH_CLASS_RATE = 100M
# No one relay may take more than 20 MB/s of it.
CCB_LIMIT_REMOTE_SITE_BANDWIDTH_SPLICE_RATE = 20M
CCB_LIMIT_REMOTE_SITE_MAX_SPLICES_CLASS = 2000
```

A relay draws on the limits of **both** its ends: the requester's class and
the target's. A site's budget therefore holds whichever side of the relay the
site is on. For the outbound proxy, the target side is the address the broker
actually dialed. Bandwidth sizes take `K`, `M` and `G`, which are powers of
1024.

A paced relay copies in userspace. An unpaced one keeps the kernel's
zero-copy path, so leave bandwidth unlimited for networks that do not need it.

### Protecting a fragile network from the outbound proxy

```
CCB_LIMIT_CLASSES = LEGACY_CLUSTER
CCB_LIMIT_LEGACY_CLUSTER_NETWORKS = 203.0.113.0/24
CCB_LIMIT_LEGACY_CLUSTER_MAX_SPLICES_CLASS = 50
CCB_LIMIT_LEGACY_CLUSTER_TARGET_REQUEST_RATE = 2
CCB_LIMIT_LEGACY_CLUSTER_TARGET_REQUEST_BURST = 10
```

`TARGET_*` limits are chosen by the class of the registered daemon's address,
so this protects the daemons in `203.0.113.0/24` from every requester.

### Turning it all off

```
CCB_LIMIT_ENABLE = false
```

## What limits do not do

Limits decide how often and how much. They never decide **who**: refusing a
network outright is `ALLOW_*` / `DENY_*`, which htc-ccb enforces per command
as the collector's CCB does. A refused registration is retried by the
daemon's CCB client, and a refused request fails that one connection attempt.
Neither changes a daemon's CCB contact.

## Knob reference

Knobs marked *class* can also be set per class as
`CCB_LIMIT_<CLASS>_<rest>`, for example `CCB_LIMIT_OFFSITE_REQUEST_RATE`. A
class name must not make a knob name ambiguous: a class called `TARGET` would
read `CCB_LIMIT_TARGET_REQUEST_RATE` as its own, so htc-ccb refuses it.

| Knob | Scope | Meaning |
|---|---|---|
| `CCB_LIMIT_ENABLE` | | `false` turns every limit off. Default `true`. |
| `CCB_LIMIT_CLASSES` | | Network class names, letters, digits and `_`. |
| `CCB_LIMIT_<CLASS>_NETWORKS` | | The class's networks: CIDRs or single addresses. Required for each class. |
| `CCB_LIMIT_CONNECT_RATE`, `_BURST` | class | New connections per source. |
| `CCB_LIMIT_CONNECT_CLASS_RATE`, `_BURST` | class | New connections, whole class. |
| `CCB_LIMIT_CONNECT_TOTAL_RATE`, `_BURST` | | New connections, broker-wide. |
| `CCB_LIMIT_MAX_PENDING` | class | Connections per source still in their handshake. |
| `CCB_LIMIT_REGISTER_RATE`, `_BURST` | class | CCB_REGISTER per source. |
| `CCB_LIMIT_REGISTER_CLASS_RATE`, `_BURST` | class | CCB_REGISTER, whole class. |
| `CCB_LIMIT_REGISTER_TOTAL_RATE`, `_BURST` | | CCB_REGISTER, broker-wide. |
| `CCB_LIMIT_MAX_REGISTRATIONS` | class | Daemons registered at once per source. |
| `CCB_LIMIT_MAX_REGISTRATIONS_CLASS` | class | Daemons registered at once, whole class. |
| `CCB_LIMIT_MAX_REGISTRATIONS_TOTAL` | | Daemons registered at once, broker-wide. |
| `CCB_LIMIT_REQUEST_RATE`, `_BURST` | class | CCB_REQUEST per source. |
| `CCB_LIMIT_REQUEST_CLASS_RATE`, `_BURST` | class | CCB_REQUEST, whole class. |
| `CCB_LIMIT_REQUEST_TOTAL_RATE`, `_BURST` | | CCB_REQUEST, broker-wide. |
| `CCB_LIMIT_PROXY_CONNECT_RATE`, `_BURST` | class | Outbound proxy requests per source. |
| `CCB_LIMIT_PROXY_CONNECT_CLASS_RATE`, `_BURST` | class | Outbound proxy requests, whole class. |
| `CCB_LIMIT_PROXY_CONNECT_TOTAL_RATE`, `_BURST` | | Outbound proxy requests, broker-wide. |
| `CCB_LIMIT_MAX_SPLICES` | class | Relayed connections at once with an end in one source. |
| `CCB_LIMIT_MAX_SPLICES_CLASS` | class | Relayed connections at once with an end in the class. |
| `CCB_LIMIT_MAX_SPLICES_TOTAL` | | Relayed connections at once, broker-wide. Default: descriptor limit ÷ 4. |
| `CCB_LIMIT_BANDWIDTH_RATE`, `_BURST` | class | Bytes/s relayed with an end in one source. |
| `CCB_LIMIT_BANDWIDTH_CLASS_RATE`, `_BURST` | class | Bytes/s relayed with an end in the class. |
| `CCB_LIMIT_BANDWIDTH_SPLICE_RATE`, `_BURST` | class | Bytes/s for each single relay; of a relay's two ends, the lower applies. |
| `CCB_LIMIT_BANDWIDTH_TOTAL_RATE`, `_BURST` | | Bytes/s relayed, broker-wide. |
| `CCB_LIMIT_TARGET_REQUEST_RATE`, `_BURST` | class | Requests forwarded to one registered daemon, by the daemon's class. |
| `CCB_LIMIT_TARGET_MAX_PENDING_REQUESTS` | class | Requests one daemon may leave unanswered. |
| `CCB_LIMIT_TARGET_MESSAGE_RATE`, `_BURST` | class | Control messages read from one daemon. |
| `CCB_LIMIT_SOURCE_PREFIX_V4`, `_V6` | class | Bits of address that make one source. Default 32 and 64. |
| `CCB_LIMIT_MAX_WAIT` | | Seconds an operation over its rate may queue. Default 5. |
| `CCB_LIMIT_LOOPBACK` | | `true` limits loopback sources too. |
| `CCB_LIMIT_MAX_TRACKED_SOURCES` | | Per-source buckets kept per limit; beyond it, new sources share one bucket per class. Default 100000. |

Per-source buckets that have refilled are forgotten every minute, so a
broker contacted once by many addresses does not keep them all. A reconfig
refills every bucket. What sources currently hold, such as registrations and
relays, stays counted, so a lowered cap applies at once to new work without
touching what already exists.
