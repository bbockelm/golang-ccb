# Container tier: a tunneled EP behind a real squid

Runs the inside/outside broker pair against a **real** squid, on a worker node
that genuinely has no route off its own network.

```sh
cd test/e2e-squid
docker compose up --build --abort-on-container-exit --exit-code-from ep
docker compose down -v
```

The exit status of the `ep` service is the result.

## Why this exists

The fast tiers (`transport/wscarrier`, `carrier_proxy_e2e_test.go`) prove the
protocol using an in-process `CONNECT` proxy, and they run on every PR. They
cannot prove a *deployment*, because what decides whether a site deployment
works belongs to squid: which ports it will `CONNECT` to, which destinations it
approves, what it demands, and what it logs.

So this tier checks the things only a real proxy can answer — including whether
the health check's advice names the rule that actually fired. Advice that is
merely plausible is worse than none.

## The topology

| Service | Networks | Role |
|---|---|---|
| `offsite` | `pub` | outside broker: CEDAR on 9618, carrier on 443, plus a CEDAR target |
| `squid` | `pub`, `hpc` | the site proxy — the only container on both |
| `ep` | `hpc` | the worker node: inside broker and the test harness |

`hpc` is declared `internal`, so `ep` has no gateway and cannot resolve
`ccb.offsite.test`; name resolution happens at the proxy, inside the `CONNECT`,
as it does on a real restricted node. `TestNodeHasNoRouteOut` asserts both, and
runs first — if a direct connection ever succeeds, everything after it is
vacuous.

## What it covers

- the carrier establishing through a real proxy, every health-check stage green
- a stock `http_access deny CONNECT !SSL_ports` refusing a carrier on 9618, and
  the health check blaming the port policy for it
- a destination the site has not approved, refused
- an EP behind the node getting a contact that names the outside broker
- outbound connections relayed to an offsite target
- the whole session using **one** proxied connection, per squid's own log

## Not yet covered

A real HTCondor pool and a real job; idle survival past squid's `read_timeout`;
recovery after the proxy restarts; `proxy_auth`; a TLS-intercepting proxy.
