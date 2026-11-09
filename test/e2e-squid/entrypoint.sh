#!/bin/sh
# Dispatches the two non-proxy roles of the squid end-to-end test.
set -eu

case "${1:-}" in
offsite)
    # Generate the TLS and token material both sides need, onto the shared
    # volume. The harness polls for the marker this writes last.
    e2esetup material

    cat > /tmp/condor_config <<CFG
LOG = /tmp
LOCK = /tmp
RUN = /tmp
SPOOL = /tmp
EXECUTE = /tmp
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_ENCRYPTION = OPTIONAL
SEC_DEFAULT_INTEGRITY = OPTIONAL
ALLOW_DAEMON = *
ALLOW_READ = *

# Accept tunnels from restricted nodes. 443 because a stock squid will CONNECT
# nowhere else; the pool still reaches this broker on 9618.
CCB_CARRIER_LISTEN = wss://0.0.0.0:443/ccb/tunnel
CCB_CARRIER_TLS_CERT = /shared/carrier.pem
CCB_CARRIER_TLS_KEY = /shared/carrier.key
SEC_TOKEN_POOL_SIGNING_KEY_FILE = /shared/passwords.d/POOL

# Exit for tunneled nodes' outbound connections, bounded to the offsite network.
CCB_OUTBOUND_PROXY = TRUE
# Both forms, because the allow-list matches the target host AS WRITTEN: a
# CIDR entry cannot cover a target named by hostname, and the tunneled node
# dials ccb.offsite.test by name.
CCB_OUTBOUND_TARGET_ALLOWLIST = ${OFFSITE_SUBNET:-172.31.200.0/24}, ccb.offsite.test
CFG

    # A CEDAR target the tunneled node reaches through the outbound chain.
    TARGET_ADDR=0.0.0.0:9700 e2esetup target &

    export CONDOR_CONFIG=/tmp/condor_config
    exec golang-ccb -listen 0.0.0.0:9618 -public ccb.offsite.test:9618
    ;;

harness)
    shift
    exec squid-e2e.test -test.v -test.timeout=20m "$@"
    ;;

*)
    echo "usage: entrypoint.sh <offsite|harness>" >&2
    exit 64
    ;;
esac
