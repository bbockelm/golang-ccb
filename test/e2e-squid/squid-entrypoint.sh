#!/bin/sh
# Prepares squid's log directory on the shared volume so the harness container
# can read the access log, then runs squid in the foreground.
set -eu

mkdir -p /var/log/squid
chown proxy:proxy /var/log/squid
: > /var/log/squid/access.log
chown proxy:proxy /var/log/squid/access.log
chmod 0644 /var/log/squid/access.log

exec squid -N -d1 -f /etc/squid/squid.conf
