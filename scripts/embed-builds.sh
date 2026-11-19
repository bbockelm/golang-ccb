#!/usr/bin/env bash
# Build the per-platform htc-ccb copies that `-tags embedremote` compiles in.
#
# An htc-ccb built with that tag can stage a broker onto a host whose
# architecture it has never seen, with no directory of builds to install and
# keep in step -- which is the point of a single-file install.
#
# The cost is the binary: each copy is about 6 MB gzipped, so carrying linux
# amd64 and arm64 adds roughly 13 MB. That is why it is a tag and not the
# default.
#
# Usage:
#   scripts/embed-builds.sh                 # linux/amd64 and linux/arm64
#   PLATFORMS="linux/amd64" scripts/embed-builds.sh
#
# Then:
#   go build -tags embedremote ./cmd/htc-ccb
set -euo pipefail

cd "$(dirname "$0")/.."
out=transport/sshcarrier/remotebin/builds
mkdir -p "$out"

# Linux only by default: these are the hosts anyone stages onto. Both
# architectures, because an arm64 login node in front of an amd64 cluster (or
# the reverse) is ordinary now, and the far host is detected at dial time --
# a build that carries only one simply fails on the other, by name.
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64}"

# -s -w drops the symbol table and DWARF, taking a release build from about
# 24 MB to 16 MB. The staged binary is run, not debugged; when it misbehaves
# an operator stages their own with CCB_CARRIER_SSH_STAGE_BINARY.
LDFLAGS="${LDFLAGS:--s -w}"

for p in $PLATFORMS; do
	goos="${p%%/*}"
	goarch="${p##*/}"
	name="htc-ccb-${goos}-${goarch}"
	echo "building ${name}"
	# CGO off so the result runs on a host with any libc, which a staged
	# binary must: we do not know what is over there.
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -buildvcs=false -ldflags="$LDFLAGS" \
		-o "${out}/${name}" ./cmd/htc-ccb
	gzip -9 -f "${out}/${name}"
	ls -l "${out}/${name}.gz"
done

echo
echo "now: go build -tags embedremote ./cmd/htc-ccb"
