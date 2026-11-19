#!/usr/bin/env bash
# Build the per-platform binaries that `-tags embedremote` compiles in, and
# that CCB_CARRIER_SSH_STAGE_BINARY_DIR can hold.
#
# What it builds is htc-ccb-relay, not htc-ccb: the relay is the same broker
# with the parts a staged process cannot use taken out (see
# cmd/htc-ccb-relay), and it is what should cross an SSH session.
#
# Usage:
#   scripts/embed-builds.sh                 # linux/amd64 and linux/arm64
#   PLATFORMS="linux/amd64" scripts/embed-builds.sh
#   OUT=/usr/share/htc-ccb/remote scripts/embed-builds.sh   # for the dir knob
#
# Then, for the compiled-in variant:
#   go build -tags embedremote ./cmd/htc-ccb
set -euo pipefail

cd "$(dirname "$0")/.."
out="${OUT:-transport/sshcarrier/remotebin/builds}"
mkdir -p "$out"

# Two destinations with different rules: the embed directory is compiled in
# (gzipped, and the host platform is redundant there), a directory named by
# CCB_CARRIER_SSH_STAGE_BINARY_DIR is read at runtime (plain, and every
# platform the fleet has is wanted).
embedding=no
if [ "$out" = "transport/sshcarrier/remotebin/builds" ]; then
	embedding=yes
fi

# Linux only by default: these are the hosts anyone stages onto. Both
# architectures, because an arm64 login node in front of an amd64 cluster (or
# the reverse) is ordinary now, and the far host is detected at dial time -- a
# build that carries only one simply fails on the other, by name.
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64}"

# A broker never needs to carry a copy of its own platform: it stages the
# binary it is running (see remotebin.self). So when these builds are being
# embedded, the platform the final htc-ccb is FOR is skipped -- which for the
# usual linux/amd64 release means only linux/arm64 is carried, halving what
# the tag costs.
#
# SELF names that platform; it defaults to what `go env` would build now.
# Set SELF= to carry every platform (useful when one binary is embedded into
# releases for several).
SELF="${SELF-$(go env GOOS)/$(go env GOARCH)}"

# -s -w drops the symbol table and DWARF. The staged binary is run, not
# debugged; when it misbehaves an operator stages their own with
# CCB_CARRIER_SSH_STAGE_BINARY.
LDFLAGS="${LDFLAGS:--s -w}"

# condor_nosqlite leaves golang-htcondor's SQLite session store out of the
# daemon framework. The relay has no use for it -- see its package comment --
# and it is most of the difference in size.
# ${TAGS-...} and not ${TAGS:-...}: the colon form substitutes for an empty
# value too, so `TAGS= scripts/embed-builds.sh` -- the documented way to opt
# out -- would silently build with the tag anyway.
TAGS="${TAGS-condor_nosqlite}"

# Whether the tag did anything is not visible in the binary's behaviour, only
# in its size, so check the dependency directly. A golang-htcondor older than
# the one that introduced the tag ignores it silently: the build succeeds, the
# relay works, and it is 4 MB bigger than it should be for no stated reason.
check_no_sqlite() {
	local goos="$1" goarch="$2" n
	n=$(GOOS="$goos" GOARCH="$goarch" go list -tags "$TAGS" -deps ./cmd/htc-ccb-relay \
		| grep -cE 'modernc.org|glebarez|goose' || true)
	if [ "$n" -ne 0 ]; then
		cat >&2 <<MSG

ERROR: $n SQLite-related packages are still linked into the relay for
       ${goos}/${goarch}, although it was built with -tags ${TAGS}.

       The tag is honoured by golang-htcondor's daemon package. A version
       that predates it ignores the tag without complaint, and the result is
       a staged binary roughly 4 MB larger than it needs to be.

       Either update github.com/bbockelm/golang-htcondor to a version whose
       daemon package has sessionstore_nosqlite.go, or set TAGS= to build
       without the tag deliberately.
MSG
		return 1
	fi
}

built=0
for p in $PLATFORMS; do
	goos="${p%%/*}"
	goarch="${p##*/}"
	# Only when embedding: a directory of builds is read by whatever broker
	# is configured to use it, which need not share this platform.
	if [ "$embedding" = yes ] && [ -n "$SELF" ] && [ "$p" = "$SELF" ]; then
		echo "skipping ${p}: an htc-ccb built for it stages itself (set SELF= to carry it anyway)"
		continue
	fi
	name="htc-ccb-relay-${goos}-${goarch}"
	echo "building ${name}"
	if [ -n "$TAGS" ]; then
		check_no_sqlite "$goos" "$goarch"
	fi
	# CGO off so the result runs on a host with any libc, which a staged
	# binary must: we do not know what is over there.
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -tags "$TAGS" -trimpath -buildvcs=false -ldflags="$LDFLAGS" \
		-o "${out}/${name}" ./cmd/htc-ccb-relay
	if [ "$embedding" = yes ]; then
		# The embedded copies are gzipped; a directory of builds is not,
		# because the staging code reads those as-is.
		gzip -9 -f "${out}/${name}"
		ls -l "${out}/${name}.gz"
	else
		chmod +x "${out}/${name}"
		ls -l "${out}/${name}"
	fi
	built=$((built + 1))
done

if [ "$built" -eq 0 ]; then
	echo
	echo "nothing to build: every requested platform is this binary's own, which it stages itself."
	exit 0
fi

echo
if [ "$embedding" = yes ]; then
	echo "now: go build -tags embedremote ./cmd/htc-ccb"
else
	echo "now set: CCB_CARRIER_SSH_STAGE_BINARY_DIR = $out"
fi
