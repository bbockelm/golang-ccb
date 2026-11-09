#!/bin/sh
# Fail if a built golang-ccb binary was linked against C.
#
# Usage: packaging/check-static.sh <binary> [<binary>...]
#
# CGO_ENABLED=0 in a workflow's `env:` is an intention, not a result. A step
# that forgets it, a tool that resets it, a stale binary left in dist/ from an
# earlier build, or a dependency that grows a cgo-only path all produce a cgo
# binary while the variable still reads 0 everywhere you look. So this reads
# the binary instead of the environment that produced it.
#
# Why it matters here: golang-ccb is deployed onto worker nodes whose glibc is
# older than any builder's, often with no shell to diagnose it. A cgo build
# fails there at exec time with a loader error, which is a long way from the
# cause. modernc.org/sqlite is the cgo-free SQLite driver precisely so this
# stays true.
set -eu

test $# -gt 0 || { echo "usage: $0 <binary> [<binary>...]" >&2; exit 2; }

fail() {
	echo "check-static: FAIL: $1" >&2
	echo "check-static:   $2" >&2
	exit 1
}

for bin in "$@"; do
	test -f "${bin}" || fail "${bin}: no such file" \
		"Build it first, e.g. CGO_ENABLED=0 go build -o ${bin} ./cmd/golang-ccb"

	settings="$(go version -m "${bin}" 2>/dev/null || true)"
	cgo="$(printf '%s\n' "${settings}" | awk '$1 == "build" && $2 ~ /^CGO_ENABLED=/ { sub(/^CGO_ENABLED=/, "", $2); print $2; exit }')"

	case "${cgo}" in
	0) ;;
	'')
		fail "${bin}: no CGO_ENABLED build setting recorded" \
			"Not a Go binary, or stripped of its build info. \`go version -m ${bin}\` shows what is there."
		;;
	*)
		fail "${bin}: built with CGO_ENABLED=${cgo}, want 0" \
			"Set CGO_ENABLED=0 for this build. A cgo binary links the builder's libc and will not run on an older host."
		;;
	esac

	# The build setting says no cgo was compiled; being dynamically linked says
	# something pulled in an external linker anyway (-linkmode external, a
	# -extld flag, a plugin build mode). Only checkable on ELF: a Go binary on
	# macOS always links libSystem, cgo or not, so there is no static Mach-O to
	# compare against.
	magic="$(od -An -tx1 -N4 "${bin}" | tr -d ' \n')"
	if [ "${magic}" != "7f454c46" ]; then
		echo "check-static: ok ${bin} (CGO_ENABLED=0; not ELF, so no dynamic-link check)"
		continue
	fi

	if command -v readelf >/dev/null 2>&1; then
		if readelf -lW "${bin}" 2>/dev/null | grep -q 'INTERP'; then
			fail "${bin}: ELF binary has a program interpreter, so it is dynamically linked" \
				"Something linked externally despite CGO_ENABLED=0. \`readelf -lW ${bin}\` names the interpreter."
		fi
		if readelf -dW "${bin}" 2>/dev/null | grep -q 'NEEDED'; then
			fail "${bin}: ELF binary has NEEDED shared libraries" \
				"\`readelf -dW ${bin}\` lists them; a static build has none."
		fi
		echo "check-static: ok ${bin} (CGO_ENABLED=0, statically linked ELF)"
		continue
	fi

	# No binutils -- a developer cross-building on macOS, say. A dynamic ELF
	# names its loader and its libraries as literal strings; a static one has
	# neither. Weaker than reading the headers, but it is the same evidence and
	# it keeps the check running off the CI runner rather than quietly skipping.
	if LC_ALL=C grep -aq -e '/ld-linux' -e '/ld64\.so' -e '/ld-musl' "${bin}"; then
		fail "${bin}: ELF binary names a dynamic loader, so it is dynamically linked" \
			"Something linked externally despite CGO_ENABLED=0. Install binutils and run \`readelf -lW ${bin}\` for the detail."
	fi
	if LC_ALL=C grep -aq -e 'libc\.so\.' -e 'libpthread\.so\.' "${bin}"; then
		fail "${bin}: ELF binary names a shared C library" \
			"Something linked externally despite CGO_ENABLED=0. Install binutils and run \`readelf -dW ${bin}\` for the detail."
	fi

	echo "check-static: ok ${bin} (CGO_ENABLED=0, no dynamic loader in the ELF; readelf absent, so this was the string check)"
done
