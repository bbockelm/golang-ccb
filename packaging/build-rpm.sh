#!/bin/sh
# Stage a prebuilt htc-ccb binary and turn it into an RPM with nfpm.
#
# Usage:
#   packaging/build-rpm.sh <binary> <arch> <version> [outdir]
#
#   binary   a linux build of cmd/htc-ccb (an RPM of a Darwin binary would
#            install and then not run, so the caller picks)
#   arch     amd64 | arm64 -- the RPM's architecture, which nfpm maps to
#            x86_64 / aarch64
#   version  a tag like v1.2.3, or a `git describe`; translated by
#            rpm-version.sh into an RPM Version and Release
#   outdir   where the .rpm lands (default: dist)
#
# Run from the repository root.
set -eu

bin="${1:?usage: build-rpm.sh <binary> <arch> <version> [outdir]}"
arch="${2:?usage: build-rpm.sh <binary> <arch> <version> [outdir]}"
version="${3:?usage: build-rpm.sh <binary> <arch> <version> [outdir]}"
outdir="${4:-dist}"

: "${NFPM:=nfpm}"
: "${PKG_MAINTAINER:=Brian Bockelman <bbockelm@morgridge.org>}"
: "${PKG_VENDOR:=htc-ccb}"

# contents.src in nfpm.yaml names this directory literally; nfpm globs that
# field without expanding variables, so the two have to agree.
stage=packaging/staging

command -v "${NFPM}" >/dev/null 2>&1 || {
	echo "nfpm not found. Build the pinned version:" >&2
	echo "  (cd .github/tools && GOWORK=off go build -o \"\$HOME/go/bin/nfpm\" github.com/goreleaser/nfpm/v2/cmd/nfpm)" >&2
	echo "or point NFPM at one you already have: NFPM=/path/to/nfpm $0 ..." >&2
	exit 1
}
test -f "${bin}" || { echo "no binary at ${bin}" >&2; exit 1; }

# A package is the worst place to discover a cgo binary: it installs, and then
# fails on a host whose glibc differs from the builder's.
packaging/check-static.sh "${bin}"

rm -rf "${stage}"
mkdir -p "${stage}"
cp "${bin}" "${stage}/htc-ccb"
chmod 0755 "${stage}/htc-ccb"

# nfpm writes --target as a FILE unless the path is an existing directory.
mkdir -p "${outdir}"

# Word splitting is the point: the script prints "<version> <release>".
# shellcheck disable=SC2046
set -- $(packaging/rpm-version.sh "${version}")
pkg_version="$1"
pkg_release="$2"

echo "Packaging ${bin} as htc-ccb ${pkg_version}-${pkg_release} (${arch})..."
PKG_VERSION="${pkg_version}" PKG_RELEASE="${pkg_release}" PKG_ARCH="${arch}" \
PKG_MAINTAINER="${PKG_MAINTAINER}" PKG_VENDOR="${PKG_VENDOR}" \
	"${NFPM}" package --config packaging/nfpm.yaml --packager rpm --target "${outdir}"

rm -rf "${stage}"
ls -1 "${outdir}"/*.rpm
