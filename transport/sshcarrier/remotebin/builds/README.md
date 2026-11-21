# Compiled-in remote builds

This directory is empty in a checkout, and it is embedded only in an htc-ccb
built with `-tags embedremote`. Fill it before such a build with gzipped
per-platform binaries named for the platform they run on:

    builds/htc-ccb-linux-amd64.gz
    builds/htc-ccb-linux-arm64.gz

`make embed-builds` produces exactly those two. Nothing here is committed: a
binary in git would be a 6 MB blob per release, and the release workflow has
the builds already.

This file exists so `//go:embed builds` has something to match in a checkout
with no builds in it. It is not a build, and the code skips anything that is
not a `.gz`.
