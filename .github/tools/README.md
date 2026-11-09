# CI tool pins

A module of its own, separate from the repository's, so the versions of the
binaries CI builds are recorded and verified like any other dependency without
dragging them into `golang-ccb`'s own dependency graph.

Nothing imports it. `tools.go` is behind a `tools` build tag; the imports exist
so `go.sum` has the versions and Dependabot has something to bump.

Build one:

```sh
(cd .github/tools && GOWORK=off go build -o "$HOME/go/bin/nfpm" github.com/goreleaser/nfpm/v2/cmd/nfpm)
```
