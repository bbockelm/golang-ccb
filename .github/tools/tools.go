//go:build tools

// Package tools pins the external binaries CI builds. It is never imported;
// the build tag keeps it out of ordinary builds while still making the import
// a real dependency, recorded in this module's go.sum and bumped by
// Dependabot -- rather than whatever `go install ...@latest` resolved to in
// the minutes before the job started.
package tools

import (
	// nfpm: builds the release RPM.
	_ "github.com/goreleaser/nfpm/v2/cmd/nfpm"
)
