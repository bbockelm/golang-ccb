//go:build embedremote

package remotebin

import (
	"embed"
	"io/fs"
	"path"
	"strings"
)

// builds holds the per-platform binaries compiled into this one.
//
// They are kept gzipped: an htc-ccb for linux/amd64 is about 16 MB stripped
// and 6.6 MB compressed, so carrying two arches costs roughly 13 MB rather
// than 31. Populate internal/remotebuilds before building with this tag; the
// Makefile target does it.
//
//go:embed builds
var builds embed.FS

func embedded(name string) ([]byte, bool) {
	body, err := fs.ReadFile(builds, path.Join("builds", name+".gz"))
	if err != nil {
		return nil, false
	}
	out, err := gunzip(body)
	if err != nil {
		return nil, false
	}
	return out, true
}

func embeddedNames() []string {
	var out []string
	entries, err := fs.ReadDir(builds, "builds")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		// builds/README.md rides along because //go:embed takes the whole
		// directory, and it must match in a checkout that holds no builds.
		if !strings.HasSuffix(e.Name(), ".gz") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".gz")+" (embedded)")
	}
	return out
}
