// Package remotebin finds the htc-ccb build to stage on a remote host.
//
// There are two ways to have one, and a site will want different ones:
//
//   - a directory of per-platform builds, which is what a package install
//     gives you for free and what a build farm already produces; or
//   - builds compiled into this binary, for a broker that is itself shipped as
//     a single file and has nowhere to keep a directory.
//
// The second is behind the `embedremote` build tag, because it roughly doubles
// the binary for everyone who never stages anything. A default build looks in
// the directory; `-tags embedremote` adds the compiled-in copies as a
// fallback, so a site can have both and the directory still wins.
package remotebin

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Name is what a per-platform build is called in a directory:
// htc-ccb-<os>-<arch>, as the release tarballs name them.
func Name(goos, goarch string) string {
	return fmt.Sprintf("htc-ccb-%s-%s", goos, goarch)
}

// Source is where a staged binary came from, for the log line. An operator
// debugging a staging problem needs to know which copy was sent.
type Source struct {
	// Path is a file on disk, empty when the build was compiled in.
	Path string
	// Embedded reports a build carried inside this binary.
	Embedded bool
	Size     int
}

func (s Source) String() string {
	if s.Embedded {
		return fmt.Sprintf("embedded (%d bytes)", s.Size)
	}
	return fmt.Sprintf("%s (%d bytes)", s.Path, s.Size)
}

// Find returns the build for goos/goarch.
//
// dir is searched first when set, so a site that ships its own builds keeps
// control of what lands on its hosts; a compiled-in copy is the fallback. If
// neither has it, the error says which platforms are available rather than
// just that this one is missing -- "no linux/arm64 build" is not actionable
// when the caller cannot see what there was.
func Find(dir, goos, goarch string) ([]byte, Source, error) {
	want := Name(goos, goarch)
	if dir != "" {
		path := filepath.Join(dir, want)
		body, err := os.ReadFile(path)
		if err == nil {
			return body, Source{Path: path, Size: len(body)}, nil
		}
		if !os.IsNotExist(err) {
			return nil, Source{}, fmt.Errorf("remotebin: reading %s: %w", path, err)
		}
	}
	if body, ok := embedded(want); ok {
		return body, Source{Embedded: true, Size: len(body)}, nil
	}
	return nil, Source{}, fmt.Errorf("remotebin: no %s/%s build available%s; %s",
		goos, goarch, inDir(dir), haveWhat(dir))
}

func inDir(dir string) string {
	if dir == "" {
		return ""
	}
	return " in " + dir
}

// haveWhat lists what is on hand, so the error names the fix.
func haveWhat(dir string) string {
	var have []string
	if dir != "" {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "htc-ccb-") {
					have = append(have, e.Name())
				}
			}
		}
	}
	have = append(have, embeddedNames()...)
	if len(have) == 0 {
		if dir == "" {
			return "no directory is configured and this build carries none (rebuild with -tags embedremote, or set the directory)"
		}
		return "that directory holds no htc-ccb-<os>-<arch> builds"
	}
	sort.Strings(have)
	return "available: " + strings.Join(have, ", ")
}

// Local names the platform this binary was built for, which is the only one a
// single-file install can stage without either a directory or the embed tag.
func Local() (string, string) { return runtime.GOOS, runtime.GOARCH }

// Any reports whether this build carries any compiled-in binaries at all.
//
// It answers a question a caller can ask before it knows the far host's
// platform: with no directory configured and nothing embedded, staging cannot
// work for any host, which is a configuration error worth reporting at
// startup rather than on the first dial.
func Any() bool { return len(embeddedNames()) > 0 }
