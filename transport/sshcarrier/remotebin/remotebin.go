// Package remotebin finds the htc-ccb-splice build to stage on a remote host.
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

// Names is what a per-platform build can be called in a directory:
// htc-ccb-splice-<os>-<arch>, as the release tarballs name it.
//
// There is deliberately no fallback to htc-ccb. The far end of this carrier is
// a splice helper -- a byte relay with no CEDAR, no ClassAds and no
// credentials -- and the full broker is not one. It would start, register as a
// broker, and behave like an inside CCB, which is a different model with a
// different authorization boundary, not a degraded version of this one. A
// missing build is an error rather than a silent change of topology.
func Names(goos, goarch string) []string {
	return []string{
		fmt.Sprintf("htc-ccb-splice-%s-%s", goos, goarch),
	}
}

// Name is the preferred spelling for one platform.
func Name(goos, goarch string) string { return Names(goos, goarch)[0] }

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
	switch {
	case s.Embedded:
		return fmt.Sprintf("embedded (%d bytes)", s.Size)
	default:
		return fmt.Sprintf("%s (%d bytes)", s.Path, s.Size)
	}
}

// Find returns the build for goos/goarch.
//
// dir is searched first when set, so a site that ships its own builds keeps
// control of what lands on its hosts; a compiled-in copy is the fallback. If
// neither has it, the error says which platforms are available rather than
// just that this one is missing -- "no linux/arm64 build" is not actionable
// when the caller cannot see what there was.
func Find(dir, goos, goarch string) ([]byte, Source, error) {
	wanted := Names(goos, goarch)
	if dir != "" {
		for _, want := range wanted {
			path := filepath.Join(dir, want)
			body, err := os.ReadFile(path)
			if err == nil {
				return body, Source{Path: path, Size: len(body)}, nil
			}
			if !os.IsNotExist(err) {
				return nil, Source{}, fmt.Errorf("remotebin: reading %s: %w", path, err)
			}
		}
	}
	for _, want := range wanted {
		if body, ok := embedded(want); ok {
			return body, Source{Embedded: true, Size: len(body)}, nil
		}
	}
	// There is no self-staging fallback. A broker could stage a copy of
	// ITSELF when the far host matched its platform, which is what made
	// staging "always work" and let the embedded set skip the host platform,
	// halving what `-tags embedremote` cost. That ended with the relay: this
	// broker is not a splice helper, so its own binary is not a candidate.
	// Every platform that will be staged onto must be present.
	return nil, Source{}, fmt.Errorf("remotebin: no %s/%s build available%s; %s. %s",
		goos, goarch, inDir(dir), haveWhat(dir), remedy)
}

func inDir(dir string) string {
	if dir == "" {
		return ""
	}
	return " in " + dir
}

// remedy is the fix, said once rather than guessed at per case. A missing
// platform is nearly always a build that was never made, so the message names
// both ways to make one.
const remedy = "Put an htc-ccb-splice-<os>-<arch> build in CCB_CARRIER_SSH_STAGE_BINARY_DIR, " +
	"or build htc-ccb with -tags embedremote after running scripts/embed-builds.sh"

// haveWhat lists what is on hand, so the error says what there was rather
// than only what was missing.
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
	sort.Strings(have)
	if len(have) == 0 {
		return "available: nothing"
	}
	return "available: " + strings.Join(have, ", ")
}

// ParsePlatform reads an htc-ccb-splice-<os>-<arch> file name back into its
// platform.
//
// Having one parser matters because there are now two spellings: code that
// splits on "-" and takes the last two fields works for both, and code that
// strips a single "htc-ccb-" prefix silently mis-parses the relay.
func ParsePlatform(name string) (goos, goarch string, ok bool) {
	name = strings.TrimSuffix(name, ".gz")
	if !strings.HasPrefix(name, "htc-ccb-") {
		return "", "", false
	}
	parts := strings.Split(name, "-")
	if len(parts) < 4 {
		return "", "", false
	}
	return parts[len(parts)-2], parts[len(parts)-1], true
}

// Local names the platform this binary was built for.
func Local() (string, string) { return runtime.GOOS, runtime.GOARCH }

// Any reports whether this build carries any compiled-in binaries at all.
//
// It answers a question a caller can ask before it knows the far host's
// platform: with no directory configured and nothing embedded, staging cannot
// work for any host, which is a configuration error worth reporting at
// startup rather than on the first dial.
func Any() bool { return len(embeddedNames()) > 0 }
