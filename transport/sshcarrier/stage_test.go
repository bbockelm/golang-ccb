package sshcarrier

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeHost is just enough of a remote host to exercise staging: a file table,
// `uname`, the size probe, and the upload pipeline.
type fakeHost struct {
	mu       sync.Mutex
	files    map[string][]byte
	uname    string
	uploads  int // how many times a body was actually written
	probes   int
	truncate bool // write a short file, to test the post-upload check
}

func newFakeHost(uname string) *fakeHost {
	return &fakeHost{files: map[string][]byte{}, uname: uname}
}

var quoted = regexp.MustCompile(`'((?:[^']|'\\'')*)'`)

func (h *fakeHost) paths(cmd string) []string {
	var out []string
	for _, m := range quoted.FindAllStringSubmatch(cmd, -1) {
		out = append(out, strings.ReplaceAll(m[1], `'\''`, "'"))
	}
	return out
}

func (h *fakeHost) handle(cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch {
	case strings.HasPrefix(cmd, "uname"):
		fmt.Fprintln(stdout, h.uname)
		return 0

	case strings.Contains(cmd, "wc -c <"):
		h.probes++
		p := h.paths(cmd)
		if len(p) == 0 {
			return 1
		}
		if body, ok := h.files[p[0]]; ok {
			fmt.Fprintln(stdout, len(body))
		}
		return 0 // `|| true` means the real command never fails either

	case strings.Contains(cmd, "cat >"):
		p := h.paths(cmd)
		// mkdir dir, cat > tmp, chmod tmp, mv tmp dest
		if len(p) < 5 {
			fmt.Fprintln(stderr, "unexpected staging command")
			return 1
		}
		dest := p[4]
		body, err := io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if h.truncate && len(body) > 4 {
			body = body[:4]
		}
		h.files[dest] = body
		h.uploads++
		return 0
	}
	fmt.Fprintf(stderr, "fakeHost: unhandled command %q\n", cmd)
	return 127
}

func (h *fakeHost) count() (uploads, probes int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.uploads, h.probes
}

func stagingClient(t *testing.T, h *fakeHost) *ssh.Client {
	t.Helper()
	s := newTestSSHServer(t, h.handle)
	cfg := s.config("unused")
	hostKey, _ := cfg.hostKeyCallback()
	auths, _ := cfg.authMethods()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := dialClient(ctx, s.addr, &ssh.ClientConfig{
		User: "tester", Auth: auths, HostKeyCallback: hostKey, Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("dialClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func localBinary(t *testing.T, body string) string {
	t.Helper()
	p := t.TempDir() + "/htc-ccb"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectPlatform(t *testing.T) {
	for _, tc := range []struct {
		uname string
		want  Platform
	}{
		{"Linux x86_64", Platform{"linux", "amd64"}},
		{"Linux aarch64", Platform{"linux", "arm64"}},
		{"Darwin arm64", Platform{"darwin", "arm64"}},
	} {
		t.Run(tc.uname, func(t *testing.T) {
			client := stagingClient(t, newFakeHost(tc.uname))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			got, err := DetectPlatform(ctx, client)
			if err != nil {
				t.Fatalf("DetectPlatform: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectPlatformRejectsTheUnsupported(t *testing.T) {
	client := stagingClient(t, newFakeHost("SunOS sparc"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if p, err := DetectPlatform(ctx, client); err == nil {
		t.Fatalf("accepted an unsupported platform as %v", p)
	}
}

// Zero touch: the binary lands on a host that had nothing, at a path named
// after its content.
func TestStageUploadsToAContentAddressedPath(t *testing.T) {
	h := newFakeHost("Linux x86_64")
	client := stagingClient(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	remote, err := Stage(ctx, client, StageConfig{
		Binary:    localBinary(t, "fake htc-ccb binary body"),
		Platform:  Platform{"linux", "amd64"},
		RemoteDir: "/home/ccb/.cache/htc-ccb",
	})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !strings.HasPrefix(remote, "/home/ccb/.cache/htc-ccb/htc-ccb-") {
		t.Errorf("staged to %q, which is not under the configured directory", remote)
	}
	uploads, _ := h.count()
	if uploads != 1 {
		t.Errorf("uploaded %d times, want 1", uploads)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if string(h.files[remote]) != "fake htc-ccb binary body" {
		t.Errorf("remote file is %q", h.files[remote])
	}
}

// Reconnecting must not move the binary again. With a 22 MB binary and a
// broker that re-establishes its carrier on every blip, this is the difference
// between a staged install and a transfer storm.
func TestStageSkipsAnIdenticalBinaryAlreadyThere(t *testing.T) {
	h := newFakeHost("Linux x86_64")
	client := stagingClient(t, h)
	bin := localBinary(t, "fake htc-ccb binary body")

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if _, err := Stage(ctx, client, StageConfig{Binary: bin, Platform: Platform{"linux", "amd64"}}); err != nil {
			cancel()
			t.Fatalf("Stage %d: %v", i, err)
		}
		cancel()
	}
	uploads, probes := h.count()
	if uploads != 1 {
		t.Errorf("uploaded %d times across 3 stages, want 1", uploads)
	}
	if probes < 3 {
		t.Errorf("probed %d times, want at least 3 (one per stage)", probes)
	}
}

// A different build gets a different name, so two brokers staging different
// versions cannot overwrite each other.
func TestStageSeparatesDifferentBuilds(t *testing.T) {
	h := newFakeHost("Linux x86_64")
	client := stagingClient(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a, err := Stage(ctx, client, StageConfig{Binary: localBinary(t, "build A"), Platform: Platform{"linux", "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Stage(ctx, client, StageConfig{Binary: localBinary(t, "build B"), Platform: Platform{"linux", "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two different builds staged to the same path %q", a)
	}
}

// A truncated upload must be caught here, not discovered later as an
// unintelligible exec failure on the far host.
func TestStageCatchesATruncatedUpload(t *testing.T) {
	h := newFakeHost("Linux x86_64")
	h.truncate = true
	client := stagingClient(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := Stage(ctx, client, StageConfig{Binary: localBinary(t, "a body long enough to be truncated"), Platform: Platform{"linux", "amd64"}})
	if err == nil {
		t.Fatal("a truncated upload was accepted")
	}
	if !strings.Contains(err.Error(), "expected size") {
		t.Errorf("error %q does not say the staged file was the wrong size", err)
	}
}

// Sending the wrong build is caught before the transfer, not after.
func TestStageRefusesAPlatformMismatch(t *testing.T) {
	h := newFakeHost("Linux x86_64")
	client := stagingClient(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := Stage(ctx, client, StageConfig{
		Binary:        localBinary(t, "darwin build"),
		Platform:      Platform{"linux", "amd64"},
		LocalPlatform: Platform{"darwin", "arm64"},
	})
	if err == nil {
		t.Fatal("staged a darwin binary onto a linux host")
	}
	if uploads, _ := h.count(); uploads != 0 {
		t.Errorf("transferred %d bodies despite the mismatch", uploads)
	}
}

// Paths reach the remote shell, so they must be quoted.
func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/tmp/htc-ccb":   `'/tmp/htc-ccb'`,
		"/tmp/a b":       `'/tmp/a b'`,
		"/tmp/it's":      `'/tmp/it'\''s'`,
		"/tmp/$(whoami)": `'/tmp/$(whoami)'`,
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
