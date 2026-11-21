package sshcarrier

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
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
	}, nil, "")
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
	if !strings.HasPrefix(remote.Binary, "/home/ccb/.cache/htc-ccb/htc-ccb-") {
		t.Errorf("staged to %q, which is not under the configured directory", remote.Binary)
	}
	uploads, _ := h.count()
	if uploads != 1 {
		t.Errorf("uploaded %d times, want 1", uploads)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if string(h.files[remote.Binary]) != "fake htc-ccb binary body" {
		t.Errorf("remote file is %q", h.files[remote.Binary])
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
	if a.Binary == b.Binary {
		t.Fatalf("two different builds staged to the same path %q", a.Binary)
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

// Zero touch end to end: a host with nothing on it gets the binary and then
// runs it as the carrier, with the command derived from where it landed. An
// operator configures a host and a binary; the path is not theirs to track.
func TestDialStagedInstallsThenRunsTheStagedCopy(t *testing.T) {
	h := newFakeHost("Linux x86_64")
	var ran atomic.Pointer[string]
	s := newTestSSHServer(t, func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
		// Staging commands go to the fake host; anything else is the carrier.
		if strings.HasPrefix(cmd, "uname") || strings.Contains(cmd, "wc -c <") || strings.Contains(cmd, "cat >") {
			return h.handle(cmd, stdin, stdout, stderr)
		}
		ran.Store(&cmd)
		_, _ = io.Copy(stdout, stdin)
		return 0
	})

	cfg := s.config("") // no explicit command: it must be derived
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := DialStaged(ctx, cfg, StageConfig{
		Binary:    localBinary(t, "fake htc-ccb binary body"),
		RemoteDir: "/home/ccb/.cache/htc-ccb",
	})
	if err != nil {
		t.Fatalf("DialStaged: %v", err)
	}
	defer func() { _ = c.Close() }()

	// The pipe works.
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	cmd := ran.Load()
	if cmd == nil {
		t.Fatal("the staged binary was never run")
	}
	if !strings.Contains(*cmd, "/home/ccb/.cache/htc-ccb/htc-ccb-") {
		t.Errorf("ran %q; it does not name the staged path", *cmd)
	}
	// The helper takes its carrier from stdin without being told; what the
	// command must NOT carry is the old broker invocation.
	if strings.Contains(*cmd, "-carrier-stdio") {
		t.Errorf("ran %q; the staged process is a splice helper, not a broker", *cmd)
	}
	if uploads, _ := h.count(); uploads != 1 {
		t.Errorf("uploaded %d times, want 1", uploads)
	}
}

// An explicit command still wins, for a site that installs the binary itself.
func TestDialStagedHonoursAnExplicitCommand(t *testing.T) {
	h := newFakeHost("Linux x86_64")
	var ran atomic.Pointer[string]
	s := newTestSSHServer(t, func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
		if strings.HasPrefix(cmd, "uname") || strings.Contains(cmd, "wc -c <") || strings.Contains(cmd, "cat >") {
			return h.handle(cmd, stdin, stdout, stderr)
		}
		ran.Store(&cmd)
		_, _ = io.Copy(stdout, stdin)
		return 0
	})

	const want = "/usr/sbin/htc-ccb -carrier-stdio -listen 0.0.0.0:9618"
	cfg := s.config(want)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := DialStaged(ctx, cfg, StageConfig{Binary: localBinary(t, "body")})
	if err != nil {
		t.Fatalf("DialStaged: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && ran.Load() == nil {
		time.Sleep(10 * time.Millisecond)
	}
	if cmd := ran.Load(); cmd == nil || *cmd != want {
		t.Errorf("ran %v, want %q", cmd, want)
	}
}

// Nothing but the binary is staged, and it is run plainly.
//
// A staged broker needed a condor_config beside it and an `env -i` wrapper, so
// that a stray _CONDOR_<PARAM> in the login host's environment could not
// override its security settings. A splice helper reads no configuration and
// holds no credentials, so there is nothing to stage and nothing to protect --
// and a knob that staged a file the far end ignores would be worse than none.
func TestOnlyTheBinaryIsStaged(t *testing.T) {
	h := newFakeHost("Linux x86_64")
	var ran atomic.Pointer[string]
	s := newTestSSHServer(t, func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
		if strings.HasPrefix(cmd, "uname") || strings.Contains(cmd, "wc -c <") || strings.Contains(cmd, "cat >") {
			return h.handle(cmd, stdin, stdout, stderr)
		}
		ran.Store(&cmd)
		_, _ = io.Copy(stdout, stdin)
		return 0
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := DialStaged(ctx, s.config(""), StageConfig{
		Binary:    localBinary(t, "fake htc-ccb-splice body"),
		RemoteDir: "/scratch/ccb",
	})
	if err != nil {
		t.Fatalf("DialStaged: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}

	cmd := ran.Load()
	if cmd == nil {
		t.Fatal("the helper was never run")
	}
	for _, gone := range []string{"env -i", "CONDOR_CONFIG"} {
		if strings.Contains(*cmd, gone) {
			t.Errorf("the command still carries %q: %q", gone, *cmd)
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for path := range h.files {
		if strings.HasSuffix(path, ".conf") {
			t.Errorf("a configuration file was staged (%s); the helper reads none", path)
		}
	}
}

// Without a staged configuration the broker is run plainly: clearing the
// environment would take CONDOR_CONFIG with it, and the operator is relying on
// the far host's own configuration on purpose.
func TestNoStagedConfigLeavesTheEnvironmentAlone(t *testing.T) {
	h := newFakeHost("Linux x86_64")
	var ran atomic.Pointer[string]
	s := newTestSSHServer(t, func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
		if strings.HasPrefix(cmd, "uname") || strings.Contains(cmd, "wc -c <") || strings.Contains(cmd, "cat >") {
			return h.handle(cmd, stdin, stdout, stderr)
		}
		ran.Store(&cmd)
		_, _ = io.Copy(stdout, stdin)
		return 0
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := DialStaged(ctx, s.config(""), StageConfig{Binary: localBinary(t, "body")})
	if err != nil {
		t.Fatalf("DialStaged: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if cmd := ran.Load(); cmd == nil || strings.Contains(*cmd, "env -i") {
		t.Errorf("ran %v; with no staged config the environment should be left alone", cmd)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
