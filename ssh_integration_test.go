package ccbserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-ccb/internal/sshtest"
)

// These drive the real htc-ccb binary as the far end of an SSH carrier: the
// test server actually executes what the carrier asks for, so the staged
// broker is a genuine process reading a genuine configuration, not a
// stand-in. What they prove that a unit test cannot is that the derived
// command line, the staged configuration, the cleared environment and the
// -carrier-stdio mode all agree with each other.

var (
	builtOnce sync.Once
	builtPath string
	builtErr  error

	helperOnce sync.Once
	helperPath string
	helperErr  error
)

// brokerBinary compiles htc-ccb once for the whole run.
//
// Once, not per test: the build is several seconds and there are a handful of
// these. t.TempDir would give each test its own copy and pay it every time.
func brokerBinary(t *testing.T) string {
	t.Helper()
	builtOnce.Do(func() {
		dir, err := os.MkdirTemp("", "htc-ccb-integration")
		if err != nil {
			builtErr = err
			return
		}
		builtPath = filepath.Join(dir, "htc-ccb")
		out, err := exec.Command("go", "build", "-buildvcs=false", "-o", builtPath, "./cmd/htc-ccb").CombinedOutput()
		if err != nil {
			builtErr = fmt.Errorf("building htc-ccb: %w\n%s", err, out)
		}
	})
	if builtErr != nil {
		t.Fatal(builtErr)
	}
	return builtPath
}

// helperBinary compiles htc-ccb-splice once for the whole run.
//
// The helper is what a staging carrier actually sends, so it gets the same
// end-to-end treatment as the full binary rather than being trusted to behave
// because it shares a library: it is a different main with a different, much
// smaller wiring, and the ways it could differ -- a flag it rejects, a role it
// does not take -- are exactly the ones a unit test cannot see.
func helperBinary(t *testing.T) string {
	t.Helper()
	helperOnce.Do(func() {
		dir, err := os.MkdirTemp("", "htc-ccb-splice-integration")
		if err != nil {
			helperErr = err
			return
		}
		helperPath = filepath.Join(dir, "htc-ccb-splice")
		out, err := exec.Command("go", "build", "-buildvcs=false", "-o", helperPath, "./cmd/htc-ccb-splice").CombinedOutput()
		if err != nil {
			helperErr = fmt.Errorf("building htc-ccb-splice: %w\n%s", err, out)
		}
	})
	if helperErr != nil {
		t.Fatal(helperErr)
	}
	return helperPath
}

// remoteConfig writes the configuration the staged broker will run with.
//
// CCB_LISTEN matters here for the same reason it matters in the field: the
// staged broker's default is :9618, several of these tests run in one process
// against one loopback host, and the first one to start would own the port for
// all of them -- as the real login node's own HTCondor already does. The
// configuration file is the only way to tell a staged broker otherwise.
func remoteConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "remote.conf")
	addr := freeLoopbackAddr(t)
	body := fmt.Sprintf(`LOG = %s
LOCK = %s
RUN = %s
SPOOL = %s
SEC_DEFAULT_AUTHENTICATION = NEVER
SEC_DEFAULT_ENCRYPTION = NEVER
SEC_DEFAULT_INTEGRITY = NEVER
ALLOW_DAEMON = *
ALLOW_READ = *
CCB_OUTBOUND_PROXY = TRUE
CCB_LISTEN = %s
CCB_PUBLIC = %s
`, dir, dir, dir, dir, addr, addr)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sshCarrierBroker starts an outside broker whose carrier is an ssh:// session
// to srv, staging the real binary.
func sshCarrierBroker(t *testing.T, srv *sshtest.Server, extra func(*SSHCarrierConfig)) (outsideAddr string, server *Server) {
	t.Helper()
	ln := mustListen(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, []byte(srv.KnownHostsLine()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sc := SSHCarrierConfig{
		User:          "tester",
		KnownHosts:    []string{kh},
		StageBinary:   brokerBinary(t),
		StageConfig:   remoteConfig(t),
		RemoteDir:     filepath.Join(t.TempDir(), "staged"),
		IdentityFiles: []string{identityFile(t, srv)},
	}
	if extra != nil {
		extra(&sc)
	}

	s, err := New(Config{
		PublicAddress:  ln.Addr().String(),
		Security:       plaintextSec(),
		RequestTimeout: 10 * time.Second,
		OperatorWait:   20 * time.Second,
		CarrierListen:  "ssh://tester@" + srv.Addr,
		CarrierSSH:     sc,
		Logger:         testLogger(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()
	return ln.Addr().String(), s
}

// The baseline: key authentication, the real binary staged and run as the far
// end of the carrier.
func TestIntegrationSSHCarrierStagesAndRunsTheRealBinary(t *testing.T) {
	srv, err := sshtest.Start(sshtest.RunReal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	_, broker := sshCarrierBroker(t, srv, nil)
	waitForStagedBroker(t, broker)
}

// A site that wants a one-time code. Nothing can answer it but a person, so
// the operator console is the only way this login completes.
func TestIntegrationKeyboardInteractiveLogin(t *testing.T) {
	srv, err := sshtest.Start(sshtest.RunReal,
		sshtest.WithKeyboardInteractive("Two-factor required", "Verification code:", "424242"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	outsideAddr, broker := sshCarrierBroker(t, srv, func(sc *SSHCarrierConfig) {
		sc.IdentityFiles = nil // no key will do; only the code
	})
	answerFromConsole(t, outsideAddr, "Verification code:", "424242")
	waitForStagedBroker(t, broker)
}

// The same, with a password.
func TestIntegrationPasswordLogin(t *testing.T) {
	srv, err := sshtest.Start(sshtest.RunReal, sshtest.WithPassword("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	outsideAddr, broker := sshCarrierBroker(t, srv, func(sc *SSHCarrierConfig) {
		sc.IdentityFiles = nil
	})
	answerFromConsole(t, outsideAddr, "Password:", "hunter2")
	waitForStagedBroker(t, broker)
}

// Through a bastion, which is the usual shape for a cluster you cannot reach
// directly -- and frequently the same cluster you cannot install on.
func TestIntegrationProxyJump(t *testing.T) {
	target, err := sshtest.Start(sshtest.RunReal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	bastion, err := sshtest.Start(sshtest.Echo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bastion.Close() }()

	ln := mustListen(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	// Both hops must verify.
	body := target.KnownHostsLine() + "\n" + bastion.KnownHostsLine() + "\n"
	if err := os.WriteFile(kh, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New(Config{
		PublicAddress:  ln.Addr().String(),
		Security:       plaintextSec(),
		RequestTimeout: 10 * time.Second,
		CarrierListen:  "ssh://tester@" + target.Addr,
		CarrierSSH: SSHCarrierConfig{
			User:        "tester",
			KnownHosts:  []string{kh},
			ProxyJump:   []string{bastion.Addr},
			StageBinary: brokerBinary(t),
			StageConfig: remoteConfig(t),
			RemoteDir:   filepath.Join(t.TempDir(), "staged"),
			IdentityFiles: []string{
				identityFile(t, target),
				identityFile(t, bastion),
			},
		},
		Logger: testLogger(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()

	waitForStagedBroker(t, s)
}

// waitForStagedBroker waits until the far broker has registered through the
// carrier, which is the signal that staging, the configuration and the
// -carrier-stdio mode all worked.
func waitForStagedBroker(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if registeredCount(s) > 0 {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("the staged broker never registered through the carrier")
}

// registeredCount is how many brokers have registered with this one.
func registeredCount(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.targets)
}

// freeLoopbackAddr picks a loopback port nothing is using. The usual caveat
// applies -- another process could take it in the gap -- but on a loopback
// interface in a test run that is not a practical risk, and the alternative
// (a fixed port) is the collision this exists to avoid.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// answerFromConsole attaches to the operator console in the background and
// answers the expected question.
func answerFromConsole(t *testing.T, outsideAddr string, wantPrompt, answer string) {
	t.Helper()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		_ = WaitForLogin(ctx, outsideAddr, plaintextSec(), 80*time.Second, func(c OperatorChallenge) ([]string, error) {
			if len(c.Questions) == 0 || !strings.Contains(c.Questions[0].Prompt, strings.TrimSuffix(wantPrompt, ":")) {
				return nil, fmt.Errorf("unexpected challenge %+v", c.Questions)
			}
			out := make([]string, len(c.Questions))
			for i := range out {
				out[i] = answer
			}
			return out, nil
		})
	}()
}

// identityFile writes a server's accepted credential to disk, so the carrier
// can offer it the way an operator's configuration would.
func identityFile(t *testing.T, srv *sshtest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id")
	body, err := srv.ClientKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The relay is the binary a staging carrier should send, so stage it and
// drive the same end-to-end path: an ssh session, the derived
// `<binary> -carrier-stdio` command line, the staged configuration, and a
// registration arriving back through the pipe.
func TestIntegrationSSHCarrierStagesTheRelay(t *testing.T) {
	srv, err := sshtest.Start(sshtest.RunReal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	_, broker := sshCarrierBroker(t, srv, func(sc *SSHCarrierConfig) {
		sc.StageBinary = helperBinary(t)
	})
	waitForStagedBroker(t, broker)
}

// A directory holding both builds must stage the relay: it is the one meant
// to cross the network, and a site that has both should not pay for the
// larger one by accident.
func TestIntegrationADirectoryOfBuildsPrefersTheRelay(t *testing.T) {
	srv, err := sshtest.Start(sshtest.RunReal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	dir := t.TempDir()
	goos, goarch := runtime.GOOS, runtime.GOARCH
	copyFile(t, helperBinary(t), filepath.Join(dir, "htc-ccb-splice-"+goos+"-"+goarch))
	copyFile(t, brokerBinary(t), filepath.Join(dir, "htc-ccb-"+goos+"-"+goarch))

	remoteDir := filepath.Join(t.TempDir(), "staged")
	_, broker := sshCarrierBroker(t, srv, func(sc *SSHCarrierConfig) {
		sc.StageBinary = ""
		sc.StageBinaryDir = dir
		sc.RemoteDir = remoteDir
	})
	waitForStagedBroker(t, broker)

	// Which build crossed is the whole point, and it is only visible in what
	// landed: both run the same role, so a working tunnel proves nothing
	// about which one is on the far host.
	staged := stagedNames(t, remoteDir)
	if len(staged) != 1 {
		t.Fatalf("expected exactly one staged binary, found %v", staged)
	}
	got := fileSize(t, filepath.Join(remoteDir, staged[0]))
	relaySize := fileSize(t, helperBinary(t))
	if got != relaySize {
		t.Errorf("staged %d bytes; the relay is %d and the full binary %d -- the wrong build was sent",
			got, relaySize, fileSize(t, brokerBinary(t)))
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	body, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, body, 0o755); err != nil {
		t.Fatal(err)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func stagedNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".conf") {
			out = append(out, e.Name())
		}
	}
	return out
}
