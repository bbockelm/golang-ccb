package sshcarrier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func dialTest(t *testing.T, cfg Config) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The pipe must carry bytes in both directions: the remote command echoes, so
// what goes in comes back.
func TestSessionCarriesBytes(t *testing.T) {
	s := newTestSSHServer(t, echo)
	c := dialTest(t, s.config("htc-ccb -carrier-stdio"))

	payload := bytes.Repeat([]byte("ccb over ssh\n"), 500)
	go func() { _, _ = c.Write(payload) }()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("the session did not echo the payload intact")
	}
}

// The half-close the relay needs is native here: closing the session's stdin
// is an EOF on the channel, and the far end can still reply. A yamux stream
// had to have this adapted onto it.
func TestSessionSupportsHalfClose(t *testing.T) {
	const reply = "answer after the client finished sending"
	s := newTestSSHServer(t, func(_ string, stdin io.Reader, stdout, _ io.Writer) int {
		// Read to EOF -- which only arrives if the client half-closed --
		// then reply.
		body, _ := io.ReadAll(stdin)
		fmt.Fprintf(stdout, "%s:%d", reply, len(body))
		return 0
	})
	c := dialTest(t, s.config("htc-ccb -carrier-stdio"))

	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("an ssh carrier pipe (%T) has no CloseWrite; the relay could not half-close it", c)
	}
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if want := fmt.Sprintf("%s:%d", reply, len("request")); string(got) != want {
		t.Errorf("got %q, want %q -- the half-close did not reach the far end", got, want)
	}
}

// Host-key verification is the one thing this carrier must never be talked out
// of: accepting an unknown key hands the whole tunnel to whoever answered.
func TestUnknownHostKeyIsRefused(t *testing.T) {
	s := newTestSSHServer(t, echo)

	// A different server's key, pinned instead of this one's.
	other := newTestSSHServer(t, echo)
	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.HostKeyCallback = ssh.FixedHostKey(other.hostKey)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if c, err := Dial(ctx, cfg); err == nil {
		_ = c.Close()
		t.Fatal("the carrier accepted a host key it had not verified")
	}
}

// And there must be no way to configure "accept anything" by omission: a
// config with no host-key policy is an error, not a permissive default.
func TestNoHostKeyPolicyIsAnError(t *testing.T) {
	s := newTestSSHServer(t, echo)
	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.HostKeyCallback = nil
	cfg.KnownHosts = nil

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Dial(ctx, cfg)
	if err == nil {
		t.Fatal("a carrier with no host-key policy was allowed to dial")
	}
	if !strings.Contains(err.Error(), "known_hosts") {
		t.Errorf("error %q does not explain that a host-key policy is required", err)
	}
}

// A host whose key is not in known_hosts is the archetype of a failure that
// retrying cannot fix, so it is reported as its own type for the retry policy
// to recognise.
func TestUnknownHostInKnownHostsIsClassified(t *testing.T) {
	s := newTestSSHServer(t, echo)

	empty := t.TempDir() + "/known_hosts"
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.HostKeyCallback = nil
	cfg.KnownHosts = []string{empty}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := Dial(ctx, cfg)
	if err == nil {
		t.Fatal("a host absent from known_hosts was accepted")
	}
	var hke *HostKeyError
	if !errors.As(err, &hke) {
		t.Fatalf("error %v (%T) is not a *HostKeyError; the retry policy cannot tell it needs a human", err, err)
	}
	if !hke.NeedsHuman() {
		t.Error("a host-key failure did not report that it needs a human")
	}
}

// A remote command that fails must say why. Without this the relay sees a bare
// EOF, which is the complaint that produced the cmd: carrier's stderr capture.
func TestRemoteFailureIsExplained(t *testing.T) {
	s := newTestSSHServer(t, func(_ string, _ io.Reader, _, stderr io.Writer) int {
		fmt.Fprintln(stderr, "htc-ccb: no such file or directory")
		return 127
	})
	c := dialTest(t, s.config("/usr/sbin/htc-ccb -carrier-stdio"))

	// The read must end as a NORMAL end-of-stream. io.Copy and io.ReadAll
	// compare against io.EOF with ==, so annotating it here would make the
	// relay report every clean close as a failure.
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("reading to the end of the session returned %v; it must be a clean io.EOF", err)
	}

	d, ok := c.(Diagnostics)
	if !ok {
		t.Fatalf("pipe (%T) does not implement Diagnostics", c)
	}
	// The explanation lives here instead, which is what the relay logs.
	if got := d.Stderr(); !strings.Contains(got, "no such file") {
		t.Errorf("Stderr() = %q; the diagnosis must survive even though the read ended cleanly", got)
	}
	if exitErr, exited := d.Exited(); !exited || exitErr == nil {
		t.Errorf("Exited() = %v, %v; want the non-zero status", exitErr, exited)
	}
}

// The remote command is what the operator configured, verbatim.
func TestRemoteCommandIsPassedThrough(t *testing.T) {
	const want = "/opt/htc-ccb -carrier-stdio -listen 0.0.0.0:9618"
	got := make(chan string, 1)
	s := newTestSSHServer(t, func(cmd string, _ io.Reader, stdout, _ io.Writer) int {
		got <- cmd
		_, _ = stdout.Write([]byte("ok"))
		return 0
	})
	dialTest(t, s.config(want))

	select {
	case cmd := <-got:
		if cmd != want {
			t.Errorf("remote ran %q, want %q", cmd, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the remote command never ran")
	}
}
