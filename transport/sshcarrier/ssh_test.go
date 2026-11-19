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
	"golang.org/x/crypto/ssh/knownhosts"
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

// A broker with no durable filesystem -- a container, a glidein -- can carry
// its host keys in configuration instead of a file. It is still the operator
// declaring what the host is, not the broker discovering it.
func TestInlineHostKeysAreHonoured(t *testing.T) {
	s := newTestSSHServer(t, echo)

	line := knownHostsLine(t, s.addr, s.hostKey)
	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.HostKeyCallback = nil
	cfg.HostKeys = []string{line}

	c := dialTest(t, cfg)
	if _, err := c.Write([]byte("up")); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// And a wrong inline key is refused, so the inline path is not a way around
// verification.
func TestInlineHostKeysStillRefuseAStranger(t *testing.T) {
	s := newTestSSHServer(t, echo)
	other := newTestSSHServer(t, echo)

	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.HostKeyCallback = nil
	cfg.HostKeys = []string{knownHostsLine(t, s.addr, other.hostKey)}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if c, err := Dial(ctx, cfg); err == nil {
		_ = c.Close()
		t.Fatal("an inline key that does not match the server was accepted")
	}
}

func knownHostsLine(t *testing.T, addr string, key ssh.PublicKey) string {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return knownhosts.Line([]string{knownhosts.Normalize(net.JoinHostPort(host, port))}, key)
}

// A refusal has to tell the operator what to do next, and must not tell them
// to ask the host itself: ssh-keyscan trusts whatever answered, which is the
// exact thing the refusal exists to prevent. The broker already saw the key
// during the failed handshake, so it can show the fingerprint to check and
// the line to add once it checks out.
func TestUnknownHostKeyErrorExplainsWhatToDo(t *testing.T) {
	s := newTestSSHServer(t, echo)

	known := t.TempDir() + "/known_hosts"
	if err := os.WriteFile(known, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.HostKeyCallback = nil
	cfg.KnownHosts = []string{known}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := Dial(ctx, cfg)
	if err == nil {
		t.Fatal("an unknown host key was accepted")
	}
	var hke *HostKeyError
	if !errors.As(err, &hke) {
		t.Fatalf("error %v is not a *HostKeyError", err)
	}
	if hke.Offered == nil {
		t.Fatal("the error does not carry the key the server offered, so it cannot name a fingerprint")
	}

	msg := err.Error()
	// The fingerprint of the key actually seen, to check out of band.
	if want := ssh.FingerprintSHA256(s.hostKey); !strings.Contains(msg, want) {
		t.Errorf("message does not carry the offered fingerprint %q:\n%s", want, msg)
	}
	// The file to put it in.
	if !strings.Contains(msg, known) {
		t.Errorf("message does not name the known_hosts file:\n%s", msg)
	}
	// A line that actually parses as known_hosts, not prose about one.
	line := extractKnownHostsLine(t, msg, s.addr)
	if line == "" {
		t.Fatalf("message contains no usable known_hosts line:\n%s", msg)
	}
	tmp := t.TempDir() + "/from_message"
	if err := os.WriteFile(tmp, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The real test of the advice: following it works.
	retry := s.config("htc-ccb -carrier-stdio")
	retry.HostKeyCallback = nil
	retry.KnownHosts = []string{tmp}
	c := dialTest(t, retry)
	if _, err := c.Write([]byte("up")); err != nil {
		t.Fatalf("after following the advice, the carrier still failed: %v", err)
	}
}

// The advice asks for the one step that cannot be automated -- checking the
// fingerprint against a trusted source -- and says what ssh-keyscan does
// establish, since it is the first tool most people reach for. It states
// facts; the decision is the administrator's.
func TestUnknownHostKeyAdviceIsFactual(t *testing.T) {
	s := newTestSSHServer(t, echo)
	hke := &HostKeyError{Addr: "h:22", Err: errors.New("x"), Offered: s.hostKey}
	help := hke.Help()

	if !strings.Contains(help, "Verify that fingerprint against a source you trust") {
		t.Errorf("the advice does not ask for the one manual step:\n%s", help)
	}
	// It gives the command, not just the tool's name: an operator should not
	// have to work out the flags.
	if !strings.Contains(help, "ssh-keyscan -t ssh-ed25519 h") {
		t.Errorf("the advice does not give a runnable ssh-keyscan command:\n%s", help)
	}
	// It should describe what the tool does, not tell them off for using it.
	for _, scold := range []string{"would trust whatever answered", "refusal is for", "Do not ", "must not"} {
		if strings.Contains(help, scold) {
			t.Errorf("the advice lectures (%q):\n%s", scold, help)
		}
	}
}

// A changed key is a different situation and says so, but still leaves the
// call to the person who can find out which it is.
func TestChangedHostKeyAdviceNamesTheAmbiguity(t *testing.T) {
	s := newTestSSHServer(t, echo)
	hke := &HostKeyError{Addr: "h:22", Err: errors.New("x"), Changed: true, Offered: s.hostKey}
	help := hke.Help()
	for _, want := range []string{"differs from the key already on record", "look the same from here", "confirming the change with the site"} {
		if !strings.Contains(help, want) {
			t.Errorf("the changed-key advice is missing %q:\n%s", want, help)
		}
	}
	if strings.Contains(help, "Do not simply replace") {
		t.Errorf("the changed-key advice issues an order rather than stating the situation:\n%s", help)
	}
}

// With no known_hosts file configured -- an inline-only deployment -- the
// advice must point at the setting that exists, not a file the operator does
// not have.
func TestAdvicePointsAtTheConfiguredPlace(t *testing.T) {
	s := newTestSSHServer(t, echo)

	withFile := &HostKeyError{Addr: "h:22", Err: errors.New("x"), Offered: s.hostKey, Where: "/etc/condor/ccb/known_hosts"}
	if !strings.Contains(withFile.Help(), "/etc/condor/ccb/known_hosts") {
		t.Errorf("the advice does not name the configured file:\n%s", withFile.Help())
	}

	inlineOnly := &HostKeyError{Addr: "h:22", Err: errors.New("x"), Offered: s.hostKey}
	help := inlineOnly.Help()
	if !strings.Contains(help, "CCB_CARRIER_SSH_HOST_KEY") {
		t.Errorf("the inline-only advice does not name the setting:\n%s", help)
	}
	if strings.Contains(help, "known_hosts:") {
		t.Errorf("the inline-only advice points at a file the operator has not configured:\n%s", help)
	}
}

// extractKnownHostsLine pulls the suggested line out of the message.
func extractKnownHostsLine(t *testing.T, msg, addr string) string {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	prefix := knownhosts.Normalize(net.JoinHostPort(host, port))
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix+" ") {
			return line
		}
	}
	return ""
}

// The generated ssh-keyscan command has to be runnable as printed: the right
// key type, and -p only when the port is not the default.
func TestKeyscanCommandIsRunnable(t *testing.T) {
	s := newTestSSHServer(t, echo)
	for _, tc := range []struct{ addr, want string }{
		{"login.cluster.edu:22", "ssh-keyscan -t ssh-ed25519 login.cluster.edu"},
		{"login.cluster.edu:2222", "ssh-keyscan -t ssh-ed25519 -p 2222 login.cluster.edu"},
	} {
		e := &HostKeyError{Addr: tc.addr, Err: errors.New("x"), Offered: s.hostKey}
		if got := e.Help(); !strings.Contains(got, tc.want) {
			t.Errorf("for %s the advice lacks %q:\n%s", tc.addr, tc.want, got)
		}
		// -p 22 is noise; ssh-keyscan defaults to it.
		if tc.addr == "login.cluster.edu:22" && strings.Contains(e.Help(), "-p 22") {
			t.Errorf("the command spells out the default port:\n%s", e.Help())
		}
	}
}
