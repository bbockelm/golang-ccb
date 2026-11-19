package ccbserver

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-ccb/transport/sshcarrier"
)

// startConsoleBroker starts a broker serving the operator console.
func startConsoleBroker(t *testing.T) (addr string, srv *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	kh := t.TempDir() + "/known_hosts"
	if err := writeFile(kh, ""); err != nil {
		t.Fatal(err)
	}
	srv, err = New(Config{
		PublicAddress:           ln.Addr().String(),
		Security:                plaintextSec(),
		RequestTimeout:          5 * time.Second,
		OperatorWait:            10 * time.Second,
		OutboundNextHop:         "ssh://login.cluster.edu",
		OutboundNextHopSecurity: plaintextSec(),
		CarrierSSH: SSHCarrierConfig{
			KnownHosts:  []string{kh},
			StageBinary: "/nonexistent/htc-ccb",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String(), srv
}

// End to end over CEDAR: the broker is stuck on a login, an operator attaches,
// the question reaches them, and their answer reaches the carrier.
func TestConsoleCarriesAChallengeAndAnswer(t *testing.T) {
	addr, srv := startConsoleBroker(t)

	// The carrier asks, as it would mid-handshake.
	answered := make(chan []string, 1)
	failed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		// Wait for an operator before asking: Prompt reports ErrNoOperator
		// when nobody is attached, which is the parking path, not this one.
		for i := 0; i < 200; i++ {
			if srv.console.anyAttached() {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		a, err := srv.console.Prompt(ctx, sshcarrier.Challenge{
			Addr:        "login.cluster.edu:22",
			User:        "ccb",
			Instruction: "Two-factor required",
			Questions:   []sshcarrier.Question{{Prompt: "Verification code:", Echo: false}},
		})
		if err != nil {
			failed <- err
			return
		}
		answered <- a
	}()

	var seen OperatorChallenge
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := FinishLogin(ctx, addr, plaintextSec(), func(c OperatorChallenge) ([]string, error) {
		seen = c
		return []string{"424242"}, nil
	})
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}

	if seen.Host != "login.cluster.edu:22" || seen.User != "ccb" {
		t.Errorf("the operator could not tell which login this was: %+v", seen)
	}
	if seen.Instruction != "Two-factor required" {
		t.Errorf("the server's preamble did not reach the operator: %q", seen.Instruction)
	}
	if len(seen.Questions) != 1 || seen.Questions[0].Prompt != "Verification code:" {
		t.Fatalf("questions = %+v", seen.Questions)
	}
	if seen.Questions[0].Echo {
		t.Error("a secret arrived marked echoable; a client would print it to the terminal")
	}

	select {
	case a := <-answered:
		if len(a) != 1 || a[0] != "424242" {
			t.Errorf("the carrier got %q", a)
		}
	case err := <-failed:
		t.Fatalf("the carrier's prompt failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the answer never reached the carrier")
	}
}

// Attaching to a healthy broker is not an error worth shouting about, and it
// must not hang: it reports that there was nothing to do.
func TestConsoleReportsNothingWaiting(t *testing.T) {
	addr, srv := startConsoleBroker(t)
	srv.cfg.OperatorWait = 500 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := FinishLogin(ctx, addr, plaintextSec(), func(OperatorChallenge) ([]string, error) {
		t.Error("the client was asked to answer something when nothing was waiting")
		return nil, nil
	})
	if !errors.Is(err, ErrNoLoginWaiting) && !strings.Contains(err.Error(), "no login waiting") {
		t.Fatalf("FinishLogin returned %v, want the nothing-waiting report", err)
	}
}

// Attaching releases a parked carrier even when there turns out to be nothing
// to answer: the visit is the signal.
func TestAttachingReleasesAParkedCarrier(t *testing.T) {
	addr, srv := startConsoleBroker(t)
	srv.cfg.OperatorWait = 500 * time.Millisecond

	srv.carrier.gate.Park(sshcarrier.ErrNoOperator)
	if _, parked := srv.carrier.gate.Parked(); !parked {
		t.Fatal("the gate did not park")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = FinishLogin(ctx, addr, plaintextSec(), func(OperatorChallenge) ([]string, error) {
		return nil, nil
	})

	if _, parked := srv.carrier.gate.Parked(); parked {
		t.Error("the carrier is still parked after an operator attached")
	}
	if n := srv.carrier.gate.Releases(); n != 1 {
		t.Errorf("gate released %d times, want 1", n)
	}
}

// An operator who gives up must tell the carrier, not just drop: a dropped
// connection reads as a network fault and leaves the carrier waiting.
func TestOperatorAbandoningIsReportedToTheCarrier(t *testing.T) {
	addr, srv := startConsoleBroker(t)

	failed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for i := 0; i < 200 && !srv.console.anyAttached(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		_, err := srv.console.Prompt(ctx, sshcarrier.Challenge{
			Addr:      "login.cluster.edu:22",
			Questions: []sshcarrier.Question{{Prompt: "Password:"}},
		})
		failed <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	want := errors.New("the operator pressed ctrl-c")
	if err := FinishLogin(ctx, addr, plaintextSec(), func(OperatorChallenge) ([]string, error) {
		return nil, want
	}); !errors.Is(err, want) {
		t.Fatalf("FinishLogin returned %v, want the abandon error", err)
	}

	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("the carrier was told the login succeeded")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the carrier was left waiting after the operator gave up")
	}
}
