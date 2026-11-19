package ccbserver

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-ccb/transport/sshcarrier"
)

func testChallenge() sshcarrier.Challenge {
	return sshcarrier.Challenge{
		Addr:        "login.cluster.edu:22",
		User:        "ccb",
		Instruction: "Two-factor required",
		Questions:   []sshcarrier.Question{{Prompt: "Verification code:", Echo: false}},
	}
}

// With nobody attached the carrier must be told so at once. Waiting would hold
// a doomed handshake open; retrying would ask a question nobody can hear.
func TestPromptWithNoOperatorFailsImmediately(t *testing.T) {
	o := newOperatorConsole()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err := o.Prompt(ctx, testChallenge())
	if !errors.Is(err, sshcarrier.ErrNoOperator) {
		t.Fatalf("Prompt returned %v, want ErrNoOperator", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %v to report that nobody is attached; it must not wait", elapsed)
	}
}

// The rendezvous: an attached operator receives the question and their answer
// reaches the carrier.
func TestOperatorReceivesTheChallengeAndAnswers(t *testing.T) {
	o := newOperatorConsole()
	o.attach()
	defer o.detach()

	got := make(chan sshcarrier.Challenge, 1)
	go func() {
		select {
		case p := <-o.pending:
			got <- p.challenge
			p.answers <- []string{"424242"}
		case <-time.After(10 * time.Second):
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	answers, err := o.Prompt(ctx, testChallenge())
	if err != nil {
		t.Fatalf("Prompt: %v", err)
	}
	if len(answers) != 1 || answers[0] != "424242" {
		t.Errorf("answers = %q", answers)
	}

	select {
	case c := <-got:
		if c.Instruction != "Two-factor required" || len(c.Questions) != 1 {
			t.Errorf("the operator got %+v; the server's own question must reach them", c)
		}
		if c.Questions[0].Echo {
			t.Error("a secret was marked echoable")
		}
	default:
		t.Fatal("the operator never saw the challenge")
	}
}

// If the operator's connection drops, the carrier must be told rather than
// left blocked until its context expires.
func TestOperatorFailureReachesTheCarrier(t *testing.T) {
	o := newOperatorConsole()
	o.attach()
	defer o.detach()

	go func() {
		p := <-o.pending
		p.failed <- errors.New("the operator's connection dropped")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := o.Prompt(ctx, testChallenge()); err == nil {
		t.Fatal("Prompt succeeded after the operator failed")
	} else if !strings.Contains(err.Error(), "dropped") {
		t.Errorf("error %q does not say what went wrong", err)
	}
}

// A free-text answer may contain anything; splitting on a comma would turn one
// passphrase into two answers.
func TestAnswersSurviveAwkwardText(t *testing.T) {
	for _, in := range [][]string{
		{"plain"},
		{"has, a comma", "and another"},
		{"", "empty first"},
		{"newline\nin it", "tab\there"},
	} {
		if got := splitUnit(joinUnit(in)); len(got) != len(in) {
			t.Errorf("round trip of %q produced %q", in, got)
			continue
		} else {
			for i := range in {
				if got[i] != in[i] {
					t.Errorf("round trip of %q produced %q", in, got)
					break
				}
			}
		}
	}
	if got := splitUnit(""); got != nil {
		t.Errorf("splitUnit(\"\") = %q, want nil", got)
	}
}

// The console is only offered where a carrier could actually ask a person: an
// ordinary broker should not carry the surface at all.
func TestOnlyAnSSHCarrierCanAskAnOperator(t *testing.T) {
	for _, tc := range []struct {
		scheme string
		want   bool
	}{
		{"ssh", true},
		{"cmd", false},
		{"ws", false},
		{"fs", false},
		{"tcp", false},
		{"stdio", false},
	} {
		// Via the inside knob.
		s := &Server{carrier: &carrierClient{ref: carrierRef{scheme: tc.scheme}}}
		if got := s.canAskAnOperator(); got != tc.want {
			t.Errorf("scheme %q on the inside knob: canAskAnOperator() = %v, want %v", tc.scheme, got, tc.want)
		}
	}
}

// A parked carrier must not dial. The whole point is that the far server would
// ask the same question and nobody would be there.
func TestAParkedCarrierDoesNotDial(t *testing.T) {
	kh := t.TempDir() + "/known_hosts"
	if err := writeFile(kh, ""); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		PublicAddress:           "127.0.0.1:9618",
		Security:                plaintextSec(),
		OutboundNextHop:         "ssh://login.cluster.edu",
		OutboundNextHopSecurity: plaintextSec(),
		CarrierSSH: SSHCarrierConfig{
			KnownHosts:  []string{kh},
			StageBinary: "/nonexistent/htc-ccb",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv.carrier.gate.Park(sshcarrier.ErrNoOperator)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = srv.carrier.src.Pipe(ctx)
	if err == nil {
		t.Fatal("a parked carrier dialed anyway")
	}
	if !strings.Contains(err.Error(), "waiting for an operator") {
		t.Errorf("error %q does not say it is parked", err)
	}

	// And an operator attaching releases it.
	srv.console.attach()
	defer srv.console.detach()
	srv.carrier.gate.Release()
	if _, parked := srv.carrier.gate.Parked(); parked {
		t.Error("the gate is still parked after a release")
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// An outside broker reaching into a cluster over ssh:// meets the same
// two-factor prompt as an inside broker reaching out, and its carrier is
// built by the listener rather than by detectCarrier -- so the console has to
// be offered for that role too.
func TestConsoleIsOfferedForAnOutsideSSHCarrier(t *testing.T) {
	s := &Server{cfg: Config{CarrierListen: "ssh://login.cluster.edu"}}
	if !s.canAskAnOperator() {
		t.Error("an outside ssh:// carrier does not offer the console; a login needing a person could never be finished")
	}
	plain := &Server{cfg: Config{CarrierListen: "tcp://127.0.0.1:9700"}}
	if plain.canAskAnOperator() {
		t.Error("a tcp:// listener offers the console")
	}
}

// The gate must exist before anything dials. It lives on the Server because
// both roles need it and only one of them builds a carrierClient through
// detectCarrier; a nil gate here was a panic in the outside role.
func TestEveryCarrierRoleHasAGate(t *testing.T) {
	kh := t.TempDir() + "/known_hosts"
	if err := writeFile(kh, ""); err != nil {
		t.Fatal(err)
	}
	sc := SSHCarrierConfig{KnownHosts: []string{kh}, StageBinary: "/nonexistent/htc-ccb"}

	inside, err := New(Config{
		PublicAddress: "127.0.0.1:9618", Security: plaintextSec(),
		OutboundNextHop: "ssh://h", OutboundNextHopSecurity: plaintextSec(), CarrierSSH: sc,
	})
	if err != nil {
		t.Fatalf("inside role: %v", err)
	}
	if inside.gate == nil || inside.carrier == nil || inside.carrier.gate == nil {
		t.Error("the inside role has no gate")
	}
	if inside.carrier.gate != inside.gate {
		t.Error("the carrier does not share the broker's gate, so the console would release the wrong one")
	}

	outside, err := New(Config{
		PublicAddress: "127.0.0.1:9618", Security: plaintextSec(),
		CarrierListen: "ssh://h", CarrierSSH: sc,
	})
	if err != nil {
		t.Fatalf("outside role: %v", err)
	}
	if outside.gate == nil {
		t.Error("the outside role has no gate")
	}
}
