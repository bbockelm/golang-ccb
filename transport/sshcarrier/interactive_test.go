package sshcarrier

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A server that demands a code gets one from the operator, and the carrier
// comes up. This is the case that cannot be done by spawning the system ssh.
func TestOperatorAnswersAChallenge(t *testing.T) {
	s := interactiveServer(t, "424242", echo)

	var seen atomic.Pointer[Challenge]
	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.authOverride = nil // force the interactive path
	cfg.Prompter = PrompterFunc(func(_ context.Context, c Challenge) ([]string, error) {
		seen.Store(&c)
		return []string{"424242"}, nil
	})

	c := dialTest(t, cfg)
	if _, err := c.Write([]byte("up")); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := seen.Load()
	if got == nil {
		t.Fatal("the operator was never asked")
	}
	if len(got.Questions) != 1 || !strings.Contains(got.Questions[0].Prompt, "Verification code") {
		t.Errorf("challenge did not carry the server's question: %+v", got.Questions)
	}
	if got.Questions[0].Echo {
		t.Error("a secret answer was marked echoable; an operator interface would display it")
	}
	if got.Instruction != "Two-factor required" {
		t.Errorf("instruction = %q; the server's own preamble must reach the operator", got.Instruction)
	}
}

// Nobody attached: the dial must fail in a way the retry policy can tell apart
// from an ordinary network failure, so it stops asking until someone arrives.
func TestNoOperatorIsClassifiedAsNeedsHuman(t *testing.T) {
	s := interactiveServer(t, "424242", echo)

	var asked atomic.Int32
	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.authOverride = nil
	cfg.Prompter = PrompterFunc(func(context.Context, Challenge) ([]string, error) {
		asked.Add(1)
		return nil, ErrNoOperator
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := Dial(ctx, cfg)
	if err == nil {
		t.Fatal("the dial succeeded with no operator and no key")
	}
	if !errors.Is(err, ErrNoOperator) {
		t.Errorf("error %v does not wrap ErrNoOperator", err)
	}
	if !NeedsHuman(err) {
		t.Error("NeedsHuman(err) is false; the retry loop would keep hammering a host nobody can log into")
	}
	if asked.Load() == 0 {
		t.Error("the prompter was never consulted")
	}
}

// A wrong answer is NOT a needs-human condition in the same sense -- the
// operator was there, they simply got it wrong, and the retry policy must not
// confuse "nobody is home" with "that code was stale".
func TestAWrongAnswerIsNotMistakenForNoOperator(t *testing.T) {
	s := interactiveServer(t, "424242", echo)

	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.authOverride = nil
	cfg.Prompter = PrompterFunc(func(context.Context, Challenge) ([]string, error) {
		return []string{"000000"}, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := Dial(ctx, cfg)
	if err == nil {
		t.Fatal("a wrong code was accepted")
	}
	if errors.Is(err, ErrNoOperator) {
		t.Error("a wrong answer was reported as nobody being attached")
	}
	if NeedsHuman(err) {
		t.Error("a wrong answer was classified as needs-human; the carrier would stop retrying a recoverable failure")
	}
}

// A host that takes a key must never wake an operator.
func TestKeyAuthDoesNotDisturbTheOperator(t *testing.T) {
	s := newTestSSHServer(t, echo)

	var asked atomic.Int32
	cfg := s.config("htc-ccb -carrier-stdio") // keeps the working key
	cfg.Prompter = PrompterFunc(func(context.Context, Challenge) ([]string, error) {
		asked.Add(1)
		return nil, ErrNoOperator
	})

	dialTest(t, cfg)
	if n := asked.Load(); n != 0 {
		t.Errorf("the operator was asked %d times for a host that accepts a key", n)
	}
}

// An empty challenge is the server talking to itself; it must not summon
// anyone. Some servers send one when they cannot tell in advance.
func TestEmptyChallengeDoesNotSummonAnOperator(t *testing.T) {
	s := newTestSSHServerWith(t, echo, func(cfg *ssh.ServerConfig) {
		cfg.PublicKeyCallback = nil
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, chal ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if _, err := chal("", "", nil, nil); err != nil {
				return nil, err
			}
			return &ssh.Permissions{}, nil
		}
	})

	var asked atomic.Int32
	cfg := s.config("htc-ccb -carrier-stdio")
	cfg.authOverride = nil
	cfg.Prompter = PrompterFunc(func(context.Context, Challenge) ([]string, error) {
		asked.Add(1)
		return nil, ErrNoOperator
	})

	c := dialTest(t, cfg)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("an empty challenge woke the operator %d times", n)
	}
}

// NeedsHuman must recognise an unapproved host key too: same policy, different
// cause.
func TestNeedsHumanCoversHostKeys(t *testing.T) {
	if !NeedsHuman(&HostKeyError{Addr: "h:22", Err: io.EOF}) {
		t.Error("a host-key failure is not classified as needing a human")
	}
	if NeedsHuman(io.EOF) {
		t.Error("an ordinary error was classified as needing a human")
	}
}
