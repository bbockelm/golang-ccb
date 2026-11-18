package sshcarrier

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ErrNoOperator reports that the far server asked for something only a person
// can supply, and nobody was attached to supply it.
//
// This is not a transport failure and retrying it changes nothing: the server
// will ask the same question again, and there will still be no one to answer.
// It is the condition the carrier's retry policy waits on an operator to clear.
var ErrNoOperator = errors.New("sshcarrier: the server asked for input and no operator is attached")

// Question is one prompt from the server.
type Question struct {
	Prompt string
	// Echo reports whether the answer may be shown as it is typed. It is false
	// for a password, and an operator interface must honour it.
	Echo bool
}

// Challenge is what the far server wants answered, addressed to a person.
type Challenge struct {
	// Addr and User identify what is being logged into, so an operator can
	// tell which of several pending logins they are answering.
	Addr string
	User string
	// Instruction is the server's own preamble, if it sent one.
	Instruction string
	Questions   []Question
}

// Prompter supplies answers to a server's challenge.
//
// The broker implements this over its CEDAR command surface: an administrator
// connects, is handed the pending challenge, and sends the answers back. That
// same connection is what tells the carrier to try again -- the arrival of an
// operator is the event, so there is nothing to poll and nothing to guess.
//
// Prompt returns ErrNoOperator when nobody is attached. It should block while
// someone is, bounded by ctx.
type Prompter interface {
	Prompt(ctx context.Context, c Challenge) ([]string, error)
}

// PrompterFunc adapts a function to Prompter.
type PrompterFunc func(ctx context.Context, c Challenge) ([]string, error)

func (f PrompterFunc) Prompt(ctx context.Context, c Challenge) ([]string, error) { return f(ctx, c) }

// NeedsHuman reports whether err describes a condition that will not clear
// until a person acts: an unapproved host key, or a login that needed an
// operator who was not there.
//
// A carrier retry loop uses this to stop hammering something no amount of
// waiting will fix. Everything else -- a refused connection, a dead route, a
// server that is down -- is ordinary and should be retried.
func NeedsHuman(err error) bool {
	if errors.Is(err, ErrNoOperator) {
		return true
	}
	var nh interface{ NeedsHuman() bool }
	if errors.As(err, &nh) {
		return nh.NeedsHuman()
	}
	return false
}

// needsHumanError marks a failure as awaiting a person.
type needsHumanError struct{ err error }

func (e *needsHumanError) Error() string    { return e.err.Error() }
func (e *needsHumanError) Unwrap() error    { return e.err }
func (e *needsHumanError) NeedsHuman() bool { return true }

// authState records what happened inside the auth callbacks.
//
// x/crypto/ssh reports only that authentication failed; which method failed and
// why is lost. Without this, "nobody was there to type the password" is
// indistinguishable from "the password was wrong", and the first must stop the
// retry loop while the second should not.
type authState struct {
	mu         sync.Mutex
	noOperator bool
	promptErr  error
	askedHuman bool
}

func (a *authState) record(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.askedHuman = true
	if errors.Is(err, ErrNoOperator) {
		a.noOperator = true
	}
	if err != nil && a.promptErr == nil {
		a.promptErr = err
	}
}

// classify turns a handshake failure into one the retry policy can act on.
func (a *authState) classify(err error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.noOperator:
		// Both causes are wrapped: a caller can test for ErrNoOperator and
		// still reach the underlying handshake error.
		return &needsHumanError{err: fmt.Errorf("%w: %w", ErrNoOperator, err)}
	case a.promptErr != nil:
		return fmt.Errorf("sshcarrier: the operator did not complete the login: %w", a.promptErr)
	default:
		return err
	}
}

// interactiveAuth answers a keyboard-interactive challenge by asking the
// operator.
//
// A server that sends no questions is answering its own challenge -- some send
// an empty one when they cannot tell in advance whether it is needed -- and
// must not summon a person for nothing.
func interactiveAuth(ctx context.Context, cfg Config, st *authState) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		if len(questions) == 0 {
			return nil, nil
		}
		c := Challenge{Addr: cfg.Addr, User: user, Instruction: instruction}
		for i, q := range questions {
			echo := false
			if i < len(echos) {
				echo = echos[i]
			}
			c.Questions = append(c.Questions, Question{Prompt: q, Echo: echo})
		}
		answers, err := cfg.Prompter.Prompt(ctx, c)
		if err != nil {
			st.record(err)
			return nil, err
		}
		st.record(nil)
		return answers, nil
	})
}

// passwordAuth asks the operator for a password.
func passwordAuth(ctx context.Context, cfg Config, st *authState) ssh.AuthMethod {
	return ssh.PasswordCallback(func() (string, error) {
		c := Challenge{
			Addr:      cfg.Addr,
			User:      cfg.User,
			Questions: []Question{{Prompt: "Password:", Echo: false}},
		}
		answers, err := cfg.Prompter.Prompt(ctx, c)
		if err != nil {
			st.record(err)
			return "", err
		}
		if len(answers) == 0 {
			err := errors.New("sshcarrier: the operator returned no password")
			st.record(err)
			return "", err
		}
		st.record(nil)
		return answers[0], nil
	})
}
