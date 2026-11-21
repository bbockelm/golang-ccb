package ccbserver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// OperatorChallenge is a login a broker is stuck on, as the console presents
// it to whoever has come to finish it.
type OperatorChallenge struct {
	// Host and User say which login this is, so an operator answering for a
	// fleet can tell one from another before typing a secret into it.
	Host string
	User string
	// Instruction is the far server's own preamble, passed through unchanged.
	Instruction string
	Questions   []OperatorQuestion
}

// OperatorQuestion is one prompt.
type OperatorQuestion struct {
	Prompt string
	// Echo reports whether the answer may be shown as it is typed. A client
	// that ignores it will print somebody's password to a terminal.
	Echo bool
}

// AnswerFunc is asked to answer a challenge. Returning an error abandons the
// login and tells the broker why.
type AnswerFunc func(OperatorChallenge) ([]string, error)

// ErrNoLoginWaiting reports that the broker had nothing to ask.
//
// It is not a failure: it is the normal answer when an operator attaches to a
// broker that is working. Attaching still released the carrier's gate, so a
// broker parked on something else has been nudged by the visit.
var ErrNoLoginWaiting = fmt.Errorf("the broker has no login waiting for an operator")

// FinishLogin attaches to a broker's operator console and answers whatever
// login it is stuck on.
//
// Attaching is itself the signal for the broker to retry: a carrier parked for
// want of a person tries again the moment this connects, and the question it
// then asks arrives on this connection. So the usual sequence is one round
// trip, not a poll.
func FinishLogin(ctx context.Context, brokerAddr string, sec *security.SecurityConfig, answer AnswerFunc) error {
	addr := strings.Trim(brokerAddr, "<>")
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connecting to the broker at %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	s := stream.NewStream(conn)
	s.SetPeerAddr(addr)
	cfg := *sec
	cfg.Command = CommandFinishLogin
	if _, err := security.NewAuthenticator(&cfg, s).ClientHandshake(ctx); err != nil {
		return fmt.Errorf("authenticating to the broker at %s: %w", addr, err)
	}

	// The request ad carries nothing yet; the broker reads it to position the
	// stream and so a later version can send options.
	if err := ccb.WriteControlAd(ctx, s, ccb.NewAd(map[string]any{})); err != nil {
		return fmt.Errorf("sending the console request: %w", err)
	}

	ask, err := ccb.ReadControlAd(ctx, s)
	if err != nil {
		return fmt.Errorf("reading the broker's reply: %w", err)
	}
	if ok, _ := ccb.AdBool(ask, ccb.AttrResult); !ok {
		if msg := ccb.AdString(ask, ccb.AttrErrorString); strings.Contains(msg, "no login is waiting") {
			return ErrNoLoginWaiting
		} else if msg != "" {
			return fmt.Errorf("the broker refused: %s", msg)
		}
		return fmt.Errorf("the broker refused the console request")
	}

	prompts := splitUnit(ccb.AdString(ask, attrChallengeQuestions))
	echoes := splitUnit(ccb.AdString(ask, attrChallengeEcho))
	c := OperatorChallenge{
		Host:        ccb.AdString(ask, attrChallengeHost),
		User:        ccb.AdString(ask, attrChallengeUser),
		Instruction: ccb.AdString(ask, attrChallengeInstruction),
	}
	for i, p := range prompts {
		q := OperatorQuestion{Prompt: p}
		if i < len(echoes) {
			q.Echo = echoes[i] == "true"
		}
		c.Questions = append(c.Questions, q)
	}

	answers, err := answer(c)
	if err != nil {
		// Tell the broker rather than dropping the connection: it is waiting,
		// and a dropped connection reads as a network fault.
		_ = ccb.WriteControlAd(ctx, s, ccb.NewAd(map[string]any{attrChallengeAnswers: ""}))
		return err
	}
	if err := ccb.WriteControlAd(ctx, s, ccb.NewAd(map[string]any{
		attrChallengeAnswers: joinUnit(answers),
	})); err != nil {
		return fmt.Errorf("sending the answers: %w", err)
	}

	result, err := ccb.ReadControlAd(ctx, s)
	if err != nil {
		return fmt.Errorf("reading the result: %w", err)
	}
	if ok, _ := ccb.AdBool(result, ccb.AttrResult); !ok {
		return fmt.Errorf("the broker rejected the answers: %s", ccb.AdString(result, ccb.AttrErrorString))
	}
	return nil
}

// WaitForLogin is FinishLogin with patience: a broker that has nothing to ask
// right now may have in a moment, because the carrier it just released takes a
// connect or two to get as far as the question.
func WaitForLogin(ctx context.Context, brokerAddr string, sec *security.SecurityConfig, within time.Duration, answer AnswerFunc) error {
	deadline := time.Now().Add(within)
	for {
		err := FinishLogin(ctx, brokerAddr, sec, answer)
		if err == nil || !isNoLoginWaiting(err) {
			return err
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func isNoLoginWaiting(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no login waiting")
}
