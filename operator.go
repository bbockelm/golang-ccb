package ccbserver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bbockelm/cedar/ccb"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/golang-ccb/transport/sshcarrier"
)

// CommandFinishLogin is the operator console: an administrator connects, is
// handed whatever login the broker is stuck on, and answers it.
//
// 84 continues the CCB tunneling block (82 proxy-connect, 83
// get-tunnel-address). It is NOT allocated upstream: HTCondor's
// condor_commands.h is the authoritative list, and shipping this needs a
// number reserved there so a later CCB command cannot collide with it.
const CommandFinishLogin = 84

// Attribute names on the console's wire ads. They are local to this command.
const (
	attrChallengeInstruction = "ChallengeInstruction"
	attrChallengeHost        = "ChallengeHost"
	attrChallengeUser        = "ChallengeUser"
	attrChallengeQuestions   = "ChallengeQuestions"
	attrChallengeEcho        = "ChallengeEcho"
	attrChallengeAnswers     = "ChallengeAnswers"
)

// DefaultOperatorWait is how long an attached operator waits for the broker to
// reach the point of asking something. A carrier parked on a needs-human
// failure retries the moment the operator attaches, so the question normally
// arrives within a connect; the rest of this budget is for a slow bastion.
const DefaultOperatorWait = 2 * time.Minute

// DefaultAnswerWait is how long the carrier waits for the operator to type.
const DefaultAnswerWait = 5 * time.Minute

// pendingLogin is one question waiting for a person, and the channel its
// answers come back on.
type pendingLogin struct {
	challenge sshcarrier.Challenge
	answers   chan []string
	failed    chan error
}

// operatorConsole rendezvouses a carrier that needs a human with a human who
// has turned up.
//
// The ordering is the whole design. A carrier that needs input and finds
// nobody does not wait and does not retry -- it parks (see
// carrier.HumanGate), because the server will ask the same question forever
// and nobody will answer it. The operator's arrival is what releases the gate,
// so connecting to answer the question and telling the carrier to try again
// are one act rather than two.
type operatorConsole struct {
	mu       sync.Mutex
	attached int

	// pending carries a challenge from the carrier to whichever operator is
	// listening. It is unbuffered: a challenge exists only while someone is
	// waiting on the other side of it.
	pending chan *pendingLogin
}

func newOperatorConsole() *operatorConsole {
	return &operatorConsole{pending: make(chan *pendingLogin)}
}

func (o *operatorConsole) attach() { o.mu.Lock(); o.attached++; o.mu.Unlock() }
func (o *operatorConsole) detach() { o.mu.Lock(); o.attached--; o.mu.Unlock() }
func (o *operatorConsole) anyAttached() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.attached > 0
}

// Prompt implements sshcarrier.Prompter. It is what the SSH carrier calls when
// a server wants something only a person can supply.
func (o *operatorConsole) Prompt(ctx context.Context, c sshcarrier.Challenge) ([]string, error) {
	if !o.anyAttached() {
		// Nobody to ask. Saying so immediately is what lets the carrier park
		// rather than sit in a doomed handshake holding a connection open.
		return nil, sshcarrier.ErrNoOperator
	}
	p := &pendingLogin{
		challenge: c,
		answers:   make(chan []string, 1),
		failed:    make(chan error, 1),
	}
	select {
	case o.pending <- p:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case a := <-p.answers:
		return a, nil
	case err := <-p.failed:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// handleFinishLogin serves an administrator attaching to finish a login.
//
// Attaching releases the carrier's gate, so a broker parked for want of a
// person retries at once and its question arrives on this connection.
func (s *Server) handleFinishLogin(ctx context.Context, c *cedarserver.Conn) error {
	if err := s.authorize(c, CommandFinishLogin); err != nil {
		s.log.Warn("finish-login denied", "remote", c.RemoteAddr, "error", err)
		return ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(map[string]any{
			ccb.AttrResult:      false,
			ccb.AttrErrorString: "authorization denied",
		}))
	}
	// The request ad carries nothing the broker needs yet; read it so the
	// stream is positioned, and so a future version can send options.
	if _, err := ccb.ReadControlAd(ctx, c.Stream); err != nil {
		return err
	}

	s.console.attach()
	defer s.console.detach()

	// An operator is here: let anything parked try again.
	if s.carrier != nil {
		s.carrier.gate.Release()
	}
	s.log.Info("an operator attached to finish a login", "remote", c.RemoteAddr, "user", c.AuthorizationUser())

	wait := s.cfg.OperatorWait
	if wait <= 0 {
		wait = DefaultOperatorWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	var p *pendingLogin
	select {
	case p = <-s.console.pending:
	case <-timer.C:
		return ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(map[string]any{
			ccb.AttrResult:      false,
			ccb.AttrErrorString: "no login is waiting for an operator",
		}))
	case <-ctx.Done():
		return ctx.Err()
	}

	// Hand the question over.
	prompts := make([]string, len(p.challenge.Questions))
	echo := make([]string, len(p.challenge.Questions))
	for i, q := range p.challenge.Questions {
		prompts[i] = q.Prompt
		echo[i] = fmt.Sprintf("%t", q.Echo)
	}
	ask := ccb.NewAd(map[string]any{
		ccb.AttrResult:           true,
		attrChallengeHost:        p.challenge.Addr,
		attrChallengeUser:        p.challenge.User,
		attrChallengeInstruction: p.challenge.Instruction,
		attrChallengeQuestions:   joinUnit(prompts),
		attrChallengeEcho:        joinUnit(echo),
	})
	if err := ccb.WriteControlAd(ctx, c.Stream, ask); err != nil {
		p.failed <- fmt.Errorf("the operator's connection dropped before the question reached them: %w", err)
		return err
	}

	reply, err := ccb.ReadControlAd(ctx, c.Stream)
	if err != nil {
		p.failed <- fmt.Errorf("the operator's connection dropped before an answer arrived: %w", err)
		return err
	}
	answers := splitUnit(ccb.AdString(reply, attrChallengeAnswers))
	if len(answers) != len(prompts) {
		err := fmt.Errorf("the operator sent %d answers for %d questions", len(answers), len(prompts))
		p.failed <- err
		return ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(map[string]any{
			ccb.AttrResult:      false,
			ccb.AttrErrorString: err.Error(),
		}))
	}
	p.answers <- answers
	s.log.Info("an operator answered a login challenge", "remote", c.RemoteAddr, "questions", len(prompts))
	return ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(map[string]any{ccb.AttrResult: true}))
}

// joinUnit and splitUnit carry a list of free-text strings in one ClassAd
// attribute. The unit separator is used rather than a comma because a prompt
// or an answer may contain anything at all -- a passphrase with a comma in it
// must not become two answers.
const unitSep = "\x1f"

func joinUnit(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += unitSep
		}
		out += s
	}
	return out
}

func splitUnit(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, r := range s {
		if string(r) == unitSep {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}
