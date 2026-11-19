package carrier

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// HumanGate holds back carrier attempts that failed for a reason only a person
// can clear, and releases them when one arrives.
//
// Backoff is the wrong tool for these. A host key nobody has approved, or a
// login that wanted a code with no operator attached, does not become more
// likely to succeed after a minute, or an hour, or a day -- the far side will
// ask the same question and there will still be no one to answer. Retrying is
// not merely wasted: at a site whose bastion counts failed logins, a broker
// that reconnects on a timer is a broker that gets the account locked.
//
// So the trigger is the operator, not the clock. An administrator who connects
// to finish the login releases the gate by the act of connecting, and the
// attempt resumes immediately rather than at the next tick of a backoff nobody
// chose.
//
// The zero value is an open gate.
type HumanGate struct {
	mu       sync.Mutex
	err      error     // why it is held, nil when open
	since    time.Time // when it was parked
	waiters  []chan struct{}
	releases int
}

// Park records that attempts are waiting on a person. Calling it again while
// parked updates the reason without disturbing anyone already waiting.
func (g *HumanGate) Park(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err == nil {
		g.since = time.Now()
	}
	g.err = err
}

// Release opens the gate and wakes everything waiting on it. It is what an
// operator's arrival calls. Releasing an open gate does nothing.
func (g *HumanGate) Release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err == nil {
		return
	}
	g.err = nil
	g.releases++
	for _, ch := range g.waiters {
		close(ch)
	}
	g.waiters = nil
}

// ParkState is why a gate is held and for how long. The duration is what makes
// a log line useful: "waiting for an operator" is noise, "waiting for an
// operator for 3 hours" is a page.
type ParkState struct {
	Reason error
	Since  time.Duration
}

// Parked reports the gate's state, and whether it is held at all.
func (g *HumanGate) Parked() (ParkState, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err == nil {
		return ParkState{}, false
	}
	return ParkState{Reason: g.err, Since: time.Since(g.since)}, true
}

// Releases counts how many times the gate has been opened, for tests.
func (g *HumanGate) Releases() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.releases
}

// Wait blocks while the gate is held. It returns immediately when open, and
// returns ctx.Err() if ctx ends first.
func (g *HumanGate) Wait(ctx context.Context) error {
	g.mu.Lock()
	if g.err == nil {
		g.mu.Unlock()
		return nil
	}
	ch := make(chan struct{})
	g.waiters = append(g.waiters, ch)
	g.mu.Unlock()

	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// NeedsHumanFunc classifies an error as one only a person can clear.
type NeedsHumanFunc func(error) bool

// WithNeedsHuman gives a listener a gate and a way to decide what belongs
// behind it. Without this the listener treats every failure as transient and
// retries on the backoff schedule.
func WithNeedsHuman(gate *HumanGate, classify NeedsHumanFunc) SourceOption {
	return func(l *SourceListener) {
		l.gate = gate
		l.needsHuman = classify
	}
}

// logParked reports a gate closing, once, at a level that matches what it
// means: nothing will happen here until somebody acts.
func logParked(log *slog.Logger, carrier string, err error) {
	log.Warn("carrier is waiting for an operator; it will not retry on its own",
		"carrier", carrier, "reason", err)
}
