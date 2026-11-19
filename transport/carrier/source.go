package carrier

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// ErrPipeExhausted reports a pipe source that can never produce another pipe.
// A broker whose only transport is exhausted has nothing left to do, which is
// different from one whose carrier is merely down and will be retried.
var ErrPipeExhausted = errors.New("carrier: the pipe source is exhausted")

// A PipeSource yields carrier byte pipes.
//
// It is the seam that separates *how* a pipe is obtained -- dialed out,
// accepted, or inherited from a parent process -- from *which role* the broker
// plays over it. The inside broker runs a MuxDialer over a pipe and the outside
// broker runs a MuxListener over pipes, and until this type existed those two
// choices were welded to dialing and accepting respectively. They are not the
// same choice: an outside broker that reaches into a restricted network by
// running `ssh login-node htc-ccb` obtains its pipe by dialing while still
// playing the outside role, and the broker it starts there plays the inside role
// over a pipe it did not dial.
//
// A source is used by exactly one of the two roles at a time.
type PipeSource interface {
	// Pipe returns the next carrier pipe, blocking until one is available or
	// ctx is done. It returns ErrPipeExhausted when no further pipe can ever
	// arrive, and net.ErrClosed after Close.
	Pipe(ctx context.Context) (net.Conn, error)

	// Describe names the source for logs and errors.
	Describe() string

	Close() error
}

// DialFunc establishes one carrier pipe.
type DialFunc func(ctx context.Context) (net.Conn, error)

// Dialing returns a PipeSource that establishes a new pipe on every call. It is
// the source for any carrier this broker reaches out over: a WebSocket, a
// filesystem rendezvous, a spawned command.
func Dialing(label string, dial DialFunc) PipeSource {
	return &dialSource{label: label, dial: dial}
}

type dialSource struct {
	label  string
	dial   DialFunc
	closed closeFlag
}

func (s *dialSource) Pipe(ctx context.Context) (net.Conn, error) {
	if s.closed.isSet() {
		return nil, net.ErrClosed
	}
	return s.dial(ctx)
}

func (s *dialSource) Describe() string { return s.label }

func (s *dialSource) Close() error {
	s.closed.set()
	return nil
}

// Accepting returns a PipeSource that takes each pipe from ln. It takes
// ownership of ln and closes it on Close.
func Accepting(label string, ln net.Listener) PipeSource {
	return &acceptSource{label: label, ln: ln}
}

type acceptSource struct {
	label string
	ln    net.Listener
}

func (s *acceptSource) Pipe(ctx context.Context) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := s.ln.Accept()
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *acceptSource) Describe() string { return s.label }

func (s *acceptSource) Close() error { return s.ln.Close() }

// OnePipe returns a PipeSource that yields c exactly once.
//
// This is the stdio carrier: a broker started by `ssh host htc-ccb
// -carrier-stdio` inherits one pipe from its parent and can never obtain
// another, so the second call reports ErrPipeExhausted rather than blocking.
// A broker whose stdio carrier has closed should exit -- its parent ssh is
// gone, and nothing can reach it any more.
func OnePipe(label string, c net.Conn) PipeSource {
	return &oneSource{label: label, c: c}
}

type oneSource struct {
	label string

	mu     sync.Mutex
	c      net.Conn
	taken  bool
	closed bool
}

func (s *oneSource) Pipe(context.Context) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return nil, net.ErrClosed
	case s.taken:
		return nil, ErrPipeExhausted
	}
	s.taken = true
	return s.c, nil
}

func (s *oneSource) Describe() string { return s.label }

func (s *oneSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if !s.taken && s.c != nil {
		return s.c.Close()
	}
	return nil
}

// Backoff bounds how fast a SourceListener retries a source that is failing.
type Backoff struct {
	Initial time.Duration
	Max     time.Duration
}

// DefaultBackoff is deliberately slow at the top end. A carrier that fails is
// usually failing for a reason that will not clear in a second -- a host that is
// down, a credential that is wrong -- and a broker that spawns an ssh every
// second against a site's bastion looks like an attack.
var DefaultBackoff = Backoff{Initial: time.Second, Max: time.Minute}

func (b Backoff) next(d time.Duration) time.Duration {
	initial, max := b.Initial, b.Max
	if initial <= 0 {
		initial = DefaultBackoff.Initial
	}
	if max <= 0 {
		max = DefaultBackoff.Max
	}
	if d <= 0 {
		return initial
	}
	d *= 2
	if d > max {
		d = max
	}
	return d
}

// jitter spreads retries so a pool of brokers that lost the same carrier does
// not return in lockstep.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d/2 + time.Duration(rand.Int64N(int64(d)))
}

// SourceListener presents a PipeSource as a net.Listener, so MuxListener (and
// through it the whole cedar command loop) runs over any source unchanged.
//
// It retries internally. MuxListener stops accepting on the first error its
// inner listener returns, so a transient failure -- a bastion that is briefly
// unreachable -- must not surface as one, or the outside broker would give up
// permanently on the first blip. Accept therefore returns an error only once the
// listener is closed or the source is exhausted.
type SourceListener struct {
	src     PipeSource
	log     *slog.Logger
	backoff Backoff

	// token, when non-nil, serializes pipes: one at a time, the next obtained
	// only once the last has closed.
	token chan struct{}

	// gate holds attempts that failed for a reason only a person can clear.
	// needsHuman decides which failures those are; without both, every failure
	// is treated as transient and retried on the backoff schedule.
	gate       *HumanGate
	needsHuman NeedsHumanFunc

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// SourceOption adjusts a SourceListener.
type SourceOption func(*SourceListener)

// OnePipeAtATime makes the listener hold at most one pipe, obtaining the next
// only after that one has closed.
//
// A listener over a *dialing* source needs this, and it is the difference
// between maintaining a link and a fork bomb: MuxListener accepts pipes in a
// loop, so an outside broker whose carrier is `cmd:ssh node htc-ccb` would
// otherwise spawn a second ssh the instant the first pipe was handed over, and
// keep going. With it, the command is run once, re-run when the pipe dies, and
// the backoff above governs how fast.
//
// A listener over an accepting source (a TCP or WebSocket carrier) must NOT set
// it: there, many pipes at once is the whole point.
func OnePipeAtATime() SourceOption {
	return func(l *SourceListener) {
		l.token = make(chan struct{}, 1)
		l.token <- struct{}{}
	}
}

// NewSourceListener adapts src. It takes ownership of src and closes it on
// Close.
func NewSourceListener(src PipeSource, log *slog.Logger, backoff Backoff, opts ...SourceOption) *SourceListener {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &SourceListener{src: src, log: log, backoff: backoff, ctx: ctx, cancel: cancel}
	for _, o := range opts {
		o(l)
	}
	return l
}

func (l *SourceListener) Accept() (net.Conn, error) {
	if l.token != nil {
		select {
		case <-l.token:
		case <-l.ctx.Done():
			return nil, net.ErrClosed
		}
	}
	var delay time.Duration
	for {
		if err := l.ctx.Err(); err != nil {
			return nil, net.ErrClosed
		}
		c, err := l.src.Pipe(l.ctx)
		switch {
		case err == nil:
			return l.tracked(c), nil
		case errors.Is(err, ErrPipeExhausted):
			return nil, err
		case l.ctx.Err() != nil:
			return nil, net.ErrClosed
		}
		// A failure only a person can clear does not belong on a timer. Park
		// and wait for an operator instead; the backoff is reset so that when
		// one arrives the retry is immediate rather than an hour late.
		if l.gate != nil && l.needsHuman != nil && l.needsHuman(err) {
			l.gate.Park(err)
			logParked(l.log, l.src.Describe(), err)
			if werr := l.gate.Wait(l.ctx); werr != nil {
				return nil, net.ErrClosed
			}
			l.log.Info("an operator released the carrier; retrying now", "carrier", l.src.Describe())
			delay = 0
			continue
		}

		delay = l.backoff.next(delay)
		wait := jitter(delay)
		l.log.Warn("carrier pipe unavailable; retrying",
			"carrier", l.src.Describe(), "retry_in", wait.Round(time.Millisecond), "error", err)
		select {
		case <-time.After(wait):
		case <-l.ctx.Done():
			return nil, net.ErrClosed
		}
	}
}

func (l *SourceListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.cancel()
		err = l.src.Close()
	})
	return err
}

func (l *SourceListener) Addr() net.Addr { return sourceAddr(l.src.Describe()) }

// tracked returns the token when the pipe closes, releasing the next Accept.
func (l *SourceListener) tracked(c net.Conn) net.Conn {
	if l.token == nil {
		return c
	}
	return &trackedConn{Conn: c, release: func() {
		select {
		case l.token <- struct{}{}:
		default: // already released
		}
	}}
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

type sourceAddr string

func (a sourceAddr) Network() string { return "carrier" }
func (a sourceAddr) String() string  { return string(a) }

// closeFlag is a mutex-free one-way flag.
type closeFlag struct {
	mu sync.Mutex
	v  bool
}

func (f *closeFlag) set() {
	f.mu.Lock()
	f.v = true
	f.mu.Unlock()
}

func (f *closeFlag) isSet() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.v
}

var _ net.Listener = (*SourceListener)(nil)
