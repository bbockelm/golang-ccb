package carrier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// pipePair is a usable net.Conn pair for a source to hand out.
func pipePair() (net.Conn, net.Conn) { return net.Pipe() }

type countingSource struct {
	calls atomic.Int64
	fail  atomic.Int64 // fail this many calls before succeeding
	conns []net.Conn
}

func (s *countingSource) Pipe(context.Context) (net.Conn, error) {
	n := s.calls.Add(1)
	if s.fail.Load() >= n {
		return nil, fmt.Errorf("source unavailable (attempt %d)", n)
	}
	a, b := pipePair()
	s.conns = append(s.conns, b)
	return a, nil
}

func (s *countingSource) Describe() string { return "counting" }
func (s *countingSource) Close() error     { return nil }

// Without OnePipeAtATime a dialing source behind MuxListener's accept loop is a
// fork bomb: the loop asks for the next pipe the moment it has one, so an
// outside broker on `cmd:ssh node htc-ccb` would spawn ssh after ssh. The
// listener must hand out one pipe and then wait for it to close.
func TestOnePipeAtATimeWaitsForTheLivePipe(t *testing.T) {
	src := &countingSource{}
	l := NewSourceListener(src, nil, DefaultBackoff, OnePipeAtATime())
	defer func() { _ = l.Close() }()

	first, err := l.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}

	// A second Accept must block while the first pipe is alive.
	second := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			second <- c
		}
	}()
	select {
	case <-second:
		t.Fatal("a second pipe was obtained while the first was still open")
	case <-time.After(250 * time.Millisecond):
	}
	if got := src.calls.Load(); got != 1 {
		t.Fatalf("source was asked for %d pipes while one was live, want 1", got)
	}

	// Closing the live pipe releases the next one.
	_ = first.Close()
	select {
	case c := <-second:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("closing the live pipe did not release the next Accept")
	}
	if got := src.calls.Load(); got != 2 {
		t.Errorf("source was asked for %d pipes, want 2", got)
	}
}

// An accepting carrier (TCP, WebSocket) must not be serialized -- many inside
// brokers at once is the whole point.
func TestWithoutOnePipeAtATimeAcceptsConcurrently(t *testing.T) {
	src := &countingSource{}
	l := NewSourceListener(src, nil, DefaultBackoff)
	defer func() { _ = l.Close() }()

	for i := 0; i < 3; i++ {
		if _, err := l.Accept(); err != nil {
			t.Fatalf("Accept %d: %v", i, err)
		}
	}
	if got := src.calls.Load(); got != 3 {
		t.Errorf("got %d pipes without closing any, want 3", got)
	}
}

// MuxListener stops accepting on the first error its inner listener returns, so
// a transient failure must be retried inside Accept rather than surfaced. An
// outside broker whose bastion is briefly unreachable has to come back.
func TestAcceptRetriesTransientFailures(t *testing.T) {
	src := &countingSource{}
	src.fail.Store(3)
	l := NewSourceListener(src, nil, Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond})
	defer func() { _ = l.Close() }()

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept did not retry past transient failures: %v", err)
	}
	_ = c.Close()
	if got := src.calls.Load(); got != 4 {
		t.Errorf("source was called %d times, want 4 (3 failures then a success)", got)
	}
}

// An exhausted source is not a transient failure and must not be retried: there
// is nothing to come back to.
func TestAcceptReportsExhaustion(t *testing.T) {
	a, _ := pipePair()
	src := OnePipe("stdio", a)
	l := NewSourceListener(src, nil, Backoff{Initial: time.Millisecond, Max: time.Millisecond})
	defer func() { _ = l.Close() }()

	if _, err := l.Accept(); err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrPipeExhausted) {
			t.Fatalf("second Accept = %v, want ErrPipeExhausted", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a second Accept on an exhausted source blocked instead of reporting it")
	}
}

func TestOnePipeYieldsOnce(t *testing.T) {
	a, _ := pipePair()
	src := OnePipe("stdio", a)
	got, err := src.Pipe(context.Background())
	if err != nil || got != a {
		t.Fatalf("Pipe = %v, %v; want the pipe it was given", got, err)
	}
	if _, err := src.Pipe(context.Background()); !errors.Is(err, ErrPipeExhausted) {
		t.Errorf("second Pipe = %v, want ErrPipeExhausted", err)
	}
}

// A source closed before its pipe was ever handed out still closes the pipe,
// so an unused stdio carrier does not leak its descriptors.
func TestOnePipeCloseReleasesAnUntakenPipe(t *testing.T) {
	a, b := pipePair()
	defer func() { _ = b.Close() }()
	src := OnePipe("stdio", a)
	if err := src.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Error("the pipe was not closed with the source")
	}
	if _, err := src.Pipe(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Pipe after Close = %v, want net.ErrClosed", err)
	}
}

func TestCloseStopsAccept(t *testing.T) {
	src := &countingSource{}
	src.fail.Store(1 << 30) // never succeeds
	l := NewSourceListener(src, nil, Backoff{Initial: 10 * time.Millisecond, Max: 10 * time.Millisecond})

	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = l.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not stop a retrying Accept")
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	b := Backoff{Initial: time.Second, Max: 4 * time.Second}
	var d time.Duration
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	for i, w := range want {
		d = b.next(d)
		if d != w {
			t.Errorf("step %d = %s, want %s", i, d, w)
		}
	}
}
