package carrier

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

var errNeedsHuman = errors.New("the server asked for a code and nobody is attached")

// A failure only a person can clear must stop the retry loop dead. The point
// is not to save a few connections: a broker that reconnects on a timer against
// a bastion that counts failed logins is a broker that locks the account out.
func TestListenerStopsRetryingWhenAFailureNeedsAHuman(t *testing.T) {
	var attempts atomic.Int32
	src := Dialing("ssh://cluster", func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		return nil, errNeedsHuman
	})

	gate := &HumanGate{}
	l := NewSourceListener(src, nil, Backoff{Initial: time.Millisecond, Max: time.Millisecond},
		WithNeedsHuman(gate, func(err error) bool { return errors.Is(err, errNeedsHuman) }))
	defer func() { _ = l.Close() }()

	go func() { _, _ = l.Accept() }()

	// The backoff is a millisecond, so an ungated loop would run away.
	time.Sleep(300 * time.Millisecond)
	if n := attempts.Load(); n != 1 {
		t.Fatalf("made %d attempts while parked; it must stop after the first", n)
	}
	st, parked := gate.Parked()
	if !parked {
		t.Fatal("the gate is not parked")
	}
	if !errors.Is(st.Reason, errNeedsHuman) {
		t.Errorf("parked for %v, want the needs-human error", st.Reason)
	}
	if st.Since <= 0 {
		t.Error("the gate does not report how long it has been waiting")
	}
}

// An operator arriving is the trigger. The retry must follow immediately, not
// at the next tick of a backoff nobody chose.
func TestOperatorReleaseResumesImmediately(t *testing.T) {
	var attempts atomic.Int32
	release := make(chan struct{})
	src := Dialing("ssh://cluster", func(context.Context) (net.Conn, error) {
		if attempts.Add(1) == 1 {
			return nil, errNeedsHuman
		}
		a, b := net.Pipe()
		go func() { <-release; _ = b.Close() }()
		return a, nil
	})

	gate := &HumanGate{}
	// A deliberately enormous backoff: if the release did not drive the retry,
	// this test would time out instead of passing.
	l := NewSourceListener(src, nil, Backoff{Initial: time.Hour, Max: time.Hour},
		WithNeedsHuman(gate, func(err error) bool { return errors.Is(err, errNeedsHuman) }))
	defer func() { _ = l.Close() }()

	got := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			got <- c
		}
	}()

	// Wait for it to park, then let the operator in.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, parked := gate.Parked(); parked {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, parked := gate.Parked(); !parked {
		t.Fatal("never parked")
	}
	gate.Release()

	select {
	case c := <-got:
		close(release)
		_ = c.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("the retry did not follow the operator's release")
	}
	if _, parked := gate.Parked(); parked {
		t.Error("the gate is still parked after a successful retry")
	}
}

// An ordinary failure must still be retried on the backoff: parking everything
// would turn a blip into an outage that needs a human.
func TestOrdinaryFailuresStillRetry(t *testing.T) {
	var attempts atomic.Int32
	src := Dialing("ssh://cluster", func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("connection refused")
	})

	gate := &HumanGate{}
	l := NewSourceListener(src, nil, Backoff{Initial: time.Millisecond, Max: 2 * time.Millisecond},
		WithNeedsHuman(gate, func(err error) bool { return errors.Is(err, errNeedsHuman) }))
	defer func() { _ = l.Close() }()

	go func() { _, _ = l.Accept() }()
	time.Sleep(300 * time.Millisecond)

	if n := attempts.Load(); n < 3 {
		t.Errorf("made only %d attempts against an ordinary failure; it should keep retrying", n)
	}
	if _, parked := gate.Parked(); parked {
		t.Error("an ordinary failure parked the carrier behind an operator")
	}
}

// Closing while parked must not wedge: the gate's waiter has to notice.
func TestCloseWhileParkedDoesNotWedge(t *testing.T) {
	src := Dialing("ssh://cluster", func(context.Context) (net.Conn, error) {
		return nil, errNeedsHuman
	})
	gate := &HumanGate{}
	l := NewSourceListener(src, nil, DefaultBackoff,
		WithNeedsHuman(gate, func(err error) bool { return errors.Is(err, errNeedsHuman) }))

	done := make(chan error, 1)
	go func() { _, err := l.Accept(); done <- err }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, parked := gate.Parked(); parked {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = l.Close()

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept returned %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not wake a parked Accept")
	}
}

// The gate itself: opening an open gate is a no-op, and several waiters all
// wake.
func TestGateSemantics(t *testing.T) {
	g := &HumanGate{}
	if _, parked := g.Parked(); parked {
		t.Error("the zero value is parked; it must be open")
	}
	if err := g.Wait(context.Background()); err != nil {
		t.Errorf("Wait on an open gate returned %v", err)
	}
	g.Release() // releasing an open gate does nothing
	if n := g.Releases(); n != 0 {
		t.Errorf("Releases() = %d after releasing an open gate, want 0", n)
	}

	g.Park(errNeedsHuman)
	g.Park(errors.New("a different reason")) // must not disturb waiters

	const waiters = 3
	woke := make(chan struct{}, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			_ = g.Wait(context.Background())
			woke <- struct{}{}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	g.Release()
	for i := 0; i < waiters; i++ {
		select {
		case <-woke:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d waiters woke", i, waiters)
		}
	}
	if n := g.Releases(); n != 1 {
		t.Errorf("Releases() = %d, want 1", n)
	}
}

// A ctx that ends while waiting must not leave the caller stuck.
func TestGateWaitHonoursContext(t *testing.T) {
	g := &HumanGate{}
	g.Park(errNeedsHuman)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := g.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Wait returned %v, want the context error", err)
	}
}
