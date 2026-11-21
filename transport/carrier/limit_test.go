package carrier

import (
	"net"
	"testing"
	"time"
)

func localListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// A carrier that authenticates nobody at the transport (a raw TCP pipe, or a
// WebSocket in CCB_CARRIER_AUTH = none mode) has to bound what an
// unauthenticated peer can park on the broker.
func TestLimitListenerCapsSessions(t *testing.T) {
	inner := localListener(t)
	l := NewLimitListener(inner, nil, 2, 0)

	// Fill the cap.
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer func() { _ = c.Close() }()
		accepted, err := l.Accept()
		if err != nil {
			t.Fatalf("Accept %d: %v", i, err)
		}
		held = append(held, accepted)
	}
	if got := l.Sessions(); got != 2 {
		t.Fatalf("holding %d sessions, want 2", got)
	}

	// One more arrives. Accept must not yield it while the cap is full --
	// the excess is closed and the loop keeps waiting.
	extra, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = extra.Close() }()

	got := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			got <- c
		}
	}()
	select {
	case <-got:
		t.Fatal("accepted a pipe beyond the session cap")
	case <-time.After(250 * time.Millisecond):
	}

	// Freeing a slot lets the waiting Accept through. Asserting that, rather
	// than a count sampled while that goroutine is racing to re-fill the
	// slot, is what makes this deterministic.
	_ = held[0].Close()
	again, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()

	select {
	case c := <-got:
		_ = c.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("closing a held pipe did not free a slot for the waiting Accept")
	}
}

func TestLimitListenerCapsPerSource(t *testing.T) {
	inner := localListener(t)
	l := NewLimitListener(inner, nil, 100, 1)

	c1, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c1.Close() }()
	a1, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = a1.Close() }()

	// Both dials come from 127.0.0.1, so the second is over the per-source cap.
	c2, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()

	done := make(chan struct{})
	go func() {
		_, _ = l.Accept()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("accepted a second pipe from a source capped at one")
	default:
	}
	if got := l.Sessions(); got != 1 {
		t.Errorf("holding %d sessions, want 1", got)
	}
}

// Zero disables the per-source cap, which is right wherever many brokers
// legitimately share one address: everything behind one NAT or one proxy.
func TestLimitListenerPerSourceZeroDisables(t *testing.T) {
	inner := localListener(t)
	l := NewLimitListener(inner, nil, 100, 0)
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		a, err := l.Accept()
		if err != nil {
			t.Fatalf("Accept %d: %v", i, err)
		}
		defer func() { _ = a.Close() }()
	}
	if got := l.Sessions(); got != 3 {
		t.Errorf("holding %d sessions from one source, want 3", got)
	}
}
