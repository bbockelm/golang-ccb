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

	var held []net.Conn
	for i := 0; i < 4; i++ {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer func() { _ = c.Close() }()
		if i < 2 {
			accepted, err := l.Accept()
			if err != nil {
				t.Fatalf("Accept %d: %v", i, err)
			}
			held = append(held, accepted)
		}
	}
	if got := l.Sessions(); got != 2 {
		t.Fatalf("holding %d sessions, want 2", got)
	}

	// Over the cap, the listener closes the excess and keeps accepting, so a
	// third dial yields nothing until a held pipe closes.
	done := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			done <- c
		}
	}()
	select {
	case <-done:
		t.Fatal("accepted a pipe beyond the session cap")
	default:
	}

	_ = held[0].Close()
	// Close() ends our side; the listener drops the session when ITS goroutine
	// observes that, which does not happen before Close() returns.  Reading the
	// count once races that goroutine and reports the pre-close value on a loaded
	// machine, so wait for the drop instead.
	if got := waitForSessions(l, 1); got != 1 {
		t.Errorf("after closing one pipe, holding %d sessions, want 1", got)
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

// waitForSessions polls until the listener reports want sessions, returning the
// last value it saw.  A test that wants to prove the count NEVER reaches a value
// must not use this -- it returns as soon as the value appears.
func waitForSessions(l *LimitListener, want int) int {
	deadline := time.Now().Add(5 * time.Second)
	got := l.Sessions()
	for got != want && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
		got = l.Sessions()
	}
	return got
}
