package splice

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// carrierEnd runs the broker side of a carrier: a yamux server over one pipe
// whose accepted streams are handed to serve.
func carrierEnd(t *testing.T, serve func(net.Conn)) (pipe net.Conn, stop func()) {
	t.Helper()
	ours, theirs := net.Pipe()
	yc := yamux.DefaultConfig()
	yc.LogOutput = io.Discard
	sess, err := yamux.Server(ours, yc)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			st, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go serve(st)
		}
	}()
	return theirs, func() { _ = sess.Close(); _ = ours.Close(); <-done }
}

func startHelper(t *testing.T, pipe net.Conn) *Helper {
	t.Helper()
	h, err := Start(Config{Listen: "127.0.0.1:0", Pipe: pipe, Log: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.Serve(context.Background()) }()
	return h
}

// TestBulkTransferIsNotTruncated is the half-close property. A relay that
// cannot tell the far side "I have finished sending" leaves the peer waiting
// for data that never comes, and the transfer is torn down looking truncated.
// Control traffic survives that; bulk transfers do not, so the payload here is
// large enough to span many yamux windows.
func TestBulkTransferIsNotTruncated(t *testing.T) {
	payload := make([]byte, 4<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	// The far side reads to EOF, then echoes the length it saw.
	got := make(chan int, 1)
	pipe, stopCarrier := carrierEnd(t, func(st net.Conn) {
		defer func() { _ = st.Close() }()
		b, err := io.ReadAll(st)
		if err != nil {
			t.Errorf("far side read: %v", err)
		}
		if !bytes.Equal(b, payload) {
			t.Errorf("far side got %d bytes, want %d", len(b), len(payload))
		}
		got <- len(b)
	})
	defer stopCarrier()

	h := startHelper(t, pipe)
	defer func() { _ = h.Close() }()

	c, err := net.Dial("tcp", h.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	// Half-close: the far side must see EOF while the helper keeps the
	// connection open for the reply direction.
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	select {
	case n := <-got:
		if n != len(payload) {
			t.Fatalf("far side saw %d bytes of %d", n, len(payload))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the far side never saw EOF: the relay did not half-close, so a finished transfer looks truncated")
	}
}

// TestEachConnectionGetsItsOwnStream checks the helper multiplexes rather than
// serialising: several local connections are live at once over one carrier.
func TestEachConnectionGetsItsOwnStream(t *testing.T) {
	const n = 8
	var mu sync.Mutex
	open := 0
	peak := 0
	release := make(chan struct{})
	pipe, stopCarrier := carrierEnd(t, func(st net.Conn) {
		defer func() { _ = st.Close() }()
		mu.Lock()
		open++
		if open > peak {
			peak = open
		}
		mu.Unlock()
		<-release
		_, _ = st.Write([]byte("ok"))
		mu.Lock()
		open--
		mu.Unlock()
	})
	defer stopCarrier()

	h := startHelper(t, pipe)
	defer func() { _ = h.Close() }()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", h.Addr().String())
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer func() { _ = c.Close() }()
			if _, err := c.Write([]byte("hi")); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			b := make([]byte, 2)
			if _, err := io.ReadFull(c, b); err != nil {
				t.Errorf("read: %v", err)
			}
		}()
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		p := peak
		mu.Unlock()
		if p == n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if peak != n {
		t.Errorf("peak concurrent streams was %d, want %d: the helper is serialising", peak, n)
	}
}

// TestCloseDoesNotWaitForPeers pins the shutdown bug this package shipped with
// once: Close waited on relays blocked in io.Copy on local sockets that nobody
// else would ever close, so a helper with one idle connection took two minutes
// to shut down instead of returning at once.
func TestCloseDoesNotWaitForPeers(t *testing.T) {
	pipe, stopCarrier := carrierEnd(t, func(st net.Conn) {
		// Hold the stream open and send nothing, like a real peer mid-session.
		io.Copy(io.Discard, st) //nolint:errcheck // deliberately blocks until torn down
	})
	defer stopCarrier()

	h := startHelper(t, pipe)
	c, err := net.Dial("tcp", h.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let the relay establish

	done := make(chan struct{})
	go func() { defer close(done); _ = h.Close() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked on a relay whose peers are still holding the connection open")
	}

	// Idempotent: a second Close must not panic or hang.
	if err := h.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestServeStopsWhenTheCarrierDies checks a helper does not keep accepting
// connections it has no way to carry.
func TestServeStopsWhenTheCarrierDies(t *testing.T) {
	pipe, stopCarrier := carrierEnd(t, func(st net.Conn) { _ = st.Close() })
	h, err := Start(Config{Listen: "127.0.0.1:0", Pipe: pipe, Log: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	serveErr := make(chan error, 1)
	go func() { serveErr <- h.Serve(context.Background()) }()

	stopCarrier()

	select {
	case err := <-serveErr:
		if err == nil {
			t.Fatal("Serve returned nil after the carrier died")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve kept accepting after the carrier died")
	}
}
