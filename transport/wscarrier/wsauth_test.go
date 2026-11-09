package wscarrier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// listenLocal starts a listener on a free loopback port and returns it with its
// ws:// URL.
func listenLocal(t *testing.T, cfg ListenConfig) (*Listener, string) {
	t.Helper()
	cfg.Addr = "127.0.0.1:0"
	l, err := Listen(cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	path := cfg.Path
	if path == "" {
		path = DefaultPath
	}
	return l, "ws://" + l.Addr().String() + path
}

// accepted keeps Accept from blocking the handler and hands each pipe to the
// test. A pipe's admission slot is held until the SERVER side closes, so a test
// that wants a slot back closes the conn it receives here.
type accepted struct {
	ch chan net.Conn
	mu sync.Mutex
	nc []net.Conn
}

func drainAccepts(t *testing.T, l *Listener) *accepted {
	t.Helper()
	a := &accepted{ch: make(chan net.Conn, 64)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(a.ch)
				return
			}
			a.mu.Lock()
			a.nc = append(a.nc, c)
			a.mu.Unlock()
			a.ch <- c
		}
	}()
	t.Cleanup(a.closeAll)
	return a
}

// next returns the next accepted server-side pipe.
func (a *accepted) next(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c, ok := <-a.ch:
		if !ok {
			t.Fatal("listener closed before a pipe arrived")
		}
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the server to accept a pipe")
		return nil
	}
}

func (a *accepted) closeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.nc {
		go func() { _ = c.Close() }()
	}
	a.nc = nil
}

// closeBoth closes both ends without waiting. coder/websocket's Close performs
// a close handshake the peer only answers while reading, so a synchronous close
// here would wait out its five-second timeout for no benefit. The admission
// slot is released before that handshake begins, which is what these tests
// observe, so they poll with waitSessions instead.
func closeBoth(server, client net.Conn) {
	go func() { _ = server.Close() }()
	go func() { _ = client.Close() }()
}

// TestUnauthenticatedUpgradeRequiresOptIn is the foot-gun guard: a config with
// no verifier and no opt-in must be refused, so a listener is never
// unauthenticated because a field was forgotten.
func TestUnauthenticatedUpgradeRequiresOptIn(t *testing.T) {
	_, err := Listen(ListenConfig{Addr: "127.0.0.1:0"})
	if err == nil {
		t.Fatal("Listen accepted a config with neither Verify nor AllowUnauthenticated")
	}
	if !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("got %v, want ErrNoVerifier", err)
	}
}

// TestUnauthenticatedUpgradeSendsNoCredential is the point of the whole change:
// in unauthenticated mode the dialer must put no Authorization header on the
// wire, so a proxy that terminates TLS sees no credential.
func TestUnauthenticatedUpgradeSendsNoCredential(t *testing.T) {
	seen := make(chan string, 4)
	// A bare HTTP server, so we observe the raw upgrade request headers rather
	// than trusting the carrier's own view of them.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		http.Error(w, "no upgrade here", http.StatusTeapot)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	url := "ws://" + ln.Addr().String() + DefaultPath
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Unauthenticated: no header, even though a token and a source are set.
	_, _ = Dial(ctx, DialConfig{
		URL:             url,
		Token:           "super-secret-idtoken",
		TokenSource:     func(context.Context) (string, error) { return "also-secret", nil },
		Unauthenticated: true,
	})
	if h := <-seen; h != "" {
		t.Fatalf("unauthenticated dial sent Authorization %q; a proxy would read it", h)
	}

	// The default mode still sends one, so this test can tell the two apart.
	_, _ = Dial(ctx, DialConfig{URL: url, Token: "super-secret-idtoken"})
	if h := <-seen; !strings.Contains(h, "super-secret-idtoken") {
		t.Fatalf("token mode sent Authorization %q, want the token", h)
	}
}

// TestTokenStillRequiredByDefault pins backward compatibility: a listener built
// the old way keeps rejecting a bad token and a missing one.
func TestTokenStillRequiredByDefault(t *testing.T) {
	l, url := listenLocal(t, ListenConfig{Verify: goodTokenVerifier})
	a := drainAccepts(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, tc := range []struct {
		name string
		cfg  DialConfig
	}{
		{"bad token", DialConfig{URL: url, Token: "nope"}},
		{"no token", DialConfig{URL: url}},
		{"unauthenticated client", DialConfig{URL: url, Token: "letmein", Unauthenticated: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Dial(ctx, tc.cfg); err == nil {
				t.Fatal("dial succeeded; the listener must still require a valid token")
			}
		})
	}

	good, err := Dial(ctx, DialConfig{URL: url, Token: "letmein"})
	if err != nil {
		t.Fatalf("a good token must still work: %v", err)
	}
	closeBoth(a.next(t), good)
}

// TestUnauthenticatedListenerIgnoresToken: an unauthenticated listener accepts
// a peer that presents a garbage token as readily as one that presents none. It
// must not be fooled into treating the header as meaningful.
func TestUnauthenticatedListenerIgnoresToken(t *testing.T) {
	l, url := listenLocal(t, ListenConfig{AllowUnauthenticated: true})
	a := drainAccepts(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, tc := range []DialConfig{
		{URL: url, Unauthenticated: true},
		{URL: url, Token: "garbage"},
	} {
		c, err := Dial(ctx, tc)
		if err != nil {
			t.Fatalf("dial %+v: %v", tc, err)
		}
		closeBoth(a.next(t), c)
	}
}

// TestMaxSessionsRefusesOverflow: the global cap must actually refuse, and must
// free a slot when a pipe closes.
func TestMaxSessionsRefusesOverflow(t *testing.T) {
	l, url := listenLocal(t, ListenConfig{AllowUnauthenticated: true, MaxSessions: 2})
	a := drainAccepts(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var clients, servers []net.Conn
	for i := range 2 {
		c, err := Dial(ctx, DialConfig{URL: url, Unauthenticated: true})
		if err != nil {
			t.Fatalf("dial %d under the cap: %v", i, err)
		}
		clients = append(clients, c)
		servers = append(servers, a.next(t))
	}
	waitSessions(t, l, 2)

	if _, err := Dial(ctx, DialConfig{URL: url, Unauthenticated: true}); err == nil {
		t.Fatal("dial over MaxSessions succeeded; the cap does not refuse")
	}

	// Closing one must return its slot.
	closeBoth(servers[0], clients[0])
	waitSessions(t, l, 1)
	c, err := Dial(ctx, DialConfig{URL: url, Unauthenticated: true})
	if err != nil {
		t.Fatalf("dial after a slot was freed: %v", err)
	}
	closeBoth(a.next(t), c)
	closeBoth(servers[1], clients[1])
}

// TestMaxPerSourceRefusesOverflow: the per-source cap refuses a third pipe from
// one address while the global cap is nowhere near.
func TestMaxPerSourceRefusesOverflow(t *testing.T) {
	l, url := listenLocal(t, ListenConfig{AllowUnauthenticated: true, MaxSessions: 100, MaxPerSource: 2})
	a := drainAccepts(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var clients []net.Conn
	for i := range 2 {
		c, err := Dial(ctx, DialConfig{URL: url, Unauthenticated: true})
		if err != nil {
			t.Fatalf("dial %d under the per-source cap: %v", i, err)
		}
		clients = append(clients, c)
	}
	waitSessions(t, l, 2)
	if _, err := Dial(ctx, DialConfig{URL: url, Unauthenticated: true}); err == nil {
		t.Fatal("dial over MaxPerSource succeeded; the per-source cap does not refuse")
	}
	a.closeAll()
	for _, c := range clients {
		go func() { _ = c.Close() }()
	}
}

// TestMaxPerSourceOffByDefault: the default must NOT throttle one address,
// because behind a bumping proxy every legitimate node shares it.
func TestMaxPerSourceOffByDefault(t *testing.T) {
	l, url := listenLocal(t, ListenConfig{AllowUnauthenticated: true})
	a := drainAccepts(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var clients []net.Conn
	for i := range 8 {
		c, err := Dial(ctx, DialConfig{URL: url, Unauthenticated: true})
		if err != nil {
			t.Fatalf("dial %d from one source was refused by default: %v", i, err)
		}
		clients = append(clients, c)
	}
	waitSessions(t, l, 8)
	a.closeAll()
	for _, c := range clients {
		go func() { _ = c.Close() }()
	}
}

// TestReadHeaderTimeoutClosesSlowloris: a peer that opens a connection and
// dribbles headers must be dropped rather than holding a slot forever.
func TestReadHeaderTimeoutClosesSlowloris(t *testing.T) {
	l, _ := listenLocal(t, ListenConfig{
		AllowUnauthenticated: true,
		ReadHeaderTimeout:    250 * time.Millisecond,
	})
	drainAccepts(t, l)

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// A request line and one header, then silence -- never the blank line.
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\n", DefaultPath); err != nil {
		t.Fatal(err)
	}

	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	// The server must close (EOF) or answer 408; either way it stops waiting.
	if _, err := io.ReadAll(c); err != nil && !errors.Is(err, io.EOF) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("server never closed a half-sent request; ReadHeaderTimeout is not applied")
		}
	}
}

// TestReadLimitBoundedWhenUnauthenticated: an unauthenticated listener must not
// leave the message read limit unbounded, while a token-verifying one keeps
// today's unlimited behavior.
func TestReadLimitBoundedWhenUnauthenticated(t *testing.T) {
	unauth, _ := listenLocal(t, ListenConfig{AllowUnauthenticated: true})
	if unauth.readLimit != DefaultUnauthReadLimit {
		t.Fatalf("unauthenticated read limit = %d, want %d", unauth.readLimit, DefaultUnauthReadLimit)
	}
	auth, _ := listenLocal(t, ListenConfig{Verify: goodTokenVerifier})
	if auth.readLimit != 0 {
		t.Fatalf("token-mode read limit = %d, want 0 (unlimited, as before)", auth.readLimit)
	}
}

func waitSessions(t *testing.T, l *Listener, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if l.Sessions() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("sessions = %d, want %d", l.Sessions(), want)
}
