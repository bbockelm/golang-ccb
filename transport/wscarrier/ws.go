// Package wscarrier implements a WebSocket carrier for CCB tunneling: the
// inside<->outside CCB link rides a single long-lived WebSocket to an HTTPS port
// on the outside CCB, so a node that forbids arbitrary outbound TCP (but permits
// HTTPS) can still tunnel, and the whole node lives on ONE TCP connection (yamux
// multiplexes over it, layered by transport/carrier).
//
// The carrier is transport-only: it moves opaque bytes and delegates
// authentication to callbacks. The client presents a bearer token; the server
// verifies it via a TokenVerifier and maps it to an identity. The CCB layer wires
// HTCondor token discovery (IDTOKEN/SciToken) into these callbacks, so this
// package has no HTCondor dependency.
package wscarrier

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// DefaultPath is the HTTP path the WebSocket upgrade is served on.
const DefaultPath = "/ccb/tunnel"

// TokenVerifier validates a client's bearer token and returns an identity string
// for logging/authorization (e.g. the token subject). A non-nil error rejects the
// connection with 401. Called with the request context.
type TokenVerifier func(ctx context.Context, token string) (identity string, err error)

// TokenSource returns the bearer token to present to the server. Called once per
// dial so a rotating credential is re-read.
type TokenSource func(ctx context.Context) (string, error)

// ListenConfig configures the acceptor (outside CCB) side.
type ListenConfig struct {
	// Addr is the TCP listen address ("host:port" or ":port").
	Addr string
	// Path is the upgrade path (default DefaultPath).
	Path string
	// TLS, if set, serves HTTPS (wss). nil serves plaintext HTTP (ws) -- test/dev
	// only; production must set TLS.
	TLS *tls.Config
	// Verify authenticates each client's bearer token. Required unless
	// AllowUnauthenticated is set.
	Verify TokenVerifier
	// AllowUnauthenticated serves the upgrade with no credential at all.
	//
	// A bearer token in the upgrade header is readable by any TLS-intercepting
	// proxy on the path, which is a reusable pool credential in the hands of a
	// component that only needed to pass bytes. The identity it establishes is
	// discarded here anyway: the CEDAR handshake that follows authenticates the
	// peer by proof of possession, without putting the credential on the wire,
	// and that is the identity every authorization decision uses.
	//
	// It must be set explicitly: a nil Verify alone is an error, so a listener
	// is never unauthenticated by omission.
	AllowUnauthenticated bool
	// ReadLimit caps a single inbound WebSocket message. Zero means unlimited
	// when a token is required (yamux bounds its own windows), and
	// DefaultUnauthReadLimit when it is not.
	ReadLimit int64
	// MaxSessions caps concurrently-held carrier pipes (default
	// DefaultMaxSessions). One pipe per inside broker, so this is a node count.
	MaxSessions int
	// MaxPerSource caps concurrent pipes from one remote address. Zero disables
	// it, which is the default: where a site intercepts TLS, every legitimate
	// node arrives from the proxy's single address, so this would throttle the
	// one source that must not be throttled. Useful only for brokers reached
	// directly.
	MaxPerSource int
	// ReadHeaderTimeout, ReadTimeout and IdleTimeout bound the HTTP side of the
	// upgrade; zero takes the Default* value. They apply whether or not a token
	// is required -- the request is parsed before any credential is seen, so
	// without them a peer can hold a slot indefinitely while sending nothing.
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	IdleTimeout       time.Duration
}

// Accept-path limits. See docs/CARRIER_AUTH.md for why each default is what it
// is; in short, they bound what a peer can consume before it has authenticated
// anything, which for an unauthenticated upgrade is the whole of the defence.
const (
	// DefaultMaxSessions caps concurrent carrier pipes. One per inside broker,
	// so a site tunnelling more nodes than this through one outside broker must
	// raise it.
	DefaultMaxSessions = 1024
	// DefaultUnauthReadLimit bounds one inbound message when the upgrade
	// carries no credential. yamux's default stream window is 256 KiB and a
	// frame payload cannot exceed the window, so this is ample headroom while
	// still bounding per-connection buffer growth.
	DefaultUnauthReadLimit = 1 << 20
	// DefaultReadHeaderTimeout bounds how long a peer may take to send its
	// request headers.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultReadTimeout bounds the whole upgrade request.
	DefaultReadTimeout = 30 * time.Second
	// DefaultIdleTimeout bounds a kept-alive connection that never upgrades.
	DefaultIdleTimeout = 120 * time.Second
)

// ErrNoVerifier reports a ListenConfig that neither verifies a token nor opts
// in to serving without one.
var ErrNoVerifier = errors.New("wscarrier: ListenConfig needs Verify or AllowUnauthenticated")

// Listener accepts authenticated WebSocket connections and presents each as a
// net.Conn byte pipe. It implements net.Listener, so transport/carrier's
// MuxListener (and thus the CCB command server) runs over it unchanged.
type Listener struct {
	inner     net.Listener
	srv       *http.Server
	conns     chan net.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	verify    TokenVerifier
	readLimit int64
	closeOnce sync.Once

	maxSessions  int
	maxPerSource int
	mu           sync.Mutex
	sessions     int
	perSource    map[string]int
}

// Listen starts serving the WebSocket carrier on cfg.Addr.
func Listen(cfg ListenConfig) (*Listener, error) {
	if cfg.Verify == nil && !cfg.AllowUnauthenticated {
		return nil, ErrNoVerifier
	}
	path := cfg.Path
	if path == "" {
		path = DefaultPath
	}
	readLimit := cfg.ReadLimit
	if readLimit == 0 && cfg.Verify == nil {
		readLimit = DefaultUnauthReadLimit
	}
	maxSessions := cfg.MaxSessions
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	inner, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		inner:        inner,
		conns:        make(chan net.Conn),
		ctx:          ctx,
		cancel:       cancel,
		verify:       cfg.Verify,
		readLimit:    readLimit,
		maxSessions:  maxSessions,
		maxPerSource: cfg.MaxPerSource,
		perSource:    make(map[string]int),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, l.handle)
	l.srv = &http.Server{
		Handler:           mux,
		TLSConfig:         cfg.TLS,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: orDuration(cfg.ReadHeaderTimeout, DefaultReadHeaderTimeout),
		ReadTimeout:       orDuration(cfg.ReadTimeout, DefaultReadTimeout),
		IdleTimeout:       orDuration(cfg.IdleTimeout, DefaultIdleTimeout),
	}
	go func() {
		var serveErr error
		if cfg.TLS != nil {
			serveErr = l.srv.ServeTLS(inner, "", "")
		} else {
			serveErr = l.srv.Serve(inner)
		}
		_ = serveErr // Serve returns on Close; nothing to do
	}()
	return l, nil
}

func (l *Listener) handle(w http.ResponseWriter, r *http.Request) {
	if l.verify != nil {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		if _, err := l.verify(r.Context(), token); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Claim a slot before the upgrade: once the connection is hijacked there is
	// no longer an HTTP response to refuse with.
	source := sourceOf(r)
	if !l.acquire(source) {
		http.Error(w, "too many carrier sessions", http.StatusServiceUnavailable)
		return
	}
	released := false
	defer func() {
		if !released {
			l.release(source)
		}
	}()

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return // Accept already wrote a response
	}
	if l.readLimit != 0 {
		c.SetReadLimit(l.readLimit)
	} else {
		c.SetReadLimit(-1) // unlimited: authenticated peer, yamux-bounded
	}

	nc := websocket.NetConn(l.ctx, c, websocket.MessageBinary)
	wc := &connWrap{Conn: nc, done: make(chan struct{}), release: func() { l.release(source) }}
	released = true // wc owns the slot from here
	select {
	case l.conns <- wc:
	case <-l.ctx.Done():
		_ = wc.Close()
		_ = c.Close(websocket.StatusGoingAway, "listener closing")
		return
	}
	// Keep the HTTP handler alive until the pipe is closed; returning early would
	// tear down the hijacked connection.
	select {
	case <-wc.done:
	case <-l.ctx.Done():
		_ = c.Close(websocket.StatusGoingAway, "listener closing")
	}
}

// Accept returns the next authenticated WebSocket byte pipe.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		_ = l.srv.Close()
		_ = l.inner.Close()
	})
	return nil
}

func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// DialConfig configures the initiator (inside CCB) side.
type DialConfig struct {
	// URL is the WebSocket endpoint ("wss://host:port/ccb/tunnel").
	URL string
	// Token is the bearer token to present. If empty, TokenSource is used.
	Token string
	// TokenSource supplies the bearer token when Token is empty.
	TokenSource TokenSource
	// Unauthenticated presents no credential at all, for a server that asks for
	// none. Token and TokenSource are then ignored, so a node with no token to
	// discover still dials -- and no credential reaches a proxy on the path.
	Unauthenticated bool
	// TLS configures the client TLS (CA roots, etc.) for wss.
	TLS *tls.Config
	// HandshakeTimeout bounds the WebSocket upgrade (default 30s).
	HandshakeTimeout time.Duration
	// ReadLimit caps a single inbound message (default unlimited).
	ReadLimit int64
}

// Dial opens one authenticated WebSocket to the outside CCB and returns it as a
// net.Conn byte pipe. transport/carrier wraps it in a yamux client.
func Dial(ctx context.Context, cfg DialConfig) (net.Conn, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("wscarrier: DialConfig.URL is required")
	}
	var token string
	if !cfg.Unauthenticated {
		token = cfg.Token
		if token == "" && cfg.TokenSource != nil {
			t, err := cfg.TokenSource(ctx)
			if err != nil {
				return nil, fmt.Errorf("wscarrier: token source: %w", err)
			}
			token = t
		}
	}

	hdr := http.Header{}
	if token != "" {
		hdr.Set("Authorization", "Bearer "+token)
	}
	httpClient := &http.Client{}
	if cfg.TLS != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: cfg.TLS}
	}

	hsTimeout := cfg.HandshakeTimeout
	if hsTimeout <= 0 {
		hsTimeout = 30 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, hsTimeout)
	defer cancel()

	c, resp, err := websocket.Dial(dctx, cfg.URL, &websocket.DialOptions{
		HTTPHeader: hdr,
		HTTPClient: httpClient,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close() // handshake response body is unused; close to satisfy the linter/net
	}
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("wscarrier: dial %s: unauthorized (bad or missing token)", cfg.URL)
		}
		return nil, fmt.Errorf("wscarrier: dial %s: %w", cfg.URL, err)
	}
	if cfg.ReadLimit != 0 {
		c.SetReadLimit(cfg.ReadLimit)
	} else {
		c.SetReadLimit(-1)
	}
	// The pipe outlives the dial context, so give NetConn its own lifetime.
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// connWrap makes closing the pipe unblock the HTTP handler that owns it, and
// returns the pipe's admission slot.
type connWrap struct {
	net.Conn
	done    chan struct{}
	release func()
	once    sync.Once
}

func (c *connWrap) Close() error {
	c.once.Do(func() {
		close(c.done)
		if c.release != nil {
			c.release()
		}
	})
	return c.Conn.Close()
}

// acquire takes an admission slot for a pipe from source, reporting whether one
// was available.
func (l *Listener) acquire(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sessions >= l.maxSessions {
		return false
	}
	if l.maxPerSource > 0 && l.perSource[source] >= l.maxPerSource {
		return false
	}
	l.sessions++
	l.perSource[source]++
	return true
}

// release returns a slot taken by acquire. It is idempotent per connWrap, which
// calls it once.
func (l *Listener) release(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sessions > 0 {
		l.sessions--
	}
	if n := l.perSource[source]; n > 1 {
		l.perSource[source] = n - 1
	} else {
		delete(l.perSource, source)
	}
}

// Sessions reports the number of carrier pipes currently held open.
func (l *Listener) Sessions() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessions
}

// sourceOf names the peer for per-source accounting. Behind a TLS-intercepting
// proxy every node shares one address, which is why MaxPerSource defaults off.
func sourceOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
