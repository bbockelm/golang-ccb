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
	// Verify authenticates each client's bearer token. Required.
	Verify TokenVerifier
	// ReadLimit caps a single inbound WebSocket message (default: unlimited, since
	// the peer is authenticated and yamux bounds its own windows).
	ReadLimit int64
}

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
}

// Listen starts serving the WebSocket carrier on cfg.Addr.
func Listen(cfg ListenConfig) (*Listener, error) {
	if cfg.Verify == nil {
		return nil, fmt.Errorf("wscarrier: ListenConfig.Verify is required")
	}
	path := cfg.Path
	if path == "" {
		path = DefaultPath
	}
	inner, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		inner:     inner,
		conns:     make(chan net.Conn),
		ctx:       ctx,
		cancel:    cancel,
		verify:    cfg.Verify,
		readLimit: cfg.ReadLimit,
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, l.handle)
	l.srv = &http.Server{
		Handler:     mux,
		TLSConfig:   cfg.TLS,
		BaseContext: func(net.Listener) context.Context { return ctx },
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
	token := bearerToken(r)
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	if _, err := l.verify(r.Context(), token); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

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
	wc := &connWrap{Conn: nc, done: make(chan struct{})}
	select {
	case l.conns <- wc:
	case <-l.ctx.Done():
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
	token := cfg.Token
	if token == "" && cfg.TokenSource != nil {
		t, err := cfg.TokenSource(ctx)
		if err != nil {
			return nil, fmt.Errorf("wscarrier: token source: %w", err)
		}
		token = t
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

// connWrap makes closing the pipe unblock the HTTP handler that owns it.
type connWrap struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *connWrap) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}
