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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http/httpproxy"
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
	// Proxy selects the HTTP proxy to reach the endpoint through, in the form
	// http.Transport.Proxy takes. Nil means http.ProxyFromEnvironment, so
	// HTTPS_PROXY / NO_PROXY are honoured; NoProxy disables proxying outright.
	// A proxy is reached with CONNECT, which requires a wss:// endpoint (see
	// ResolvedProxy).
	Proxy func(*http.Request) (*url.URL, error)
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
	// Resolve the proxy up front: it decides the route AND rejects the
	// unsupported ws://-through-a-proxy combination before we spend a dial.
	proxyURL, err := cfg.ResolvedProxy()
	if err != nil {
		return nil, err
	}
	// Always build our own Transport (never http.DefaultTransport): the proxy and
	// the TLS roots must both be honoured, and a Transport carrying an explicit
	// TLSClientConfig does not negotiate HTTP/2, which the handshake needs
	// (RFC 8441 is not implemented here).
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: cfg.TLS,
		Proxy:           cfg.proxyFunc(),
	}}

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
		// Name the route taken: a dial that silently went direct because a proxy
		// was not configured is otherwise indistinguishable from one the proxy
		// refused, and on a node with no route out the difference is the diagnosis.
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("wscarrier: dial %s (%s): unauthorized (bad or missing token)", cfg.URL, RouteDescription(proxyURL))
		}
		return nil, fmt.Errorf("wscarrier: dial %s (%s): %w", cfg.URL, RouteDescription(proxyURL), err)
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

// NoProxy is a DialConfig.Proxy that disables proxying outright, overriding the
// HTTPS_PROXY environment that a nil Proxy would otherwise honour.
func NoProxy(*http.Request) (*url.URL, error) { return nil, nil }

// proxyFunc is the http.Transport.Proxy to use: the configured one, or the
// environment when unset.
//
// The environment is read per dial rather than through
// http.ProxyFromEnvironment, which resolves HTTPS_PROXY / NO_PROXY once per
// process and caches the answer forever. A daemon that is reconfigured, or a
// pilot that sets the proxy after something else has already consulted the
// environment, would otherwise keep using a stale route with nothing to show for
// it. The matching rules (including the localhost exemption) are the same.
func (cfg DialConfig) proxyFunc() func(*http.Request) (*url.URL, error) {
	if cfg.Proxy != nil {
		return cfg.Proxy
	}
	return ProxyFromEnvironment
}

// ProxyFromEnvironment resolves HTTPS_PROXY / HTTP_PROXY / NO_PROXY for each
// request, with the same matching rules (and localhost exemption) as net/http's
// function of the same name -- but without its caching: net/http resolves the
// environment once per process and keeps that answer forever, so a daemon
// reconfigured afterwards, or a pilot that sets the proxy once something else
// has already consulted the environment, would keep a stale route with nothing
// in the log to show for it.
func ProxyFromEnvironment(req *http.Request) (*url.URL, error) {
	return httpproxy.FromEnvironment().ProxyFunc()(req.URL)
}

// ResolvedProxy reports the proxy this config would dial cfg.URL through: the
// result of DialConfig.Proxy (or the environment) for the equivalent HTTP
// request, or nil for a direct dial. Callers use it to log the route a carrier
// actually took, because a dial that silently went direct looks exactly like a
// proxied one in every other respect.
//
// It also enforces the one combination that cannot work: a proxy is reached
// with CONNECT, which http.Transport issues only for an https target, so a
// plaintext ws:// endpoint through a proxy would be sent as an absolute-URI GET
// that proxies do not relay as an Upgrade. That is rejected here rather than
// failing obscurely mid-handshake.
func (cfg DialConfig) ResolvedProxy() (*url.URL, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("wscarrier: bad URL %q: %w", cfg.URL, err)
	}
	// http.Transport.Proxy is consulted with the http/https equivalent of the
	// endpoint, which is also what NO_PROXY matching sees.
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	case "http", "https":
		// already in request form
	default:
		return nil, fmt.Errorf("wscarrier: unsupported URL scheme %q in %q", u.Scheme, cfg.URL)
	}
	proxyURL, err := cfg.proxyFunc()(&http.Request{URL: u, Header: http.Header{}})
	if err != nil {
		return nil, fmt.Errorf("wscarrier: resolving proxy for %s: %w", cfg.URL, err)
	}
	if proxyURL != nil && u.Scheme == "http" {
		return nil, fmt.Errorf("wscarrier: %s cannot be reached through proxy %s: "+
			"a proxied carrier requires wss:// (the proxy is traversed with CONNECT, which is issued only for TLS endpoints)",
			cfg.URL, proxyURL.Redacted())
	}
	return proxyURL, nil
}

// RouteDescription renders a resolved proxy for a log or an error message:
// "direct" when nil, otherwise the proxy URL with any password redacted.
func RouteDescription(proxyURL *url.URL) string {
	if proxyURL == nil {
		return "direct"
	}
	return "via " + proxyURL.Redacted()
}
