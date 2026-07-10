package ccbserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/bbockelm/golang-ccb/transport/carrier"
	"github.com/bbockelm/golang-ccb/transport/fstun"
	"github.com/bbockelm/golang-ccb/transport/wscarrier"
)

// A broker address may name a non-TCP carrier instead of a "host:port" Sinful.
// The scheme selects how the inside CCB reaches the outside CCB (and how the
// outside CCB accepts inside CCBs). See docs/TRANSPORTS.md.
//
//	fs:<absolute-dir>          filesystem carrier, e.g. fs:/gpfs/pool/ccb-tunnel
//	ws://host:port/path        WebSocket carrier (plaintext; test/dev)
//	wss://host:port/path       WebSocket carrier over TLS (production)
type carrierRef struct {
	scheme string // "fs" or "ws" ("ws" covers ws:// and wss://)
	path   string // filesystem root for scheme "fs"
	url    string // full ws/wss URL for scheme "ws"
	tls    bool   // wss (TLS)
}

// parseCarrierRef reports whether addr names a carrier, and if so parses it. A
// bare "host:port" (or shared-port) Sinful is not a carrier (ok == false) and
// keeps the default TCP path.
func parseCarrierRef(addr string) (carrierRef, bool) {
	addr = strings.TrimSpace(addr)
	if p, ok := strings.CutPrefix(addr, "fs:"); ok {
		return carrierRef{scheme: "fs", path: p}, true
	}
	if strings.HasPrefix(addr, "wss://") {
		return carrierRef{scheme: "ws", url: addr, tls: true}, true
	}
	if strings.HasPrefix(addr, "ws://") {
		return carrierRef{scheme: "ws", url: addr}, true
	}
	return carrierRef{}, false
}

func isCarrier(addr string) bool {
	_, ok := parseCarrierRef(addr)
	return ok
}

// fstunConfig builds the fstun endpoint config for a carrier ref (defaults for
// everything but the root).
func (r carrierRef) fstunConfig() fstun.Config {
	return fstun.Config{Root: r.path}
}

// carrierClient is an inside CCB's single, shared link to its outside CCB over a
// carrier: one fstun pipe with a yamux client on top. Both the upstream
// registration and every outbound proxy-connect ride it as yamux streams. The
// session is established lazily on first dial and transparently re-established if
// it dies, so cedar's own reconnect loops recover a dropped carrier.
type carrierClient struct {
	ref carrierRef
	log *slog.Logger

	// WebSocket dial parameters (scheme "ws"); unused for "fs".
	token       string
	tokenSource func(ctx context.Context) (string, error)
	clientTLS   *tls.Config

	mu   sync.Mutex
	md   *carrier.MuxDialer
	done bool
}

func newCarrierClient(ref carrierRef, cfg Config, log *slog.Logger) *carrierClient {
	return &carrierClient{
		ref:         ref,
		log:         log,
		token:       cfg.CarrierToken,
		tokenSource: cfg.CarrierTokenSource,
		clientTLS:   cfg.CarrierClientTLS,
	}
}

// dialPipe establishes the underlying carrier byte pipe for this ref.
func (c *carrierClient) dialPipe(ctx context.Context) (net.Conn, error) {
	switch c.ref.scheme {
	case "fs":
		return fstun.Dial(ctx, c.ref.fstunConfig())
	case "ws":
		return wscarrier.Dial(ctx, wscarrier.DialConfig{
			URL:         c.ref.url,
			Token:       c.token,
			TokenSource: c.tokenSource,
			TLS:         c.clientTLS,
		})
	default:
		return nil, fmt.Errorf("ccbserver: unknown carrier scheme %q", c.ref.scheme)
	}
}

func (c *carrierClient) describe() string {
	if c.ref.scheme == "ws" {
		return "ws:" + c.ref.url
	}
	return c.ref.scheme + ":" + c.ref.path
}

// dial is the ccb.BrokerDialer handed to cedar: it opens a fresh logical
// connection (a yamux stream) to the outside CCB over the shared pipe,
// establishing the pipe first if needed. brokerAddr is ignored -- the carrier is
// point-to-point.
func (c *carrierClient) dial(ctx context.Context, brokerAddr string) (net.Conn, error) {
	md, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	return md.Open(ctx)
}

// session returns a live yamux client session, establishing (or re-establishing)
// the underlying fstun pipe if there is none or the previous one has died.
func (c *carrierClient) session(ctx context.Context) (*carrier.MuxDialer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return nil, net.ErrClosed
	}
	if c.md != nil && !c.md.Closed() {
		return c.md, nil
	}
	if c.md != nil {
		_ = c.md.Close()
		c.md = nil
	}
	pipe, err := c.dialPipe(ctx)
	if err != nil {
		return nil, fmt.Errorf("carrier %s: dialing pipe: %w", c.describe(), err)
	}
	md, err := carrier.NewMuxDialer(pipe)
	if err != nil {
		_ = pipe.Close()
		return nil, fmt.Errorf("carrier %s: yamux client: %w", c.describe(), err)
	}
	c.md = md
	c.log.Info("carrier session established", "carrier", c.describe())
	return md, nil
}

func (c *carrierClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done = true
	if c.md != nil {
		_ = c.md.Close()
		c.md = nil
	}
}

// detectCarrier inspects the inside-CCB knobs (Upstream.BrokerAddr and
// OutboundNextHop) for a carrier scheme and, if present, returns a shared
// carrierClient. Both knobs typically point at the same outside CCB; if both name
// carriers they must name the same one (a single point-to-point pipe).
func (s *Server) detectCarrier() (*carrierClient, error) {
	var refs []carrierRef
	if s.cfg.Upstream != nil {
		if r, ok := parseCarrierRef(s.cfg.Upstream.BrokerAddr); ok {
			refs = append(refs, r)
		}
	}
	if r, ok := parseCarrierRef(s.cfg.OutboundNextHop); ok {
		refs = append(refs, r)
	}
	if len(refs) == 0 {
		return nil, nil
	}
	for _, r := range refs[1:] {
		if r != refs[0] {
			return nil, fmt.Errorf("ccbserver: Upstream and OutboundNextHop name different carriers (%v vs %v); a single carrier pipe is required", refs[0], r)
		}
	}
	return newCarrierClient(refs[0], s.cfg, s.log), nil
}

// startCarrierListener runs an outside CCB's acceptor for inside CCBs arriving
// over a carrier: one byte pipe per inside CCB, yamux-server multiplexed into
// ordinary command streams served by the same cedar command loop as TCP.
func (s *Server) startCarrierListener(ctx context.Context) {
	ref, ok := parseCarrierRef(s.cfg.CarrierListen)
	if !ok {
		s.log.Error("CarrierListen is not a recognized carrier address", "value", s.cfg.CarrierListen)
		return
	}
	inner, err := s.carrierNetListener(ref)
	if err != nil {
		s.log.Error("failed to start carrier listener", "carrier", s.cfg.CarrierListen, "error", err)
		return
	}
	ml := carrier.NewMuxListener(inner)
	go func() {
		<-ctx.Done()
		_ = ml.Close()
	}()
	go func() {
		s.log.Info("CCB carrier listener started", "carrier", s.cfg.CarrierListen)
		if err := s.srv.Serve(ctx, ml); err != nil && ctx.Err() == nil {
			s.log.Error("carrier listener serve ended", "error", err)
		}
	}()
}

// carrierNetListener builds the underlying (pre-yamux) net.Listener for a carrier.
func (s *Server) carrierNetListener(ref carrierRef) (net.Listener, error) {
	switch ref.scheme {
	case "fs":
		return fstun.Listen(ref.fstunConfig())
	case "ws":
		if s.cfg.CarrierTokenVerify == nil {
			return nil, fmt.Errorf("ccbserver: a WebSocket CarrierListen requires CarrierTokenVerify")
		}
		u, err := url.Parse(ref.url)
		if err != nil {
			return nil, fmt.Errorf("ccbserver: bad carrier URL %q: %w", ref.url, err)
		}
		if ref.tls && s.cfg.CarrierTLS == nil {
			return nil, fmt.Errorf("ccbserver: a wss:// CarrierListen requires CarrierTLS")
		}
		return wscarrier.Listen(wscarrier.ListenConfig{
			Addr:   u.Host,
			Path:   u.Path,
			TLS:    s.cfg.CarrierTLS,
			Verify: s.cfg.CarrierTokenVerify,
		})
	default:
		return nil, fmt.Errorf("ccbserver: unknown carrier scheme %q", ref.scheme)
	}
}
