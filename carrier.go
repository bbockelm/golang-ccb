package ccbserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/bbockelm/golang-ccb/transport/carrier"
	"github.com/bbockelm/golang-ccb/transport/fstun"
)

// A broker address may name a non-TCP carrier instead of a "host:port" Sinful.
// The scheme selects how the inside CCB reaches the outside CCB (and how the
// outside CCB accepts inside CCBs). Currently only the filesystem carrier ("fs")
// is implemented; a WebSocket carrier ("wss") is planned (see docs/TRANSPORTS.md).
//
//	fs:<absolute-dir>   e.g. fs:/gpfs/pool/ccb-tunnel
type carrierRef struct {
	scheme string
	path   string // filesystem root for scheme "fs"
}

// parseCarrierRef reports whether addr names a carrier, and if so parses it. A
// bare "host:port" (or shared-port) Sinful is not a carrier (ok == false) and
// keeps the default TCP path.
func parseCarrierRef(addr string) (carrierRef, bool) {
	addr = strings.TrimSpace(addr)
	if p, ok := strings.CutPrefix(addr, "fs:"); ok {
		return carrierRef{scheme: "fs", path: p}, true
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

	mu   sync.Mutex
	md   *carrier.MuxDialer
	done bool
}

func newCarrierClient(ref carrierRef, log *slog.Logger) *carrierClient {
	return &carrierClient{ref: ref, log: log}
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
	pipe, err := fstun.Dial(ctx, c.ref.fstunConfig())
	if err != nil {
		return nil, fmt.Errorf("carrier %s:%s: dialing pipe: %w", c.ref.scheme, c.ref.path, err)
	}
	md, err := carrier.NewMuxDialer(pipe)
	if err != nil {
		_ = pipe.Close()
		return nil, fmt.Errorf("carrier %s:%s: yamux client: %w", c.ref.scheme, c.ref.path, err)
	}
	c.md = md
	c.log.Info("carrier session established", "scheme", c.ref.scheme, "path", c.ref.path)
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
	return newCarrierClient(refs[0], s.log), nil
}

// startCarrierListener runs an outside CCB's acceptor for inside CCBs arriving
// over a carrier: one fstun pipe per inside CCB, yamux-server multiplexed into
// ordinary command streams served by the same cedar command loop as TCP.
func (s *Server) startCarrierListener(ctx context.Context) {
	ref, ok := parseCarrierRef(s.cfg.CarrierListen)
	if !ok {
		s.log.Error("CarrierListen is not a recognized carrier address", "value", s.cfg.CarrierListen)
		return
	}
	ln, err := fstun.Listen(ref.fstunConfig())
	if err != nil {
		s.log.Error("failed to start carrier listener", "scheme", ref.scheme, "path", ref.path, "error", err)
		return
	}
	ml := carrier.NewMuxListener(ln)
	go func() {
		<-ctx.Done()
		_ = ml.Close()
	}()
	go func() {
		s.log.Info("CCB carrier listener started", "scheme", ref.scheme, "path", ref.path)
		if err := s.srv.Serve(ctx, ml); err != nil && ctx.Err() == nil {
			s.log.Error("carrier listener serve ended", "error", err)
		}
	}()
}
