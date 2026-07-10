// Package ccbserver implements a standalone HTCondor Condor Connection Broker
// (CCB) server in Go. It is wire-compatible with the C++ CCB protocol for
// registration (CCB_REGISTER), connection requests (CCB_REQUEST) and the
// reverse-connect hello (CCB_REVERSE_CONNECT), and additionally supports a
// streaming/proxy mode for private-to-private connections.
package ccbserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/authz"
)

// Config configures a CCB Server.
type Config struct {
	// PublicAddress is the broker's externally reachable address ("host:port",
	// no angle brackets). It is used to build CCB contact strings
	// ("<PublicAddress>#<id>") and as the proxy rendezvous address. Required.
	PublicAddress string

	// Security is the server-side security config for CCB sessions. CCB
	// sessions are kept un-encrypted (so streaming can splice bytes and so
	// end-to-end CEDAR security is preserved between the real peers); callers
	// should leave Encryption at NEVER. Required.
	Security *security.SecurityConfig

	// RequestTimeout bounds how long a pending request waits for the target to
	// respond / reverse-connect (default 60s).
	RequestTimeout time.Duration

	// TargetIdleTimeout reaps a registered target that sends nothing (not even a
	// heartbeat) for this long -- detecting a silently-dead target (e.g. a network
	// partition with no TCP RST), the equivalent of the C++ CCB's polling reap.
	// It should be a few times the targets' CCB_HEARTBEAT_INTERVAL. Default 3600s
	// (3x the 1200s heartbeat default); set negative to disable.
	TargetIdleTimeout time.Duration

	// Authz, if set, enforces HTCondor ALLOW_/DENY_ authorization per command
	// (CCB_REGISTER -> DAEMON/ADVERTISE_*, CCB_REQUEST -> READ), matching the
	// collector's CCB. If nil, all authenticated peers are authorized (the
	// authentication policy in Security still applies).
	Authz *authz.Policy

	// ReconnectStore, if set, persists reconnect records so a target keeps its
	// CCBID (and advertised sinful) across connection drops and broker
	// restarts. If nil, reconnect state lives only for the process lifetime.
	ReconnectStore ReconnectStore

	// ReconnectAllowAnyIP permits a target to reclaim its CCBID from a
	// different peer IP than it originally registered from (mirrors
	// CCB_RECONNECT_ALLOWED_FROM_ANY_IP). Default false: the peer IP must match.
	ReconnectAllowAnyIP bool

	// ReconnectTTL bounds how long a reconnect record is retained after its
	// target last disconnected before being swept (default 24h). Records for
	// currently-connected targets are never swept.
	ReconnectTTL time.Duration

	// OutboundProxy enables the CCB_PROXY_CONNECT handler (CCB tunneling's
	// outbound mode): an authenticated DAEMON-authorized requester asks this
	// broker to dial a target on its behalf and splice. Default false -- an
	// outbound proxy for anyone is an open-relay/SSRF risk, so it is opt-in and
	// bounded by OutboundTargetAllowlist. Mirrors config CCB_OUTBOUND_PROXY.
	OutboundProxy bool

	// OutboundTargetAllowlist bounds which targets an outbound proxy may dial
	// (host, CIDR, or "*"-glob patterns matched against the target host).
	// Deny-by-default: an empty list permits NO remote targets. Loopback and
	// link-local targets are always refused regardless of the list. Mirrors
	// config CCB_OUTBOUND_TARGET_ALLOWLIST. Enforced by the broker that performs
	// the actual TCP dial (the exit); a next-hop forwarder defers egress control
	// to the exit. Only meaningful with OutboundProxy.
	OutboundTargetAllowlist []string

	// OutboundNextHop, if set, makes this an "inside" CCB: instead of dialing an
	// outbound target directly, it forwards the CCB_PROXY_CONNECT to this next-hop
	// CCB broker (a Sinful) and splices the resulting pipe -- the recursive
	// two-CCB tunnel (§4.3). Empty ⇒ this is an exit CCB that dials directly.
	// Mirrors config CCB_OUTBOUND_NEXT_HOP. Only meaningful with OutboundProxy.
	OutboundNextHop string

	// OutboundNextHopSecurity authenticates this broker (as a CCB client, at
	// DAEMON) to OutboundNextHop. Required when OutboundNextHop is set. Keep
	// Encryption at NEVER, like the inbound Security, so the upstream leg can be
	// spliced.
	OutboundNextHopSecurity *security.SecurityConfig

	// Upstream, if set, makes this an "inside" CCB for INBOUND tunneling: it
	// registers with the upstream (outside) CCB and feeds the reverse-connected
	// sockets that broker forwards down into its own command server, so a client
	// can rendezvous a local registrant through the upstream (recursive streaming
	// proxy, §4.4). It also stamps its derived tunnel contact
	// (<upstream>#<assigned-id>) as the broker in the contacts it hands local
	// registrants, so their advertised sinfuls nest. Independent of OutboundNextHop
	// (the outbound path); a full inside CCB typically points both at the same
	// upstream broker.
	Upstream *UpstreamConfig

	// Logger is used for operational logging (default slog.Default()).
	Logger *slog.Logger
}

// UpstreamConfig configures an inside CCB's registration with its upstream
// (outside) CCB for inbound tunneling.
type UpstreamConfig struct {
	// BrokerAddr is the upstream CCB's address ("host:port"). Required.
	BrokerAddr string
	// Security authenticates the registration (as a CCB client) to the upstream.
	// Required. Keep Encryption at NEVER so forwarded sockets can be spliced.
	Security *security.SecurityConfig
	// HeartbeatInterval is the upstream registration heartbeat (default 1200s).
	HeartbeatInterval time.Duration

	// ReadyFile, if set, is written with this inside CCB's derived tunnel contact
	// once upstream registration completes -- the readiness barrier a local master
	// waits on before injecting the child daemons' CCB_ADDRESS (Model 1,
	// CCB_TUNNEL_READY_FILE in §7). Written atomically (temp + rename).
	ReadyFile string
}

// Server is a CCB broker.
type Server struct {
	cfg      Config
	log      *slog.Logger
	srv      *cedarserver.Server
	outbound outboundTransport // how an outbound proxy reaches a target (direct dial or next-hop CCB)

	mu         sync.Mutex
	nextID     uint64
	nextReq    uint64
	targets    map[uint64]*target          // ccbid -> live registered target
	reconnects map[uint64]*ReconnectRecord // ccbid -> reconnect credentials (survive disconnect)
	requests   map[uint64]*request         // requestID -> pending standard request
	proxies    map[string]*proxySession    // connectID -> pending proxy session

	// Inbound tunneling (Config.Upstream). tunnelContact is this inside CCB's own
	// contact via the upstream ("<outside>#<id>"), used as the broker prefix when
	// stamping local registrants' contacts so they nest; empty until the upstream
	// registration completes. tunnelReady is closed at that point.
	upstream        *ccb.Listener
	tunnelContact   atomic.Pointer[string]
	tunnelReady     chan struct{}
	tunnelReadyOnce sync.Once
}

// target is a registered daemon holding a persistent connection.
type target struct {
	id      uint64
	name    string
	cookie  string
	stream  *stream.Stream
	conn    net.Conn
	writeMu sync.Mutex
}

func (t *target) write(ctx context.Context, ad *classad.ClassAd) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return ccb.WriteControlAd(ctx, t.stream, ad)
}

// request is a pending standard-mode request awaiting the target's result.
type request struct {
	id        uint64
	connectID string
	replyCh   chan replyResult
}

type replyResult struct {
	success bool
	errMsg  string
}

// New creates a CCB Server.
func New(cfg Config) (*Server, error) {
	if cfg.PublicAddress == "" {
		return nil, fmt.Errorf("ccbserver: PublicAddress is required")
	}
	if cfg.Security == nil {
		return nil, fmt.Errorf("ccbserver: Security is required")
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 60 * time.Second
	}
	if cfg.TargetIdleTimeout == 0 {
		cfg.TargetIdleTimeout = 3600 * time.Second // 3x the 1200s heartbeat default
	}
	if cfg.ReconnectTTL == 0 {
		cfg.ReconnectTTL = 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{
		cfg:        cfg,
		log:        cfg.Logger,
		targets:    map[uint64]*target{},
		reconnects: map[uint64]*ReconnectRecord{},
		requests:   map[uint64]*request{},
		proxies:    map[string]*proxySession{},
	}
	// Choose how an outbound proxy reaches a target: forward to a next-hop CCB
	// (inside CCB, two-CCB tunnel) or dial directly (exit CCB).
	if cfg.OutboundNextHop != "" {
		if cfg.OutboundNextHopSecurity == nil {
			return nil, fmt.Errorf("ccbserver: OutboundNextHopSecurity is required when OutboundNextHop is set")
		}
		// Trivial self-loop guard. A deeper A->B->A cycle is a misconfiguration
		// bounded by the connect timeout; the wire format carries no hop counter,
		// so we cannot detect it here without breaking §4.1 compatibility.
		if hop := strings.Trim(cfg.OutboundNextHop, "<>"); hop == cfg.PublicAddress || hop == s.proxyAddrSinful() {
			return nil, fmt.Errorf("ccbserver: OutboundNextHop %q points at this broker (routing loop)", cfg.OutboundNextHop)
		}
		s.outbound = &nextHopTransport{
			broker:  cfg.OutboundNextHop,
			sec:     cfg.OutboundNextHopSecurity,
			timeout: cfg.RequestTimeout,
		}
	} else {
		s.outbound = &tcpDirectTransport{s: s}
	}
	if cfg.Upstream != nil {
		if cfg.Upstream.BrokerAddr == "" || cfg.Upstream.Security == nil {
			return nil, fmt.Errorf("ccbserver: Upstream requires BrokerAddr and Security")
		}
		s.tunnelReady = make(chan struct{})
	}
	if err := s.loadReconnects(); err != nil {
		return nil, err
	}
	s.srv = cedarserver.New(cfg.Security)
	if cfg.Authz != nil {
		s.srv.Authorizer = cfg.Authz.Authorize
	}
	s.RegisterOn(s.srv)
	return s, nil
}

// RegisterOn registers the CCB command handlers onto an existing cedar
// command-dispatch server. A standalone golang-ccb registers on its own internal
// server (via New); a host daemon that wants an *embedded* CCB -- e.g. the
// collector serving CCB on its own shared command socket, like the C++ collector's
// ENABLE_CCB_SERVER -- creates the Server, calls RegisterOn(hostServer), then runs
// the host's own Serve loop and StartBackground for reconnect sweeping.
//
// The command server uses each command's registered levels to compute the
// session's ValidCommands after authentication (HTCondor's SECMAN ValidCommands, a
// C++ peer needs them to reuse the session) and, when the host server has an
// Authorizer, to authorize per command. CCB_REGISTER accepts DAEMON or any
// ADVERTISE_* level (matching the C++ ccb_server); CCB_REQUEST needs READ.
// CCB_REVERSE_CONNECT is raw (no security handshake), so it is registered with
// HandleRaw regardless of the host server's policy.
func (s *Server) RegisterOn(cs *cedarserver.Server) {
	cs.Handle(ccb.CommandRegister, s.handleRegister,
		"DAEMON", "ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER")
	cs.Handle(ccb.CommandRequest, s.handleRequest, "READ")
	cs.HandleRaw(ccb.CommandReverseConnect, s.handleReverseConnect)
	// Outbound tunneling (opt-in): dial a target on a requester's behalf and
	// splice. DAEMON authorization only -- never the open level the raw
	// reverse-connect rendezvous uses -- because it is an open-relay/SSRF risk.
	if s.cfg.OutboundProxy {
		cs.Handle(ccb.CommandProxyConnect, s.handleProxyConnect, "DAEMON")
	}
	// Inbound tunneling: an inside CCB answers a master's CCB_GET_TUNNEL_ADDRESS
	// with its derived tunnel address (Model 2 off-host CCB orchestration).
	if s.cfg.Upstream != nil {
		cs.Handle(ccb.CommandGetTunnelAddress, s.handleGetTunnelAddress, "DAEMON")
	}
}

// StartBackground starts the server's background maintenance (reconnect-record
// sweeping) under ctx. A standalone server does this from Serve; an embedded
// server whose host runs the Serve loop must call it explicitly. No-op without a
// reconnect store.
func (s *Server) StartBackground(ctx context.Context) {
	if s.cfg.ReconnectStore != nil {
		go s.sweepLoop(ctx)
	}
	if s.cfg.Upstream != nil {
		s.startUpstream(ctx)
	}
}

// loadReconnects restores persisted reconnect records and advances nextID past
// the highest known CCBID (plus a guard for records that may not have been
// flushed before a prior crash), mirroring the C++ LoadReconnectInfo behavior.
func (s *Server) loadReconnects() error {
	if s.cfg.ReconnectStore == nil {
		return nil
	}
	recs, err := s.cfg.ReconnectStore.Load(context.Background())
	if err != nil {
		return fmt.Errorf("loading reconnect records: %w", err)
	}
	var maxID uint64
	for i := range recs {
		r := recs[i]
		s.reconnects[r.CCBID] = &r
		if r.CCBID > maxID {
			maxID = r.CCBID
		}
	}
	if maxID > 0 {
		// Guard against handing out a CCBID that a pre-restart registration may
		// have been assigned but not yet persisted.
		s.nextID = maxID + 100
	}
	s.log.Info("ccb reconnect records loaded", "count", len(recs), "next_ccbid", s.nextID+1)
	return nil
}

// Serve accepts connections on l until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.log.Info("CCB server started", "address", s.cfg.PublicAddress, "listen", l.Addr().String())
	s.StartBackground(ctx)
	return s.srv.Serve(ctx, l)
}

// sweepLoop periodically removes stale reconnect records until ctx is cancelled.
func (s *Server) sweepLoop(ctx context.Context) {
	interval := s.cfg.ReconnectTTL / 24
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.SweepReconnects()
		}
	}
}

// contactString builds the contact string advertised to a local registrant.
// For an inside CCB (Upstream configured) that has completed upstream
// registration, the broker prefix is this CCB's own tunnel contact
// ("<outside>#<id>"), so the registrant's contact nests ("<outside>#<id>#<its
// id>"); otherwise it is this CCB's own public address.
func (s *Server) contactString(id uint64) string {
	if tc := s.tunnelContact.Load(); tc != nil && *tc != "" {
		return *tc + "#" + strconv.FormatUint(id, 10)
	}
	return ccb.ContactString(s.cfg.PublicAddress, id)
}

// authorize applies the configured ALLOW_/DENY_ policy for command, verifying
// the peer's authenticated identity against the authorization levels the command
// was registered with (the single source of truth also used to advertise
// ValidCommands). It returns nil if authorized (or if no policy is configured),
// and a descriptive error otherwise.
func (s *Server) authorize(c *cedarserver.Conn, command int) error {
	if s.cfg.Authz == nil {
		return nil
	}
	user := ""
	if c.Negotiation != nil {
		user = c.Negotiation.User
	}
	for _, perm := range s.srv.CommandPerms(command) {
		if s.cfg.Authz.Authorize(perm, c.RemoteAddr, user) {
			return nil
		}
	}
	return fmt.Errorf("authorization denied for command %d from %s (user %q)", command, c.RemoteAddr, user)
}

// peerIP extracts the IP from a "host:port" peer address, returning nil if it
// cannot be parsed.
func peerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

// handleRegister handles CCB_REGISTER: assign a ccbid, reply, then service the
// persistent connection (result reports + heartbeats) until it drops.
func (s *Server) handleRegister(ctx context.Context, c *cedarserver.Conn) error {
	if err := s.authorize(c, ccb.CommandRegister); err != nil {
		s.log.Warn("register denied", "remote", c.RemoteAddr, "error", err)
		return err
	}
	ad, err := ccb.ReadControlAd(ctx, c.Stream)
	if err != nil {
		return fmt.Errorf("register: reading ad: %w", err)
	}
	name := ccb.AdString(ad, ccb.AttrName)

	t := &target{
		name:   name,
		stream: c.Stream,
		conn:   c.Stream.GetConnection(),
	}

	peerIPStr := ""
	if ip := peerIP(c.RemoteAddr); ip != nil {
		peerIPStr = ip.String()
	}
	reqCookie := ccb.AdString(ad, ccb.AttrClaimID)
	prevContact := ccb.AdString(ad, ccb.AttrCCBID)

	s.mu.Lock()
	// Reconnect: honor a prior ccbid if the presented cookie (and, unless
	// reconnect-from-any-ip is allowed, the peer IP) matches a known record.
	// The record survives target disconnect and broker restart, so the target
	// keeps its advertised sinful.
	reused := false
	if prevContact != "" && reqCookie != "" {
		if prevID, ok := parseContactID(prevContact); ok {
			if rec, ok := s.reconnects[prevID]; ok && rec.Cookie == reqCookie &&
				(s.cfg.ReconnectAllowAnyIP || rec.PeerIP == peerIPStr) {
				t.id = prevID
				t.cookie = rec.Cookie // keep the client's existing ClaimId valid
				reused = true
			}
		}
	}
	if !reused {
		cookie, err := ccb.GenerateConnectID()
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.nextID++
		t.id = s.nextID
		t.cookie = cookie
	}
	s.targets[t.id] = t
	rec := &ReconnectRecord{
		CCBID:     t.id,
		Cookie:    t.cookie,
		PeerIP:    peerIPStr,
		Name:      name,
		UpdatedAt: time.Now(),
	}
	s.reconnects[t.id] = rec
	s.mu.Unlock()

	if s.cfg.ReconnectStore != nil {
		s.cfg.ReconnectStore.Put(*rec)
	}

	contact := s.contactString(t.id)
	reply := ccb.NewAd(map[string]any{
		ccb.AttrCommand:      ccb.CommandRegister,
		ccb.AttrCCBID:        contact,
		ccb.AttrClaimID:      t.cookie,
		ccb.AttrCCBStreaming: true,
	})
	if err := t.write(ctx, reply); err != nil {
		s.removeTarget(t.id)
		return fmt.Errorf("register: reply: %w", err)
	}
	s.log.Info("target registered", "ccbid", contact, "name", name)

	// Service the persistent socket until it drops.
	s.serveTarget(ctx, t)
	s.removeTarget(t.id)
	s.log.Info("target deregistered", "ccbid", contact, "name", name)
	return nil
}

// serveTarget reads result reports and heartbeats from a target's persistent
// connection until it errors. If TargetIdleTimeout is set, a target that sends
// nothing (not even a heartbeat) for that long is reaped -- the goroutine-per-
// target equivalent of the C++ CCB's polling reap of a silently-dead target
// (e.g. a network partition with no TCP RST), so its registration does not leak.
func (s *Server) serveTarget(ctx context.Context, t *target) {
	for {
		if s.cfg.TargetIdleTimeout > 0 {
			_ = t.conn.SetReadDeadline(time.Now().Add(s.cfg.TargetIdleTimeout))
		}
		ad, err := ccb.ReadControlAd(ctx, t.stream)
		if err != nil {
			if s.cfg.TargetIdleTimeout > 0 {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					s.log.Info("target reaped: idle past TargetIdleTimeout", "ccbid", t.id, "name", t.name)
				}
			}
			return
		}
		if cmd, ok := ccb.AdInt(ad, ccb.AttrCommand); ok && int(cmd) == ccb.CommandAlive {
			// Echo heartbeat.
			_ = t.write(ctx, ccb.NewAd(map[string]any{ccb.AttrCommand: ccb.CommandAlive}))
			continue
		}
		// Otherwise a result report for a standard-mode request.
		s.deliverResult(ad)
	}
}

// deliverResult routes a target's result report to the waiting requester.
func (s *Server) deliverResult(ad *classad.ClassAd) {
	reqIDStr := ccb.AdString(ad, ccb.AttrRequestID)
	reqID, err := strconv.ParseUint(reqIDStr, 10, 64)
	if err != nil {
		return
	}
	s.mu.Lock()
	req, ok := s.requests[reqID]
	s.mu.Unlock()
	if !ok {
		return
	}
	success, _ := ccb.AdBool(ad, ccb.AttrResult)
	res := replyResult{success: success, errMsg: ccb.AdString(ad, ccb.AttrErrorString)}
	select {
	case req.replyCh <- res:
	default:
	}
}

func (s *Server) removeTarget(id uint64) {
	s.mu.Lock()
	delete(s.targets, id)
	// Keep the reconnect record (so the target can reclaim its CCBID), but
	// stamp it so the sweep TTL counts from disconnect.
	var rec *ReconnectRecord
	if r, ok := s.reconnects[id]; ok {
		r.UpdatedAt = time.Now()
		cp := *r
		rec = &cp
	}
	s.mu.Unlock()

	if rec != nil && s.cfg.ReconnectStore != nil {
		s.cfg.ReconnectStore.Put(*rec)
	}
}

// SweepReconnects removes reconnect records for targets that are not currently
// connected and whose records are older than ReconnectTTL, mirroring the C++
// SweepReconnectInfo. It is safe to call periodically.
func (s *Server) SweepReconnects() {
	cutoff := time.Now().Add(-s.cfg.ReconnectTTL)
	var stale []uint64
	s.mu.Lock()
	for id, rec := range s.reconnects {
		if _, live := s.targets[id]; live {
			continue
		}
		if rec.UpdatedAt.Before(cutoff) {
			stale = append(stale, id)
		}
	}
	for _, id := range stale {
		delete(s.reconnects, id)
	}
	s.mu.Unlock()

	if s.cfg.ReconnectStore != nil {
		for _, id := range stale {
			s.cfg.ReconnectStore.Delete(id)
		}
	}
	if len(stale) > 0 {
		s.log.Info("ccb reconnect records swept", "count", len(stale))
	}
}

// parseTargetID parses the CCBID a requester names in a CCB_REQUEST. Per the
// protocol this is the BARE numeric ccbid (both CCBClient and the Go client send
// only the id for the hop). Parsing is STRICT -- a value not wholly consumed as a
// single unsigned integer is rejected -- which is what makes an *old* client's
// mis-parse of a nested contact fail cleanly: an old client splits on the first
// '#' and sends e.g. "42#17", which we reject rather than lenient-routing to
// registrant 42 (see the CCB tunneling design §4.7). Do NOT accept a full
// "addr#id" contact here; that fallback would reintroduce the leniency.
func parseTargetID(s string) (uint64, bool) {
	id, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// parseContactID extracts the numeric ccbid from a contact string "addr#id".
func parseContactID(contact string) (uint64, bool) {
	_, idStr, ok := addresses.SplitCCBContact(contact)
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// proxyAddrSinful returns the broker's rendezvous address as an HTCondor sinful.
func (s *Server) proxyAddrSinful() string {
	return "<" + strings.Trim(s.cfg.PublicAddress, "<>") + ">"
}
