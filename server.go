// Package ccbserver implements a standalone HTCondor Condor Connection Broker
// (CCB) server in Go. It is wire-compatible with the C++ CCB protocol for
// registration (CCB_REGISTER), connection requests (CCB_REQUEST) and the
// reverse-connect hello (CCB_REVERSE_CONNECT), and additionally supports a
// streaming/proxy mode for private-to-private connections.
package ccbserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
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

	// Logger is used for operational logging (default slog.Default()).
	Logger *slog.Logger
}

// Server is a CCB broker.
type Server struct {
	cfg Config
	log *slog.Logger
	srv *cedarserver.Server

	mu         sync.Mutex
	nextID     uint64
	nextReq    uint64
	targets    map[uint64]*target          // ccbid -> live registered target
	reconnects map[uint64]*ReconnectRecord // ccbid -> reconnect credentials (survive disconnect)
	requests   map[uint64]*request         // requestID -> pending standard request
	proxies    map[string]*proxySession    // connectID -> pending proxy session
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
	if err := s.loadReconnects(); err != nil {
		return nil, err
	}
	// Give the security layer our authorization policy so its post-auth response
	// reports the authenticated identity (FQU) and the CCB commands this peer is
	// authorized for -- HTCondor's SECMAN ValidCommands, which a C++ peer needs
	// to establish the session. This mirrors authorize() below.
	if cfg.Authz != nil {
		cfg.Security.PostAuthPolicy = func(user, peerAddr string) (string, []int) {
			ip := peerIP(peerAddr)
			var valid []int
			for _, cmd := range []int{ccb.CommandRegister, ccb.CommandRequest} {
				for _, perm := range authz.CommandPerms(ccb.CommandRegister, ccb.CommandRequest, cmd) {
					if cfg.Authz.Verify(perm, ip, user) {
						valid = append(valid, cmd)
						break
					}
				}
			}
			// The FQU is the authenticated identity, matching what authorize()
			// verifies against (mapfile canonicalization is a future refinement).
			return user, valid
		}
	}

	s.srv = cedarserver.New(cfg.Security)
	s.srv.Handle(ccb.CommandRegister, s.handleRegister)
	s.srv.Handle(ccb.CommandRequest, s.handleRequest)
	s.srv.HandleRaw(ccb.CommandReverseConnect, s.handleReverseConnect)
	return s, nil
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
	if s.cfg.ReconnectStore != nil {
		go s.sweepLoop(ctx)
	}
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

// contactString builds the contact string advertised to clients.
func (s *Server) contactString(id uint64) string {
	return ccb.ContactString(s.cfg.PublicAddress, id)
}

// authorize applies the configured ALLOW_/DENY_ policy for command, using the
// peer's IP and authenticated identity. It returns nil if authorized (or if no
// policy is configured), and a descriptive error otherwise.
func (s *Server) authorize(c *cedarserver.Conn, command int) error {
	if s.cfg.Authz == nil {
		return nil
	}
	ip := peerIP(c.RemoteAddr)
	user := ""
	if c.Negotiation != nil {
		user = c.Negotiation.User
	}
	for _, perm := range authz.CommandPerms(ccb.CommandRegister, ccb.CommandRequest, command) {
		if s.cfg.Authz.Verify(perm, ip, user) {
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
// connection until it errors.
func (s *Server) serveTarget(ctx context.Context, t *target) {
	for {
		ad, err := ccb.ReadControlAd(ctx, t.stream)
		if err != nil {
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

// parseTargetID parses the CCBID a requester names: per the protocol this is
// the bare numeric ccbid (CCBClient sends only the id after the '#'), but we
// also accept a full "addr#id" contact for robustness.
func parseTargetID(s string) (uint64, bool) {
	if id, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err == nil {
		return id, true
	}
	return parseContactID(s)
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
