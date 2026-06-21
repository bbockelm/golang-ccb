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

	// Logger is used for operational logging (default slog.Default()).
	Logger *slog.Logger
}

// Server is a CCB broker.
type Server struct {
	cfg Config
	log *slog.Logger
	srv *cedarserver.Server

	mu       sync.Mutex
	nextID   uint64
	nextReq  uint64
	targets  map[uint64]*target       // ccbid -> registered target
	requests map[uint64]*request      // requestID -> pending standard request
	proxies  map[string]*proxySession // connectID -> pending proxy session
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
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		targets:  map[uint64]*target{},
		requests: map[uint64]*request{},
		proxies:  map[string]*proxySession{},
	}
	s.srv = cedarserver.New(cfg.Security)
	s.srv.Handle(ccb.CommandRegister, s.handleRegister)
	s.srv.Handle(ccb.CommandRequest, s.handleRequest)
	s.srv.HandleRaw(ccb.CommandReverseConnect, s.handleReverseConnect)
	return s, nil
}

// Serve accepts connections on l until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.log.Info("CCB server started", "address", s.cfg.PublicAddress, "listen", l.Addr().String())
	return s.srv.Serve(ctx, l)
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

	cookie, err := ccb.GenerateConnectID()
	if err != nil {
		return err
	}
	t.cookie = cookie

	s.mu.Lock()
	// Reconnect: honor a prior ccbid if the cookie matches.
	reused := false
	if prevContact := ccb.AdString(ad, ccb.AttrCCBID); prevContact != "" {
		if prevID, ok := parseContactID(prevContact); ok {
			if old, ok := s.targets[prevID]; ok && old.cookie == ccb.AdString(ad, ccb.AttrClaimID) {
				t.id = prevID
				reused = true
			}
		}
	}
	if !reused {
		s.nextID++
		t.id = s.nextID
	}
	s.targets[t.id] = t
	s.mu.Unlock()

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
	s.mu.Unlock()
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
