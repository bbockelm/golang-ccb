package ccbserver

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/ccb"
	"github.com/htcondor/cedar/client/sharedport"
	"github.com/htcondor/cedar/security"
	cedarserver "github.com/htcondor/cedar/server"
)

// outboundTransport yields a connected byte pipe to a target for the proxy relay.
// It is the Stage-C seam: an exit CCB dials the target directly, an inside CCB
// forwards to a next-hop CCB. The "reach the next-hop" step is the future
// pluggable carrier (TCP now).
type outboundTransport interface {
	// connect returns a pipe carrying opaque bytes to target (a Sinful), or an
	// error whose message is safe to relay back to the requester. ttl is the
	// remaining outbound hop budget: a forwarding transport refuses at <= 0 and
	// forwards ttl-1; a direct transport ignores it (it dials, it does not forward).
	connect(ctx context.Context, target string, ttl int) (net.Conn, error)
	// describe names the transport for logging.
	describe() string
}

// tcpDirectTransport is the exit CCB: it enforces egress control (loopback
// refusal + allow-list) and dials the target directly over TCP.
type tcpDirectTransport struct{ s *Server }

func (t *tcpDirectTransport) describe() string { return "direct" }

func (t *tcpDirectTransport) connect(ctx context.Context, target string, _ int) (net.Conn, error) {
	dialAddr, sharedPortID, err := t.s.outboundTargetAllowed(target)
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, t.s.cfg.RequestTimeout)
	defer cancel()
	// The literal-address check in outboundTargetAllowed cannot see what a
	// hostname resolves to; check the resolved address too.
	control := chainDialControl(RefuseLocalAddresses, t.s.cfg.DialControl)

	// A target behind shared port needs the SHARED_PORT_CONNECT handoff before
	// anything else crosses the connection: a bare TCP connect reaches the
	// remote condor_shared_port with nothing saying which daemon it is for, and
	// it is closed without a reply. The requester cannot do this itself -- on
	// the outbound-CCB path the client hands us the whole sinful and expects
	// the broker to reach it (CCB_TUNNELING_DESIGN.md section 5: "non-blocking
	// dial the target via the standard connect path (so the target may itself
	// be direct / shared-port / CCB-routed)").
	if sharedPortID != "" {
		spc := sharedport.NewSharedPortClient("htc-ccb outbound proxy")
		spc.DialControl = control
		st, err := spc.ConnectViaSharedPort(dctx, dialAddr, sharedPortID, t.s.cfg.RequestTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to reach target behind shared port: %w", err)
		}
		// The handoff writes and reads nothing back, so no bytes are buffered
		// above the connection: the raw socket is positioned exactly where the
		// relay needs it, with the target daemon on the other end.
		return st.GetConnection(), nil
	}

	d := net.Dialer{Control: control}
	conn, err := d.DialContext(dctx, "tcp", dialAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial target: %w", err)
	}
	return conn, nil
}

// nextHopTransport is an inside CCB: it forwards the request one hop by speaking
// CCB_PROXY_CONNECT to the next-hop CCB and hands back the resulting pipe. Egress
// control (allow-list) is deferred to whichever hop finally dials.
type nextHopTransport struct {
	broker  string
	sec     *security.SecurityConfig
	timeout time.Duration
	dial    ccb.BrokerDialer // non-nil ⇒ reach the next hop over a carrier, not TCP
}

func (t *nextHopTransport) describe() string { return "next-hop " + t.broker }

func (t *nextHopTransport) connect(ctx context.Context, target string, ttl int) (net.Conn, error) {
	// Decrementing TTL (like TCP): the originator set it; we only decrement and
	// refuse -- so the chain length is bounded by the originator, not any broker.
	if ttl <= 0 {
		return nil, fmt.Errorf("outbound proxy TTL expired")
	}
	conn, err := ccb.OutboundConnect(ctx, t.broker, target, ccb.OutboundOptions{
		Security: t.sec,
		Name:     "ccb-inside-forwarder",
		Timeout:  t.timeout,
		Dial:     t.dial,
		TTL:      ttl - 1, // next hop refuses once the originator's budget is spent
	})
	if err != nil {
		return nil, fmt.Errorf("next-hop %s: %w", t.broker, err)
	}
	return conn, nil
}

// handleProxyConnect services CCB_PROXY_CONNECT -- CCB tunneling's outbound mode.
// An authenticated, DAEMON-authorized requester asks the broker to dial a target
// (addressed by Sinful, not a registered CCBID) and splice. The broker validates
// the target against its allow-list, dials it, replies {Result}, then relays
// opaque bytes: it disables its own session crypto by splicing the raw sockets,
// while the requester runs a full end-to-end CEDAR handshake to the real target
// through the relay (the broker never holds the end-to-end keys).
func (s *Server) handleProxyConnect(ctx context.Context, c *cedarserver.Conn) error {
	if err := s.authorize(c, ccb.CommandProxyConnect); err != nil {
		s.log.Warn("proxy-connect denied", "remote", c.RemoteAddr, "error", err)
		return s.replyFailure(ctx, c, "authorization denied")
	}
	reqEp := s.limits.endpointOf(c.Stream.GetConnection())
	if err := s.limits.take(ctx, kindProxyConnect, s.maxWait(), reqEp); err != nil {
		return s.replyFailure(ctx, c, err.Error())
	}
	// Hold the requester's side of the splice caps before dialing, so a
	// refused relay costs no connection to the target.
	releaseSplice, err := s.limits.acquire(kindSplices, reqEp)
	if err != nil {
		return s.replyFailure(ctx, c, err.Error())
	}
	defer func() { releaseSplice() }()
	ad, err := ccb.ReadControlAd(ctx, c.Stream)
	if err != nil {
		return fmt.Errorf("proxy-connect: reading ad: %w", err)
	}

	target := ccb.AdString(ad, ccb.AttrMyAddress) // "address to dial" (§4.1)
	connectID := ccb.AdString(ad, ccb.AttrClaimID)
	name := ccb.AdString(ad, ccb.AttrName)
	if target == "" || connectID == "" {
		return s.replyFailure(ctx, c, "proxy-connect missing MyAddress or ClaimId")
	}

	// Decrementing TTL (like TCP): the originator set it; intermediate brokers only
	// decrement. Fall back to our configured default when the request carries none.
	ttl := s.cfg.OutboundTTL
	if ttl <= 0 {
		ttl = 8
	}
	if v, ok := ccb.AdInt(ad, ccb.AttrCCBTTL); ok {
		ttl = int(v)
	}

	// Reach the target via the configured transport: an exit CCB dials directly
	// (enforcing loopback refusal + allow-list), an inside CCB forwards one hop to
	// its next-hop CCB with TTL-1 (§4.3). Any failure is reported to the requester
	// and closes.
	targetConn, err := s.outbound.connect(ctx, target, ttl)
	if err != nil {
		s.log.Warn("proxy-connect target unreachable", "remote", c.RemoteAddr, "target", target,
			"via", s.outbound.describe(), "error", err)
		return s.replyFailure(ctx, c, err.Error())
	}

	// An exit CCB knows where it actually connected, so the target's network
	// is charged too: its caps and bandwidth limits protect that network from
	// the relay. A forwarding broker's connection goes to its next hop, not
	// the target; the exit that dials accounts for the target.
	eps := []endpoint{reqEp}
	if _, direct := s.outbound.(*tcpDirectTransport); direct {
		eps = append(eps, s.limits.endpointFor(targetConn.RemoteAddr()))
		// Trade the requester-only hold for one covering both ends, so a
		// splice whose ends share a class counts once there. Released first:
		// held across the acquire, it would count this splice against itself.
		releaseSplice()
		both, err := s.limits.acquire(kindSplices, eps...)
		if err != nil {
			_ = targetConn.Close()
			return s.replyFailure(ctx, c, err.Error())
		}
		releaseSplice = both
	}

	// Reply {Result:true} (no ProxyMode, no hello -- the requester is the CEDAR
	// connector) while the requester socket still has broker-session crypto, THEN
	// splice the raw sockets (crypto off both sides) and relay opaque bytes.
	if err := s.replySuccess(ctx, c, false); err != nil {
		_ = targetConn.Close()
		return err
	}
	s.log.Info("proxy-connect splice established", "remote", c.RemoteAddr, "target", target,
		"via", s.outbound.describe(), "name", name)
	st := spliceConns(c.Stream.GetConnection(), targetConn, s.limits.bandwidthFor(eps...)...)
	// A relay that only ever logs its start cannot be used to tell a transport
	// failure from an application one. The counterpart carries how much crossed
	// in each direction, how long it lasted, and why it stopped.
	args := append([]any{"remote", c.RemoteAddr, "target", target,
		"via", s.outbound.describe(), "name", name}, st.LogArgs()...)
	if st.OK() {
		s.log.Info("proxy-connect splice closed", args...)
	} else {
		s.log.Warn("proxy-connect splice failed", args...)
	}
	return cedarserver.KeepOpen()
}

// outboundTargetAllowed parses target (a Sinful), enforces the loopback/link-local
// refusal and the allow-list, and returns the "host:port" to dial. Deny-by-
// default: an empty allow-list (or no match) permits nothing.
// It returns the "host:port" to dial and the target's shared-port id, if it
// carries one. The id is NOT part of the authorization decision -- the
// allow-list governs which hosts may be reached, and a shared-port id only
// selects a daemon once there -- but it must survive to the dial, or the
// connection lands on the remote shared-port server addressed to nobody.
func (s *Server) outboundTargetAllowed(target string) (string, string, error) {
	info, err := addresses.ParseSinful(target)
	if err != nil {
		return "", "", fmt.Errorf("bad target sinful %q", target)
	}
	host, port := info.Host, info.Port
	if host == "" || port == "" {
		return "", "", fmt.Errorf("target %q has no host:port", target)
	}

	// Refuse broker-local scopes so a hostile-but-authenticated requester cannot
	// reach broker-local services (SSRF). Checked here by literal IP and by
	// obvious loopback hostnames, and again on the resolved address at dial time
	// (RefuseLocalAddresses).
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return "", "", fmt.Errorf("target %q is loopback/link-local (refused)", host)
		}
	} else if strings.EqualFold(host, "localhost") {
		return "", "", fmt.Errorf("target %q is loopback (refused)", host)
	}

	if !s.matchAllowlist(host) {
		return "", "", fmt.Errorf("target host %q not permitted by CCB_OUTBOUND_TARGET_ALLOWLIST", host)
	}
	return net.JoinHostPort(host, port), info.SharedPortID, nil
}

// matchAllowlist reports whether host matches any allow-list entry. An entry is a
// CIDR ("10.0.0.0/8"), a glob ("*.example.com", "192.168.*"), or an exact
// host/IP literal (case-insensitive). An empty list (all entries blank) permits
// all targets except the loopback/link-local ones already refused by the caller --
// set a narrower list to restrict the outbound proxy to a specific target set.
func (s *Server) matchAllowlist(host string) bool {
	ip := net.ParseIP(host)
	hasEntry := false
	for _, pat := range s.cfg.OutboundTargetAllowlist {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		hasEntry = true
		if _, cidr, err := net.ParseCIDR(pat); err == nil {
			if ip != nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if strings.ContainsAny(pat, "*?[") {
			if ok, _ := filepath.Match(strings.ToLower(pat), strings.ToLower(host)); ok {
				return true
			}
			continue
		}
		if strings.EqualFold(pat, host) {
			return true
		}
	}
	// No non-blank entries configured: permit all (loopback/link-local already
	// refused by the caller). A configured-but-unmatched host is denied.
	return !hasEntry
}

// RefuseLocalAddresses is a Config.DialControl that refuses loopback,
// link-local and unspecified destinations, judged by the resolved IP, so a
// remote party cannot point the broker at its own host's services.
func RefuseLocalAddresses(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ccbserver: bad dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ccbserver: dial address %q is not an IP", address)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("ccbserver: refusing to dial local address %s", host)
	}
	return nil
}

// chainDialControl returns a dial control that runs each non-nil control in
// turn, failing on the first error.
func chainDialControl(controls ...func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		for _, control := range controls {
			if control == nil {
				continue
			}
			if err := control(network, address, c); err != nil {
				return err
			}
		}
		return nil
	}
}
