package ccbserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
	"github.com/htcondor/golang-htcondor/authz"
)

// nonLoopbackIPv4 returns a routable (global-unicast, non-loopback, non-link-local)
// IPv4 address of this host, or skips the test. The outbound proxy deliberately
// refuses loopback/link-local targets (SSRF guard), so the happy-path target must
// bind to a real address.
func nonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot list interfaces: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.IsGlobalUnicast() {
			return ip.String()
		}
	}
	t.Skip("no non-loopback IPv4 address available for an outbound-proxy target")
	return ""
}

// startOutboundBroker starts a CCB broker with the outbound proxy enabled and the
// given target allow-list, capturing its logs.
func startOutboundBroker(t *testing.T, allowlist []string) (addr string, rec *logCatcher, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	rec = &logCatcher{}
	srv, err := New(Config{
		PublicAddress:           addr,
		Security:                plaintextSec(),
		RequestTimeout:          5 * time.Second,
		OutboundProxy:           true,
		OutboundTargetAllowlist: allowlist,
		Logger:                  slog.New(rec),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return addr, rec, c
}

// startCedarDialTarget is a plain TCP listener (the broker dials it directly)
// whose accepted sockets are served by a real CEDAR command server handling
// DC_NOP. A dispatched DC_NOP proves the end-to-end CEDAR handshake ran through
// the broker's byte splice.
func startCedarDialTarget(t *testing.T, listenIP string, served chan<- struct{}) (addr string, cancel func()) {
	t.Helper()
	srv := cedarserver.New(plaintextSec())
	srv.Handle(commands.DC_NOP, func(_ context.Context, _ *cedarserver.Conn) error {
		select {
		case served <- struct{}{}:
		default:
		}
		// KeepOpen, not nil. Returning nil lets ServeConn close the socket in
		// the same breath as its reply, and on macOS closing a socket with
		// unread data discards the send buffer -- so the client sees EOF
		// instead of the response it was given. That is the long-standing
		// flake in this suite: it needs load to lose the race, so it bites in
		// a full run and never in isolation.
		return cedarserver.KeepOpen()
	})
	ln, err := net.Listen("tcp", net.JoinHostPort(listenIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.ServeConn(ctx, conn) }()
		}
	}()
	return ln.Addr().String(), func() { c(); _ = ln.Close() }
}

// outboundDCNop runs the requester side of an outbound tunnel: OutboundConnect to
// the broker for target, then a full end-to-end CEDAR DC_NOP client handshake to
// the real target over the returned (raw, relayed) conn.
func outboundDCNop(ctx context.Context, brokerAddr, target string) error {
	conn, err := ccb.OutboundConnect(ctx, brokerAddr, target, ccb.OutboundOptions{
		Security: plaintextSec(),
		Name:     "outbound-test",
		Timeout:  8 * time.Second,
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// Fresh stream over the relayed conn (resets state, drops broker-session
	// crypto); run the end-to-end handshake as the CEDAR connector.
	s := stream.NewStream(conn)
	s.SetPeerAddr(target)
	cfg := *plaintextSec()
	cfg.Command = commands.DC_NOP
	auth := security.NewAuthenticator(&cfg, s)
	if _, err := auth.ClientHandshake(ctx); err != nil {
		return err
	}
	return nil
}

// TestOutboundProxyStageA is the Stage-A differential-testable unit: requester ->
// CCB (outbound proxy) -> a plain CEDAR listener. It asserts the splice carries an
// end-to-end CEDAR round trip (the target's DC_NOP dispatches) and that the broker
// itself logged the splice -- never inferred from configuration.
func TestOutboundProxyStageA(t *testing.T) {
	targetIP := nonLoopbackIPv4(t)

	served := make(chan struct{}, 1)
	targetAddr, stopTgt := startCedarDialTarget(t, targetIP, served)
	defer stopTgt()

	// Allow the target's host (its /32).
	brokerAddr, rec, stopSrv := startOutboundBroker(t, []string{targetIP + "/32"})
	defer stopSrv()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := outboundDCNop(ctx, brokerAddr, "<"+targetAddr+">"); err != nil {
		t.Fatalf("outbound DC_NOP through broker: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("target DC_NOP handler did not run; command did not dispatch through the outbound relay")
	}
	if !rec.saw("proxy-connect splice established") {
		t.Fatal("broker did not log an outbound proxy splice")
	}
}

// startInsideBroker starts an "inside" CCB whose outbound proxy forwards to
// nextHop (a next-hop CCB) instead of dialing directly.
func startInsideBroker(t *testing.T, nextHop string) (addr string, rec *logCatcher, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	rec = &logCatcher{}
	srv, err := New(Config{
		PublicAddress:           addr,
		Security:                plaintextSec(),
		RequestTimeout:          5 * time.Second,
		OutboundProxy:           true,
		OutboundNextHop:         nextHop,
		OutboundNextHopSecurity: plaintextSec(),
		Logger:                  slog.New(rec),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return addr, rec, c
}

// TestOutboundProxyTwoCCB is the Stage-C differential unit (§4.3, §11.2): EP ->
// inside CCB -> outside CCB -> target. The inside CCB forwards the request one hop
// (CCB_PROXY_CONNECT to the outside CCB, reusing the requester client); the
// outside CCB dials the target and enforces the allow-list. Success is verified
// end-to-end (the target's DC_NOP dispatches through BOTH splices) and from both
// brokers' logs.
func TestOutboundProxyTwoCCB(t *testing.T) {
	targetIP := nonLoopbackIPv4(t)

	served := make(chan struct{}, 1)
	targetAddr, stopTgt := startCedarDialTarget(t, targetIP, served)
	defer stopTgt()

	// Outside (exit) CCB: dials directly, enforces the allow-list.
	outsideAddr, outsideRec, stopOut := startOutboundBroker(t, []string{targetIP + "/32"})
	defer stopOut()

	// Inside CCB: forwards to the outside CCB (no local allow-list -- egress is the
	// exit's job).
	insideAddr, insideRec, stopIn := startInsideBroker(t, outsideAddr)
	defer stopIn()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	if err := outboundDCNop(ctx, insideAddr, "<"+targetAddr+">"); err != nil {
		t.Fatalf("outbound DC_NOP through two CCBs: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("target DC_NOP did not run; command did not dispatch through the two-CCB tunnel")
	}
	if !insideRec.saw("proxy-connect splice established") {
		t.Fatal("inside CCB did not log a splice")
	}
	if !outsideRec.saw("proxy-connect splice established") {
		t.Fatal("outside CCB did not log a splice")
	}
}

// TestOutboundProxyTargetNotAllowed verifies that a configured allow-list refuses a
// target that does not match any entry (before any dial). (An *empty* allow-list
// permits all non-loopback targets -- see the module doc; that is exercised by the
// success-path tests, which pass no allow-list.)
func TestOutboundProxyTargetNotAllowed(t *testing.T) {
	targetIP := nonLoopbackIPv4(t)
	served := make(chan struct{}, 1)
	targetAddr, stopTgt := startCedarDialTarget(t, targetIP, served)
	defer stopTgt()

	// A non-empty allow-list naming only a reserved TEST-NET range that cannot
	// contain the real target IP => the target is not permitted.
	brokerAddr, _, stopSrv := startOutboundBroker(t, []string{"192.0.2.0/24"})
	defer stopSrv()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := outboundDCNop(ctx, brokerAddr, "<"+targetAddr+">"); err == nil {
		t.Fatal("expected refusal for a target not in the allow-list, got success")
	}
	select {
	case <-served:
		t.Fatal("target was dialed despite not being allow-listed")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestOutboundProxyRefusesLoopback verifies a loopback target is refused even when
// explicitly allow-listed (SSRF guard: no reaching broker-local services).
func TestOutboundProxyRefusesLoopback(t *testing.T) {
	served := make(chan struct{}, 1)
	targetAddr, stopTgt := startCedarDialTarget(t, "127.0.0.1", served)
	defer stopTgt()

	brokerAddr, _, stopSrv := startOutboundBroker(t, []string{"127.0.0.1", "0.0.0.0/0"})
	defer stopSrv()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := outboundDCNop(ctx, brokerAddr, "<"+targetAddr+">"); err == nil {
		t.Fatal("expected loopback target to be refused, got success")
	}
	select {
	case <-served:
		t.Fatal("loopback target was dialed")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestOutboundProxyRefusesNameResolvingToLoopback: a target named by a hostname
// passes the literal-address check, so the refusal must come from the resolved
// address. "localhost." resolves to loopback but is not the literal
// "localhost".
func TestOutboundProxyRefusesNameResolvingToLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var accepts atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = c.Close()
		}
	}()
	if addrs, err := net.LookupHost("localhost."); err != nil || len(addrs) == 0 {
		t.Skipf("localhost. does not resolve: %v", err)
	}

	srv, err := New(Config{
		PublicAddress:  "127.0.0.1:1",
		Security:       plaintextSec(),
		RequestTimeout: 2 * time.Second,
		OutboundProxy:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	conn, err := srv.outbound.connect(context.Background(), "<localhost.:"+port+">", 1)
	if err == nil {
		_ = conn.Close()
		t.Fatal("target resolving to loopback was dialed")
	}
	time.Sleep(100 * time.Millisecond)
	if n := accepts.Load(); n != 0 {
		t.Errorf("loopback listener accepted %d connections", n)
	}
}

// TestRefuseLocalAddresses checks the dial policy on resolved addresses.
func TestRefuseLocalAddresses(t *testing.T) {
	for addr, refuse := range map[string]bool{
		"127.0.0.1:9618":     true,
		"[::1]:9618":         true,
		"169.254.169.254:80": true,
		"[fe80::1]:80":       true,
		"0.0.0.0:9618":       true,
		"192.0.2.10:9618":    false,
		"[2001:db8::1]:9618": false,
	} {
		if err := RefuseLocalAddresses("tcp", addr, nil); (err != nil) != refuse {
			t.Errorf("RefuseLocalAddresses(%s) = %v, want refused=%v", addr, err, refuse)
		}
	}
}

// TestOutboundProxyUnauthorized verifies the DAEMON authorization gate: a
// requester whose IP is not permitted at DAEMON is refused (an outbound proxy for
// anyone is an open-relay/SSRF risk, so it must never run at an open level).
func TestOutboundProxyUnauthorized(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	// DAEMON restricted to a subnet that excludes loopback, so the 127.0.0.1
	// requester is authenticated but not authorized.
	policy, err := authz.NewPolicy(testCfg{"ALLOW_DAEMON": "10.0.0.0/8"}, "CCB")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		PublicAddress:           addr,
		Security:                plaintextSec(),
		Authorizer:              policy.Authorize,
		OutboundProxy:           true,
		OutboundTargetAllowlist: []string{"10.0.0.0/8"},
		RequestTimeout:          5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	dctx, dcancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer dcancel()
	if _, err := ccb.OutboundConnect(dctx, addr, "<10.1.2.3:9618>", ccb.OutboundOptions{
		Security: plaintextSec(),
		Timeout:  5 * time.Second,
	}); err == nil {
		t.Fatal("expected an unauthorized requester to be refused, got success")
	}
}

// TestOutboundProxyNextHopConfig verifies the inside-CCB config guards: a next hop
// requires a security config, and must not point at this broker (self-loop).
func TestOutboundProxyNextHopConfig(t *testing.T) {
	base := Config{
		PublicAddress: "1.2.3.4:9618",
		Security:      plaintextSec(),
		OutboundProxy: true,
	}

	cfg := base
	cfg.OutboundNextHop = "5.6.7.8:9618"
	if _, err := New(cfg); err == nil {
		t.Error("expected error when OutboundNextHopSecurity is missing")
	}

	cfg = base
	cfg.OutboundNextHop = "1.2.3.4:9618" // == PublicAddress
	cfg.OutboundNextHopSecurity = plaintextSec()
	if _, err := New(cfg); err == nil {
		t.Error("expected a routing-loop error when next hop points at this broker")
	}
}

// TestOutboundProxyDisabled verifies the handler is opt-in: with OutboundProxy off
// the broker has no command-82 handler, so an outbound connect fails cleanly.
func TestOutboundProxyDisabled(t *testing.T) {
	brokerAddr, stopSrv := startTestServer(t) // no OutboundProxy
	defer stopSrv()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err := ccb.OutboundConnect(ctx, brokerAddr, "<10.1.2.3:9618>", ccb.OutboundOptions{
		Security: plaintextSec(),
		Timeout:  5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected outbound connect to fail against a broker without the outbound proxy")
	}
}

// A target behind shared port must be reached through the SHARED_PORT_CONNECT
// handoff, not by a bare TCP connect. Essentially every modern HTCondor daemon
// advertises a sock= -- a schedd's sinful is
// "<host:9618?...&sock=schedd_7891_25eb>" -- and dropping it lands the
// connection on the remote condor_shared_port addressed to nobody, which
// closes it without a reply. See issue #39.
//
// The shared-port server must be off loopback, because the proxy refuses
// loopback targets; the daemon behind it need not be, since only the
// shared-port server dials it.
func TestOutboundProxyReachesTargetBehindSharedPort(t *testing.T) {
	targetIP := nonLoopbackIPv4(t)

	served := make(chan struct{}, 1)
	backendAddr, stopBackend := startCedarDialTarget(t, "127.0.0.1", served)
	defer stopBackend()

	const sock = "schedd_7891_25eb"
	sp := startFwdSharedPortServerOn(t, targetIP, map[string]string{sock: backendAddr})
	defer sp.Close()

	brokerAddr, rec, stopSrv := startOutboundBroker(t, []string{targetIP + "/32"})
	defer stopSrv()

	target := fmt.Sprintf("<%s?sock=%s>", sp.addr(), sock)
	if err := outboundDCNopRetrying(t, brokerAddr, target); err != nil {
		t.Fatalf("outbound DC_NOP to a shared-port target: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon behind shared port never saw the command; the sock= was dropped")
	}
	if !rec.saw("proxy-connect splice established") {
		t.Fatal("broker did not log an outbound proxy splice")
	}
}

// The allow-list governs hosts; a shared-port id only selects a daemon once
// there. A target the list does not permit must still be refused, sock= or no.
func TestOutboundProxySharedPortTargetStillNeedsAllowlist(t *testing.T) {
	targetIP := nonLoopbackIPv4(t)

	served := make(chan struct{}, 1)
	backendAddr, stopBackend := startCedarDialTarget(t, "127.0.0.1", served)
	defer stopBackend()

	const sock = "schedd_7891_25eb"
	sp := startFwdSharedPortServerOn(t, targetIP, map[string]string{sock: backendAddr})
	defer sp.Close()

	brokerAddr, _, stopSrv := startOutboundBroker(t, []string{"192.0.2.1/32"})
	defer stopSrv()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target := fmt.Sprintf("<%s?sock=%s>", sp.addr(), sock)
	if err := outboundDCNop(ctx, brokerAddr, target); err == nil {
		t.Fatal("a shared-port target outside the allow-list was reached")
	}
	select {
	case <-served:
		t.Fatal("the refused target was dialed anyway")
	case <-time.After(time.Second):
	}
}

// outboundTargetAllowed must hand the shared-port id back rather than fold it
// into the dial address or drop it.
func TestOutboundTargetAllowedKeepsSharedPortID(t *testing.T) {
	s := &Server{cfg: Config{OutboundTargetAllowlist: []string{"*"}}}
	for _, tc := range []struct {
		name, target, wantAddr, wantSock string
	}{
		{"schedd behind shared port",
			"<128.105.68.112:9618?addrs=128.105.68.112-9618&alias=ap2001.chtc.wisc.edu&noUDP&sock=schedd_7891_25eb>",
			"128.105.68.112:9618", "schedd_7891_25eb"},
		{"collector without one",
			"<128.105.68.172:9618?addrs=128.105.68.172-9618&alias=cm.chtc.wisc.edu&noUDP>",
			"128.105.68.172:9618", ""},
		{"bare host:port", "192.0.2.5:9618", "192.0.2.5:9618", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, sock, err := s.outboundTargetAllowed(tc.target)
			if err != nil {
				t.Fatalf("outboundTargetAllowed(%q): %v", tc.target, err)
			}
			if addr != tc.wantAddr {
				t.Errorf("dial address = %q, want %q", addr, tc.wantAddr)
			}
			if sock != tc.wantSock {
				t.Errorf("shared-port id = %q, want %q", sock, tc.wantSock)
			}
		})
	}
}

// outboundDCNopRetrying runs an outbound proxy connection, retrying a failed
// attempt with a fresh deadline.
//
// Every test here that needs a non-loopback target -- the outbound proxy
// refuses loopback, so they all do -- is intermittently unreliable on a host
// whose non-loopback address belongs to a VPN or overlay interface: a
// connection to the host's own address stalls or resets for no reason the test
// can see. Observed on this suite as TestOutboundProxyTwoCCB failing in three
// of four full-suite runs while everything around it passed.
//
// The retry does not weaken what the test proves. Without the shared-port
// handoff the remote shared-port server closes every connection that does not
// begin with SHARED_PORT_CONNECT, so all three attempts fail, every run --
// which is exactly what the pre-fix check confirms.
func outboundDCNopRetrying(t *testing.T, brokerAddr, target string) error {
	t.Helper()
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = outboundDCNop(ctx, brokerAddr, target)
		cancel()
		if err == nil {
			if attempt > 1 {
				t.Logf("the outbound connection succeeded on attempt %d", attempt)
			}
			return nil
		}
		t.Logf("attempt %d failed: %v", attempt, err)
	}
	return fmt.Errorf("three attempts failed, last: %w", err)
}
