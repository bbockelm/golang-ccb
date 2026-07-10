package ccbserver

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/authz"
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
		return nil
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

// TestOutboundProxyTargetNotAllowed verifies deny-by-default: a target that is not
// in the allow-list is refused (before any dial).
func TestOutboundProxyTargetNotAllowed(t *testing.T) {
	targetIP := nonLoopbackIPv4(t)
	served := make(chan struct{}, 1)
	targetAddr, stopTgt := startCedarDialTarget(t, targetIP, served)
	defer stopTgt()

	// Empty allow-list => nothing permitted.
	brokerAddr, _, stopSrv := startOutboundBroker(t, nil)
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
		Authz:                   policy,
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
