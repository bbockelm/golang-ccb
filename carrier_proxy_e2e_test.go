package ccbserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/golang-ccb/internal/proxytest"
	"github.com/bbockelm/golang-ccb/transport/wscarrier"
)

// These are the fast tier of the HPC-site case (docs/E2E_SQUID_WS.md): a
// restricted node whose only way out is an HTTP proxy, reaching its outside CCB
// over a single token-authenticated wss:// carrier. They prove the protocol --
// that both tunnel directions survive a CONNECT proxy in the path, and that the
// node's whole CCB footprint is ONE proxied connection. They cannot prove the
// deployment: a real squid's port and destination ACLs, idle timeouts, and TLS
// interception need the container tier.
//
// A proxied carrier must be wss:// (a proxy is traversed with CONNECT, which is
// issued only for TLS endpoints), so these tests all carry real TLS.

const carrierToken = "pilot-token"

func carrierTokenVerifier(_ context.Context, tok string) (string, error) {
	if tok == carrierToken {
		return "pilot@site", nil
	}
	return "", fmt.Errorf("bad token")
}

// wssCarrier builds a wss:// carrier endpoint on a free port with matching TLS.
func wssCarrier(t *testing.T) (url string, serverTLS, clientTLS *tls.Config) {
	t.Helper()
	serverTLS, clientTLS = proxytest.SelfSignedTLS(t)
	return fmt.Sprintf("wss://127.0.0.1:%d/ccb/tunnel", freePort(t)), serverTLS, clientTLS
}

// startOutsideWSSCCB starts an outside CCB facing the pool over TCP and
// accepting inside CCBs over a token-authenticated wss:// carrier. With
// allowlist non-empty it is also the exit for outbound proxy-connects.
func startOutsideWSSCCB(t *testing.T, carrierURL string, serverTLS *tls.Config, allowlist []string) (tcpAddr string, rec *logCatcher, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr = ln.Addr().String()
	rec = &logCatcher{}
	srv, err := New(Config{
		PublicAddress:           tcpAddr,
		Security:                plaintextSec(),
		RequestTimeout:          5 * time.Second,
		OutboundProxy:           len(allowlist) > 0,
		OutboundTargetAllowlist: allowlist,
		CarrierListen:           carrierURL,
		CarrierTLS:              serverTLS,
		CarrierTokenVerify:      carrierTokenVerifier,
		Logger:                  slog.New(rec),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return tcpAddr, rec, c
}

// insideWSSConfig is the inside CCB of a restricted node: it serves local EPs
// over TCP and reaches its outside CCB only through proxy.
func insideWSSConfig(addr, carrierURL string, clientTLS *tls.Config, proxy *proxytest.Proxy, outbound bool) Config {
	cfg := Config{
		PublicAddress:  addr,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		Upstream: &UpstreamConfig{
			BrokerAddr:        carrierURL,
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
		CarrierToken:     carrierToken,
		CarrierClientTLS: clientTLS,
		CarrierProxy:     proxy.ProxyFunc(),
	}
	if outbound {
		cfg.OutboundProxy = true
		cfg.OutboundNextHop = carrierURL
		cfg.OutboundNextHopSecurity = plaintextSec()
	}
	return cfg
}

// startInsideWSSCCB binds the inside CCB's local port FIRST and configures
// PublicAddress to the address it actually got. That address is what a local EP
// is told to reverse-connect to during a streaming rendezvous, so configuring it
// as ":0" leaves the EP dialing port 0 and the relay times out with nothing
// obviously wrong in either broker's log.
func startInsideWSSCCB(t *testing.T, carrierURL string, clientTLS *tls.Config, proxy *proxytest.Proxy, outbound bool) (addr string, srv *Server, rec *logCatcher, cancel func()) {
	t.Helper()
	return startInsideWSSCCBConfig(t, insideWSSConfig("", carrierURL, clientTLS, proxy, outbound))
}

// startInsideWSSCCBConfig starts an inside CCB from a prepared Config, so a test
// can set a field the helper above does not take. PublicAddress is always
// replaced with the address actually bound: a local EP is told to reverse-connect
// to it during a streaming rendezvous, so a placeholder there leaves the EP
// dialing nowhere and the relay times out with nothing obviously wrong.
func startInsideWSSCCBConfig(t *testing.T, cfg Config) (addr string, srv *Server, rec *logCatcher, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	rec = &logCatcher{}
	cfg.PublicAddress = addr
	cfg.Logger = slog.New(rec)
	srv, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return addr, srv, rec, c
}

// startLingeringDialTarget is startCedarDialTarget with one difference: its
// DC_NOP handler does not return the instant it is reached.
//
// cedar's server closes a connection as soon as the handler returns. When the
// target is behind two splices, that FIN races the handshake reply still in
// flight back through the relay, and the requester intermittently reads EOF
// instead of the reply -- about one run in three. That race is in the relay's
// teardown, not in the carrier, and it reproduces on main without any carrier
// involved (TestOutboundProxyStageA fails the same way). These tests are about
// whether a proxied carrier relays faithfully, so they use a target that lets
// the reply drain; the teardown race is tracked separately.
func startLingeringDialTarget(t *testing.T, listenIP string, served chan<- struct{}) (addr string, cancel func()) {
	t.Helper()
	srv := cedarserver.New(plaintextSec())
	srv.Handle(commands.DC_NOP, func(ctx context.Context, _ *cedarserver.Conn) error {
		select {
		case served <- struct{}{}:
		default:
		}
		// Hold the connection open long enough for the reply to cross both
		// splices before the close does.
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
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

// TestInboundTunnel2CCBOverWSCarrierViaProxy: a pool client offsite reaches an
// EP on the restricted node, through the outside CCB and down the proxied
// carrier. The CONNECT assertion is the point -- without it, a carrier that
// ignored the proxy and dialed the endpoint directly would pass identically.
func TestInboundTunnel2CCBOverWSCarrierViaProxy(t *testing.T) {
	carrierURL, serverTLS, clientTLS := wssCarrier(t)
	proxy := proxytest.Start(t, nil)

	outsideAddr, _, stopOut := startOutsideWSSCCB(t, carrierURL, serverTLS, nil)
	defer stopOut()

	insideAddr, insideSrv, _, stopIn := startInsideWSSCCB(t, carrierURL, clientTLS, proxy, false)
	defer stopIn()

	rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer rcancel()
	if err := insideSrv.WaitTunnelReady(rctx); err != nil {
		t.Fatalf("inside CCB never registered upstream through the proxy: %v", err)
	}

	// The EP's contact must name the OUTSIDE CCB's public address: that is what
	// makes it reachable from a pool that cannot see the node at all.
	tc := insideSrv.TunnelContact()
	if !strings.HasPrefix(tc, outsideAddr+"#") {
		t.Fatalf("tunnel contact %q does not carry the outside CCB's public address %q", tc, outsideAddr)
	}

	served := make(chan struct{}, 1)
	epContact, stopEP := startRegisteredCedarEP(t, insideAddr, served)
	defer stopEP()
	if strings.Count(epContact, "#") < 2 {
		t.Fatalf("EP contact %q is not nested (want <outside>#<inside>#<ep>)", epContact)
	}
	t.Logf("proxy=%s carrier=%s ep=%s", proxy.URL(), carrierURL, epContact)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, contactsFor(t, epContact), ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "tunneled-ep-ws-proxy",
		Timeout:    15 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial nested contact %q: %v", epContact, err)
	}
	defer func() { _ = conn.Close() }()

	if err := endToEndDCNop(ctx, conn, epContact); err != nil {
		t.Fatalf("end-to-end DC_NOP through the proxied WebSocket tunnel: %v", err)
	}
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("EP DC_NOP did not dispatch through the proxied inbound tunnel")
	}

	assertSingleCONNECT(t, proxy, carrierURL)
}

// TestOutboundProxyTwoCCBOverWSCarrierViaProxy: the direction the EP uses most
// (every collector update) -- EP -> inside CCB -> [wss through the HTTP proxy]
// -> outside CCB -> dial the target. Also the first coverage of the outbound
// chain over the WebSocket carrier at all; it previously existed only for the
// filesystem carrier.
func TestOutboundProxyTwoCCBOverWSCarrierViaProxy(t *testing.T) {
	carrierURL, serverTLS, clientTLS := wssCarrier(t)
	proxy := proxytest.Start(t, nil)
	targetIP := nonLoopbackIPv4(t)

	served := make(chan struct{}, 1)
	targetAddr, stopTgt := startLingeringDialTarget(t, targetIP, served)
	defer stopTgt()

	_, outsideRec, stopOut := startOutsideWSSCCB(t, carrierURL, serverTLS, []string{targetIP + "/32"})
	defer stopOut()

	insideAddr, insideSrv, insideRec, stopIn := startInsideWSSCCB(t, carrierURL, clientTLS, proxy, true)
	defer stopIn()

	rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer rcancel()
	if err := insideSrv.WaitTunnelReady(rctx); err != nil {
		t.Fatalf("inside CCB never registered upstream through the proxy: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := outboundDCNop(ctx, insideAddr, "<"+targetAddr+">"); err != nil {
		t.Fatalf("outbound DC_NOP through two CCBs over the proxied carrier: %v", err)
	}
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("target DC_NOP did not run; the command did not dispatch through the proxied tunnel")
	}
	if !insideRec.saw("proxy-connect splice established") {
		t.Error("inside CCB did not log a splice")
	}
	if !outsideRec.saw("proxy-connect splice established") {
		t.Error("outside (exit) CCB did not log a splice")
	}

	assertSingleCONNECT(t, proxy, carrierURL)
}

// TestCarrierFootprintIsOneConnection is the property a site that throttles live
// socket counts is buying: inbound and outbound traffic, several connections
// each, and the node still holds exactly one proxied TCP connection -- because
// yamux multiplexes every logical connection over the single carrier.
func TestCarrierFootprintIsOneConnection(t *testing.T) {
	carrierURL, serverTLS, clientTLS := wssCarrier(t)
	proxy := proxytest.Start(t, nil)
	targetIP := nonLoopbackIPv4(t)

	served := make(chan struct{}, 4)
	targetAddr, stopTgt := startLingeringDialTarget(t, targetIP, served)
	defer stopTgt()

	_, _, stopOut := startOutsideWSSCCB(t, carrierURL, serverTLS, []string{targetIP + "/32"})
	defer stopOut()

	insideAddr, insideSrv, _, stopIn := startInsideWSSCCB(t, carrierURL, clientTLS, proxy, true)
	defer stopIn()

	rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer rcancel()
	if err := insideSrv.WaitTunnelReady(rctx); err != nil {
		t.Fatalf("inside CCB never registered upstream: %v", err)
	}

	// Several independent outbound connections, each its own CCB_PROXY_CONNECT.
	const rounds = 4
	for i := range rounds {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := outboundDCNop(ctx, insideAddr, "<"+targetAddr+">")
		cancel()
		if err != nil {
			t.Fatalf("outbound round %d: %v", i, err)
		}
	}
	for i := range rounds {
		select {
		case <-served:
		case <-time.After(10 * time.Second):
			t.Fatalf("target served only %d of %d outbound connections", i, rounds)
		}
	}

	assertSingleCONNECT(t, proxy, carrierURL)
}

// assertSingleCONNECT checks the proxy carried the carrier -- and carried all of
// it on one connection.
func assertSingleCONNECT(t *testing.T, proxy *proxytest.Proxy, carrierURL string) {
	t.Helper()
	got := proxy.Connects()
	if len(got) == 0 {
		t.Fatal("the proxy saw no CONNECT: the carrier did not go through it")
	}
	if len(got) != 1 {
		t.Errorf("the proxy saw %d CONNECTs, want 1 for the whole session: %v", len(got), got)
	}
	want := strings.TrimSuffix(strings.TrimPrefix(carrierURL, "wss://"), "/ccb/tunnel")
	if got[0] != want {
		t.Errorf("the proxy CONNECTed to %q, want the carrier endpoint %q", got[0], want)
	}
}

// TestCarrierHealthCheckThroughProxy: the startup check walks every stage,
// including the CEDAR handshake to the broker at the far end -- the stage that
// distinguishes "a WebSocket opened" from "the expected broker answered and our
// credentials agree".
func TestCarrierHealthCheckThroughProxy(t *testing.T) {
	carrierURL, serverTLS, clientTLS := wssCarrier(t)
	proxy := proxytest.Start(t, nil)

	_, _, stopOut := startOutsideWSSCCB(t, carrierURL, serverTLS, nil)
	defer stopOut()

	_, insideSrv, _, stopIn := startInsideWSSCCB(t, carrierURL, clientTLS, proxy, false)
	defer stopIn()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := insideSrv.CheckCarrier(ctx)
	t.Log("\n" + res.String())
	if err := res.Err(); err != nil {
		t.Fatalf("carrier health check failed: %v", err)
	}
	if res.Route != "via "+proxy.URL() {
		t.Errorf("health check Route = %q, want the proxy", res.Route)
	}
	var sawFarBroker bool
	for _, st := range res.Stages {
		if st.Stage == StageFarBroker {
			sawFarBroker = true
			if st.Skipped || st.Err != nil {
				t.Errorf("far-broker stage did not run cleanly: skipped=%v err=%v", st.Skipped, st.Err)
			}
		}
	}
	if !sawFarBroker {
		t.Error("health check report has no far-broker stage")
	}
}

// TestCarrierHealthCheckNamesRefusingProxy: when the site proxy refuses the
// destination, the check must say so instead of reporting a generic dial
// failure, and must not go on to blame the far broker.
func TestCarrierHealthCheckNamesRefusingProxy(t *testing.T) {
	carrierURL, serverTLS, clientTLS := wssCarrier(t)
	proxy := proxytest.Start(t, proxytest.Deny(http.StatusForbidden))

	_, _, stopOut := startOutsideWSSCCB(t, carrierURL, serverTLS, nil)
	defer stopOut()

	_, insideSrv, _, stopIn := startInsideWSSCCB(t, carrierURL, clientTLS, proxy, false)
	defer stopIn()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := insideSrv.CheckCarrier(ctx)
	t.Log("\n" + res.String())
	if res.OK() {
		t.Fatal("health check passed against a proxy that refuses CONNECT")
	}
	err := res.Err()
	if !strings.Contains(err.Error(), string(wscarrier.StageConnect)) {
		t.Errorf("the failure does not name the proxy-connect stage: %v", err)
	}
	if strings.Contains(err.Error(), string(StageFarBroker)) {
		t.Errorf("a transport failure was reported as a far-broker problem: %v", err)
	}
	for _, st := range res.Stages {
		if st.Stage == StageFarBroker {
			t.Error("the far-broker stage ran although the transport never came up")
		}
	}
}

// TestRegisterRefusedUntilTunnelReady: an inside CCB that is not yet tunnel-ready
// must refuse a registration rather than answer with its own private address. A
// registrant that accepted such a contact would advertise an unroutable address
// to the pool permanently -- and over a proxied carrier, where becoming ready
// takes real time, an EP starting alongside the broker hits this race routinely.
func TestRegisterRefusedUntilTunnelReady(t *testing.T) {
	// An upstream that will never answer: the broker stays un-ready forever.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	insideAddr := ln.Addr().String()
	rec := &logCatcher{}
	srv, err := New(Config{
		PublicAddress:  insideAddr,
		Security:       plaintextSec(),
		RequestTimeout: 1 * time.Second, // bounds the wait below
		Upstream: &UpstreamConfig{
			BrokerAddr:        deadAddr,
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
		Logger: slog.New(rec),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	contact, stop := tryRegisterCedarEP(t, insideAddr, 4*time.Second)
	defer stop()
	if contact != "" {
		t.Fatalf("EP was given contact %q by a broker that is not tunnel-ready; "+
			"it would advertise that unroutable address to the pool", contact)
	}
	if !rec.saw("register refused: this inside CCB is not tunnel-ready, so the contact would not nest") {
		t.Error("the inside CCB did not log why it refused the registration")
	}
}

// tryRegisterCedarEP registers an EP with brokerAddr and returns the contact it
// was given, or "" if it never got one within wait. Unlike
// startRegisteredCedarEP it does not fail the test when no contact arrives --
// that is the expected outcome here.
func tryRegisterCedarEP(t *testing.T, brokerAddr string, wait time.Duration) (contact string, cancel func()) {
	t.Helper()
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        brokerAddr,
		Security:          plaintextSec(),
		Name:              "racing-ep",
		HeartbeatInterval: 30 * time.Second,
		Handler:           func(conn net.Conn, _ ccb.InboundMeta) { _ = conn.Close() },
	})
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = lis.Run(ctx) }()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if got := lis.Contact(); got != "" {
			return got, c
		}
		time.Sleep(20 * time.Millisecond)
	}
	return "", c
}
