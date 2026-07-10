package ccbserver

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
)

// startOutsideCarrierCCB starts an outside CCB that faces the pool over TCP
// (PublicAddress) AND accepts inside CCBs over the filesystem carrier rooted at
// carrierDir. Pool clients reach it over TCP; the inside CCB reaches it over the
// carrier.
func startOutsideCarrierCCB(t *testing.T, carrierDir string) (tcpAddr string, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr = ln.Addr().String()
	srv, err := New(Config{
		PublicAddress:  tcpAddr,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		CarrierListen:  "fs:" + carrierDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return tcpAddr, c
}

// startInsideCarrierCCB starts an inside CCB whose upstream link is the
// filesystem carrier at carrierDir (instead of a TCP broker). It still serves its
// own local EPs over TCP.
func startInsideCarrierCCB(t *testing.T, carrierDir string) (addr string, srv *Server, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	srv, err = New(Config{
		PublicAddress:  addr,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		Upstream: &UpstreamConfig{
			BrokerAddr:        "fs:" + carrierDir,
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return addr, srv, c
}

// TestInboundTunnel2CCBOverFSCarrier is the 2-CCB inbound tunnel (§4.4) with the
// inside<->outside link carried over the FILESYSTEM instead of TCP. It proves the
// carrier is transparent to the relay: upstream registration, inbound request
// forwarding, and the reverse-connect all traverse the fstun/yamux pipe, yet a
// client reaching the nested contact over TCP dispatches an end-to-end CEDAR
// DC_NOP through both CCBs exactly as in the all-TCP case.
func TestInboundTunnel2CCBOverFSCarrier(t *testing.T) {
	dir := t.TempDir()

	outsideAddr, stopOut := startOutsideCarrierCCB(t, dir)
	defer stopOut()

	insideAddr, insideSrv, stopIn := startInsideCarrierCCB(t, dir)
	defer stopIn()

	// Upstream registration completes over the carrier.
	rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer rcancel()
	if err := insideSrv.WaitTunnelReady(rctx); err != nil {
		t.Fatalf("inside CCB never registered upstream over the carrier: %v", err)
	}

	// The tunnel contact must be the OUTSIDE CCB's public TCP address (what pool
	// clients dial), not the carrier path -- the outside CCB stamps its own
	// PublicAddress into the registration reply regardless of how it was reached.
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
	t.Logf("carrier=fs:%s tunnel_contact=%s ep_nested_contact=%s", dir, tc, epContact)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, contactsFor(t, epContact), ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "tunneled-ep-fs",
		Timeout:    12 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial nested contact %q: %v", epContact, err)
	}
	defer func() { _ = conn.Close() }()

	if err := endToEndDCNop(ctx, conn, epContact); err != nil {
		t.Fatalf("end-to-end DC_NOP through the 2-CCB filesystem tunnel: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("EP DC_NOP did not dispatch through the filesystem-carried inbound tunnel")
	}
}

// TestOutboundProxyTwoCCBOverFSCarrier is the Stage-C outbound tunnel (§4.3) with
// the inside<->outside link over the FILESYSTEM carrier: EP -> inside CCB
// --(fs carrier)--> outside CCB -> target. The inside CCB forwards the
// CCB_PROXY_CONNECT over the carrier pipe; the outside (exit) CCB dials the target
// and enforces the allow-list. Verified end-to-end (target DC_NOP dispatches
// through both splices) and from both brokers' logs.
func TestOutboundProxyTwoCCBOverFSCarrier(t *testing.T) {
	dir := t.TempDir()
	targetIP := nonLoopbackIPv4(t)

	served := make(chan struct{}, 1)
	targetAddr, stopTgt := startCedarDialTarget(t, targetIP, served)
	defer stopTgt()

	// Outside (exit) CCB: faces the pool over TCP, accepts the inside CCB over the
	// carrier, dials the target directly, enforces the allow-list.
	outLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	outsideAddr := outLn.Addr().String()
	outsideRec := &logCatcher{}
	outsideSrv, err := New(Config{
		PublicAddress:           outsideAddr,
		Security:                plaintextSec(),
		RequestTimeout:          5 * time.Second,
		OutboundProxy:           true,
		OutboundTargetAllowlist: []string{targetIP + "/32"},
		CarrierListen:           "fs:" + dir,
		Logger:                  slog.New(outsideRec),
	})
	if err != nil {
		t.Fatal(err)
	}
	octx, ocancel := context.WithCancel(context.Background())
	defer ocancel()
	go func() { _ = outsideSrv.Serve(octx, outLn) }()

	// Inside CCB: forwards outbound proxy-connects to the outside CCB over the
	// carrier (OutboundNextHop uses the fs: scheme).
	insideAddr, insideRec, stopIn := startInsideBroker(t, "fs:"+dir)
	defer stopIn()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := outboundDCNop(ctx, insideAddr, "<"+targetAddr+">"); err != nil {
		t.Fatalf("outbound DC_NOP through two CCBs over the carrier: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("target DC_NOP did not run; command did not dispatch through the carrier tunnel")
	}
	if !insideRec.saw("proxy-connect splice established") {
		t.Fatal("inside CCB did not log a splice")
	}
	if !outsideRec.saw("proxy-connect splice established") {
		t.Fatal("outside CCB did not log a splice")
	}
}
