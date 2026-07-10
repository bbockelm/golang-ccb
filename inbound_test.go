package ccbserver

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
)

// startInsideTunnelCCB starts an "inside" CCB registered upstream with
// upstreamAddr (the outside CCB), so local registrants get nested contacts.
func startInsideTunnelCCB(t *testing.T, upstreamAddr string) (addr string, srv *Server, cancel func()) {
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
			BrokerAddr:        upstreamAddr,
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

// startRegisteredCedarEP registers a DC_NOP CEDAR server with brokerAddr (the
// inside CCB) and returns its advertised contact (which nests when the broker is
// an inside CCB).
func startRegisteredCedarEP(t *testing.T, brokerAddr string, served chan<- struct{}) (contact string, cancel func()) {
	t.Helper()
	srv := cedarserver.New(plaintextSec())
	srv.Handle(commands.DC_NOP, func(_ context.Context, _ *cedarserver.Conn) error {
		select {
		case served <- struct{}{}:
		default:
		}
		return nil
	})
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        brokerAddr,
		Security:          plaintextSec(),
		Name:              "tunneled-ep",
		HeartbeatInterval: 30 * time.Second,
		Handler:           func(conn net.Conn) { _ = srv.ServeConn(context.Background(), conn) },
	})
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = lis.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if contact = lis.Contact(); contact != "" {
			return contact, c
		}
		time.Sleep(10 * time.Millisecond)
	}
	c()
	t.Fatal("EP did not register with the inside CCB in time")
	return "", c
}

// endToEndDCNop runs a CEDAR DC_NOP client handshake to the target over conn.
func endToEndDCNop(ctx context.Context, conn net.Conn, peer string) error {
	s := stream.NewStream(conn)
	s.SetPeerAddr(peer)
	cfg := *plaintextSec()
	cfg.Command = commands.DC_NOP
	auth := security.NewAuthenticator(&cfg, s)
	_, err := auth.ClientHandshake(ctx)
	return err
}

// TestInboundTunnel2CCB is the Stage-D inbound unit (§4.4): a client reaches a
// tunneled EP through a NESTED contact -- outside CCB -> inside CCB -> EP -- via
// recursive streaming proxy. It asserts the EP advertises a nested contact and
// that an end-to-end CEDAR DC_NOP dispatches through both splices.
func TestInboundTunnel2CCB(t *testing.T) {
	outsideAddr, stopOut := startTestServer(t)
	defer stopOut()

	insideAddr, insideSrv, stopIn := startInsideTunnelCCB(t, outsideAddr)
	defer stopIn()

	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rcancel()
	if err := insideSrv.WaitTunnelReady(rctx); err != nil {
		t.Fatalf("inside CCB never registered upstream: %v", err)
	}

	served := make(chan struct{}, 1)
	epContact, stopEP := startRegisteredCedarEP(t, insideAddr, served)
	defer stopEP()

	if strings.Count(epContact, "#") < 2 {
		t.Fatalf("EP contact %q is not nested (want <outside>#<inside>#<ep>)", epContact)
	}
	t.Logf("tunnel_contact=%s  ep_nested_contact=%s", insideSrv.TunnelContact(), epContact)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, contactsFor(t, epContact), ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "tunneled-ep",
		Timeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial nested contact %q: %v", epContact, err)
	}
	defer func() { _ = conn.Close() }()

	if err := endToEndDCNop(ctx, conn, epContact); err != nil {
		t.Fatalf("end-to-end DC_NOP through the 2-CCB tunnel: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("EP DC_NOP did not dispatch through the inbound tunnel")
	}
}

// TestInboundTunnel3CCB extends the inbound tunnel to three brokers: outside ->
// middle -> inside -> EP. The EP's contact nests three deep and the recursive
// chain-follow drives three streaming hops. Confirms the recursion generalizes.
func TestInboundTunnel3CCB(t *testing.T) {
	outsideAddr, stopOut := startTestServer(t)
	defer stopOut()

	// middle registers upstream with outside; it must be tunnel-ready before the
	// inside CCB registers with it (so the inside's contact nests through middle).
	middleAddr, middleSrv, stopMid := startInsideTunnelCCB(t, outsideAddr)
	defer stopMid()
	waitReady(t, middleSrv, "middle")

	insideAddr, insideSrv, stopIn := startInsideTunnelCCB(t, middleAddr)
	defer stopIn()
	waitReady(t, insideSrv, "inside")

	served := make(chan struct{}, 1)
	epContact, stopEP := startRegisteredCedarEP(t, insideAddr, served)
	defer stopEP()

	if strings.Count(epContact, "#") < 3 {
		t.Fatalf("EP contact %q is not 3-deep nested (want <outside>#a#b#c)", epContact)
	}
	t.Logf("ep_nested_contact=%s", epContact)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, contactsFor(t, epContact), ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "tunneled-ep-3",
		Timeout:    12 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial 3-deep nested contact %q: %v", epContact, err)
	}
	defer func() { _ = conn.Close() }()

	if err := endToEndDCNop(ctx, conn, epContact); err != nil {
		t.Fatalf("end-to-end DC_NOP through the 3-CCB tunnel: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("EP DC_NOP did not dispatch through the 3-CCB tunnel")
	}
}

func waitReady(t *testing.T, srv *Server, which string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.WaitTunnelReady(ctx); err != nil {
		t.Fatalf("%s CCB never registered upstream: %v", which, err)
	}
}

// TestGetTunnelAddress verifies the CCB_GET_TUNNEL_ADDRESS command (§4.5): an
// inside CCB returns its derived tunnel address; a non-inside CCB does not
// register the command, so the query fails.
func TestGetTunnelAddress(t *testing.T) {
	outsideAddr, stopOut := startTestServer(t)
	defer stopOut()
	insideAddr, insideSrv, stopIn := startInsideTunnelCCB(t, outsideAddr)
	defer stopIn()
	waitReady(t, insideSrv, "inside")

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	got, err := ccb.GetTunnelAddress(ctx, insideAddr, plaintextSec(), "MASTER")
	if err != nil {
		t.Fatalf("GetTunnelAddress: %v", err)
	}
	if want := insideSrv.TunnelContact(); got != want || got == "" {
		t.Errorf("tunnel address = %q, want %q", got, want)
	}

	// The outside CCB is not an inside CCB, so it doesn't register the command.
	if _, err := ccb.GetTunnelAddress(ctx, outsideAddr, plaintextSec(), "MASTER"); err == nil {
		t.Error("expected GetTunnelAddress to fail against a non-inside CCB")
	}
}

// TestTunnelReadyFile verifies an inside CCB writes its derived tunnel contact to
// the configured readiness file once upstream registration completes (the Model-1
// barrier a master waits on).
func TestTunnelReadyFile(t *testing.T) {
	outsideAddr, stopOut := startTestServer(t)
	defer stopOut()

	readyFile := filepath.Join(t.TempDir(), "ccb_tunnel_ready")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		PublicAddress:  ln.Addr().String(),
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		Upstream: &UpstreamConfig{
			BrokerAddr:        outsideAddr,
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
			ReadyFile:         readyFile,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	rctx, rc := context.WithTimeout(context.Background(), 5*time.Second)
	defer rc()
	if err := srv.WaitTunnelReady(rctx); err != nil {
		t.Fatalf("inside CCB never registered upstream: %v", err)
	}

	data, err := os.ReadFile(readyFile)
	if err != nil {
		t.Fatalf("tunnel ready file not written: %v", err)
	}
	got := strings.TrimSpace(string(data))
	if want := srv.TunnelContact(); got != want || got == "" {
		t.Errorf("ready file = %q, want tunnel contact %q", got, want)
	}
}

// TestInboundTunnelTree verifies multi-hop routing correctness in a TREE (not a
// chain): one outside CCB fans out to two inside CCBs, each with its own EP, and
// two clients concurrently reach their respective EPs. Because each inside CCB
// numbers its first EP as id 1, a mis-fan-out at the outside CCB (routing branch
// A's request to inside B) would land on the WRONG EP -- so this catches
// cross-talk, not just a generic failure.
func TestInboundTunnelTree(t *testing.T) {
	outsideAddr, stopOut := startTestServer(t)
	defer stopOut()

	insideA, srvA, stopA := startInsideTunnelCCB(t, outsideAddr)
	defer stopA()
	insideB, srvB, stopB := startInsideTunnelCCB(t, outsideAddr)
	defer stopB()
	waitReady(t, srvA, "insideA")
	waitReady(t, srvB, "insideB")
	if srvA.TunnelContact() == srvB.TunnelContact() {
		t.Fatalf("inside CCBs share tunnel contact %q; outside CCB gave non-distinct ids", srvA.TunnelContact())
	}

	servedA := make(chan struct{}, 2)
	servedB := make(chan struct{}, 2)
	epA, stopEPA := startRegisteredCedarEP(t, insideA, servedA)
	defer stopEPA()
	epB, stopEPB := startRegisteredCedarEP(t, insideB, servedB)
	defer stopEPB()

	// Each EP's contact must nest through its own inside CCB (distinct branches).
	if !strings.HasPrefix(epA, srvA.TunnelContact()+"#") {
		t.Errorf("EP_A contact %q does not nest through inside A %q", epA, srvA.TunnelContact())
	}
	if !strings.HasPrefix(epB, srvB.TunnelContact()+"#") {
		t.Errorf("EP_B contact %q does not nest through inside B %q", epB, srvB.TunnelContact())
	}
	t.Logf("branch A: %s -> %s", srvA.TunnelContact(), epA)
	t.Logf("branch B: %s -> %s", srvB.TunnelContact(), epB)

	reach := func(contact string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		conn, err := ccb.Dial(ctx, contactsFor(t, contact), ccb.DialOptions{
			Security: plaintextSec(),
			Timeout:  10 * time.Second,
		})
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		return endToEndDCNop(ctx, conn, contact)
	}

	// Two clients, one per branch, concurrently.
	var wg sync.WaitGroup
	var errA, errB error
	wg.Add(2)
	go func() { defer wg.Done(); errA = reach(epA) }()
	go func() { defer wg.Done(); errB = reach(epB) }()
	wg.Wait()
	if errA != nil {
		t.Fatalf("client A -> EP_A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("client B -> EP_B: %v", errB)
	}

	// Correct routing: EP_A saw its client and EP_B saw its client (if branch A's
	// request had been mis-fanned to inside B it would have hit EP_B, leaving
	// servedA empty).
	select {
	case <-servedA:
	case <-time.After(3 * time.Second):
		t.Fatal("EP_A was not reached: fan-out to branch A failed (possible cross-talk to branch B)")
	}
	select {
	case <-servedB:
	case <-time.After(3 * time.Second):
		t.Fatal("EP_B was not reached: fan-out to branch B failed")
	}
}
