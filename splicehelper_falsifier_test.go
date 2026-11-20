package ccbserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/golang-ccb/transport/carrier"
	"github.com/bbockelm/golang-ccb/transport/splice"
)

// startCarrierBroker starts a broker with two listeners: the public one that
// clients reach, and a carrier listener that helpers dial. The carrier side is
// a real MuxListener, so each pipe is one yamux session and one carrier.
func startCarrierBroker(t *testing.T) (publicAddr, carrierAddr string, stop func()) {
	t.Helper()
	pub, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	car, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		PublicAddress:  pub.Addr().String(),
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := carrier.NewMuxListener(car, carrier.WithPipeHooks(srv.CarrierHooks()))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, pub) }()
	go func() { _ = srv.Serve(ctx, mux) }()
	return pub.Addr().String(), car.Addr().String(), func() {
		cancel()
		_ = mux.Close()
	}
}

// startSpliceHelper runs the real helper: it dials the broker's carrier port,
// runs yamux over that one connection, and copies each local connection onto
// its own stream. It terminates nothing.
func startSpliceHelper(t *testing.T, carrierAddr string) (addr string, stop func()) {
	t.Helper()
	pipe, err := net.Dial("tcp", carrierAddr)
	if err != nil {
		t.Fatal(err)
	}
	h, err := splice.Start(splice.Config{
		Listen: "127.0.0.1:0",
		Pipe:   pipe,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = h.Serve(ctx) }()
	return h.Addr().String(), func() {
		cancel()
		_ = h.Close()
		<-done
	}
}

// startHelperEP registers a DC_NOP EP through a splice helper. Its only way out
// is the helper: the Dial hook stands in for the cedar change that makes a
// proxy-mode reverse-connect go back to the broker the target registered
// through (docs/SPLICE_HELPER.md 3.2), which is not landed yet.
func startHelperEP(t *testing.T, helperAddr string, served chan<- struct{}) (contact string, stop func()) {
	t.Helper()
	cs := cedarserver.New(plaintextSec())
	cs.Handle(commands.DC_NOP, func(_ context.Context, _ *cedarserver.Conn) error {
		select {
		case served <- struct{}{}:
		default:
		}
		return cedarserver.KeepOpen()
	})
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        helperAddr,
		Security:          plaintextSec(),
		Name:              "helper-ep",
		HeartbeatInterval: 30 * time.Second,
		Handler:           func(conn net.Conn, _ ccb.InboundMeta) { _ = cs.ServeConn(context.Background(), conn) },
		// Stands in for the cedar change (docs/SPLICE_HELPER.md 3.2): a
		// proxy-mode reverse-connect goes back to the broker the target
		// registered through. Landed as cedar CCBProxyMode; this can go once
		// golang-ccb depends on a cedar release that carries it.
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", helperAddr)
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = lis.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if contact = lis.Contact(); contact != "" {
			return contact, cancel
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("EP did not register through the splice helper in time")
	return "", cancel
}

// TestCarrierContactMakesAnOrdinaryClientStream is Option 1 (docs/SPLICE_HELPER.md
// 3.3). A target behind a splice helper can only be reached by proxy, but the
// REQUESTER picks the mode and does so before the broker sees the request --
// from the shape of the contact. So the contact nests one level through the
// carrier's id, and an ordinary client takes the streaming path on its own.
//
// The client here sets no ProxyReturnAddr and is told nothing. That is the
// whole assertion: nothing about it knows a helper exists.
func TestCarrierContactMakesAnOrdinaryClientStream(t *testing.T) {
	publicAddr, carrierAddr, stopBroker := startCarrierBroker(t)
	defer stopBroker()

	helperAddr, stopHelper := startSpliceHelper(t, carrierAddr)
	defer stopHelper()

	served := make(chan struct{}, 1)
	epContact, stopEP := startHelperEP(t, helperAddr, served)
	defer stopEP()

	t.Logf("ep_contact=%s  (public=%s carrier=%s helper=%s)", epContact, publicAddr, carrierAddr, helperAddr)
	if got := strings.Count(epContact, "#"); got != 2 {
		t.Fatalf("contact %q has %d '#'; a carrier-attached target must nest once "+
			"(<public>#P#T) or an ordinary client will take dialStandard", epContact, got)
	}
	if !strings.HasPrefix(epContact, publicAddr) {
		t.Errorf("contact %q should be rooted at the PUBLIC address %q, which is what a client can reach",
			epContact, publicAddr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, contactsFor(t, epContact), ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "helper-ep",
		Timeout:    10 * time.Second,
		// Deliberately absent: ProxyReturnAddr. The contact alone must be
		// enough to put an unmodified client on the streaming path.
	})
	if err != nil {
		t.Fatalf("an ordinary client could not reach a carrier-attached target: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := endToEndDCNop(ctx, conn, epContact); err != nil {
		t.Fatalf("end-to-end DC_NOP through the carrier: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("EP DC_NOP did not dispatch through the collapsed carrier hop")
	}
}

// TestCarrierHopWillNotReachAnotherCarriersTarget guards the collapse: the
// route's head must be a target of the carrier named, or any carrier id would
// serve as a prefix for reaching any target on the broker.
func TestCarrierHopWillNotReachAnotherCarriersTarget(t *testing.T) {
	publicAddr, carrierAddr, stopBroker := startCarrierBroker(t)
	defer stopBroker()
	helperAddr, stopHelper := startSpliceHelper(t, carrierAddr)
	defer stopHelper()

	served := make(chan struct{}, 1)
	epContact, stopEP := startHelperEP(t, helperAddr, served)
	defer stopEP()

	// epContact is "<public>#P#T". Forge "<public>#Q#T" for some carrier id Q
	// that is not P -- here P+1000, which no carrier ever took.
	_, ids, ok := strings.Cut(strings.TrimPrefix(epContact, publicAddr), "#")
	if !ok {
		t.Fatalf("unexpected contact shape %q", epContact)
	}
	pStr, tStr, _ := strings.Cut(ids, "#")
	p, err := strconv.ParseUint(pStr, 10, 64)
	if err != nil {
		t.Fatalf("carrier id in %q: %v", epContact, err)
	}
	forged := publicAddr + "#" + strconv.FormatUint(p+1000, 10) + "#" + tStr
	t.Logf("real=%s forged=%s", epContact, forged)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, contactsFor(t, forged), ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "forged",
		Timeout:    6 * time.Second,
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("a contact naming a carrier that does not own the target was accepted")
	}
	select {
	case <-served:
		t.Fatal("the EP served a connection reached through a carrier it is not on")
	default:
	}
}

// TestOldClientMisparseOfACarrierContactFailsCleanly pins the §4.6
// compatibility rule for carrier contacts. An un-upgraded client splits a
// contact on the FIRST '#' rather than the last, so given "<public>#P#T" it
// asks the broker for CCBID "P#T".
//
// The C++ lenient parse (sscanf "%lu", which stops at '#') would yield P and
// misroute the request to registrant P. A strict parse must reject it. This
// asserts the Go broker is strict, and -- because P now names a carrier rather
// than a registrant -- that a misparse cannot be turned into a reachable
// target by accident.
func TestOldClientMisparseOfACarrierContactFailsCleanly(t *testing.T) {
	publicAddr, carrierAddr, stopBroker := startCarrierBroker(t)
	defer stopBroker()
	helperAddr, stopHelper := startSpliceHelper(t, carrierAddr)
	defer stopHelper()

	served := make(chan struct{}, 1)
	epContact, stopEP := startHelperEP(t, helperAddr, served)
	defer stopEP()

	// What an old client does: split on the first '#'.
	rest := strings.TrimPrefix(epContact, publicAddr+"#")
	if !strings.Contains(rest, "#") {
		t.Fatalf("contact %q did not nest, so there is no misparse to test", epContact)
	}
	t.Logf("contact=%s  old client would send CCBID=%q", epContact, rest)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, []addresses.CCBContact{{
		Raw:        epContact,
		BrokerAddr: publicAddr,
		CCBID:      rest, // "P#T", exactly what the lenient split produces
	}}, ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "old-client",
		Timeout:    6 * time.Second,
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("the broker accepted a CCBID of \"P#T\"; a lenient parse would misroute it")
	}
	t.Logf("refused, as required: %v", err)
	select {
	case <-served:
		t.Fatal("an old client's misparse reached the EP")
	default:
	}
}

// TestV26PeelMisparseResolvesToTheRightTargetOrHangs covers what a current C++
// v26 client actually does with a carrier contact, which is not what an "old"
// client does.
//
// v26 splits a contact on the LAST '#', so given "<public>#P#T" it takes
// ccb_address "<public>#P" and ccbid "T". In HTCondor the broker address
// normally carries sinful params, and split_sin consumes everything up to '>'
// as the params blob, so the trailing "#P" is absorbed into the last param
// value: the address stays valid, points at the entry broker, and the carrier
// hop is silently gone. The client then asks the entry broker for a bare "T".
//
// In a two-BROKER tunnel that is a misroute -- "T" is the INNER broker's id for
// the EP, and the entry broker resolves it against its own unrelated table. In
// this model both ids belong to the same broker, so "T" still names the
// intended target. The request is then refused or stalls because the client is
// in standard mode and a carrier-attached target can only be proxied, but it
// never reaches a DIFFERENT daemon. That difference is the point of this test.
func TestV26PeelMisparseResolvesToTheRightTargetOrHangs(t *testing.T) {
	publicAddr, carrierAddr, stopBroker := startCarrierBroker(t)
	defer stopBroker()
	helperAddr, stopHelper := startSpliceHelper(t, carrierAddr)
	defer stopHelper()

	served := make(chan struct{}, 1)
	epContact, stopEP := startHelperEP(t, helperAddr, served)
	defer stopEP()

	// What v26 extracts: ccbid is the LAST id, and the hop is lost.
	lastHash := strings.LastIndex(epContact, "#")
	bareID := epContact[lastHash+1:]
	t.Logf("contact=%s  v26 would ask %s for bare CCBID %q", epContact, publicAddr, bareID)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, []addresses.CCBContact{{
		Raw:        epContact,
		BrokerAddr: publicAddr,
		CCBID:      bareID,
	}}, ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "v26-style",
		Timeout:    4 * time.Second,
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("a standard-mode request for a carrier-attached target succeeded; it must be proxied")
	}
	t.Logf("refused or stalled, as expected: %v", err)

	// The critical property: whatever happened, no OTHER daemon was reached.
	// Here the EP is the only registrant, so serving at all would mean the
	// standard path had worked -- which it must not, since the EP cannot dial
	// a requester.
	select {
	case <-served:
		t.Fatal("the EP served a standard-mode request; a carrier-attached target must always be proxied")
	default:
	}
}
