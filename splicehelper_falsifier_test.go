package ccbserver

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	cedarserver "github.com/bbockelm/cedar/server"
)

// startSpliceHelper is the whole proposed helper: a TCP listener on the EP's
// side of the pipe that copies bytes to the outside broker and back. It holds
// no keys, parses nothing, and knows no CCB. Each accepted connection stands in
// for one yamux stream over the carrier -- the multiplexing is not what this
// test is asking about.
func startSpliceHelper(t *testing.T, outsideAddr string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				up, err := net.Dial("tcp", outsideAddr)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				var inner sync.WaitGroup
				inner.Add(2)
				go func() { defer inner.Done(); _, _ = io.Copy(up, c); _ = up.(*net.TCPConn).CloseWrite() }()
				go func() { defer inner.Done(); _, _ = io.Copy(c, up); _ = c.(*net.TCPConn).CloseWrite() }()
				ch := make(chan struct{})
				go func() { inner.Wait(); close(ch) }()
				select {
				case <-ch:
				case <-done:
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { close(done); _ = ln.Close(); wg.Wait() }
}

// startWalledEP registers a DC_NOP EP through brokerAddr and REFUSES every
// reverse-connect dial to anywhere but allowAddr. That is the restricted node:
// the only address it can reach is the helper on its own side of the pipe.
func startWalledEP(t *testing.T, brokerAddr, allowAddr string, served chan<- struct{}, refused chan<- string) (contact string, stop func()) {
	t.Helper()
	srv := cedarserver.New(plaintextSec())
	srv.Handle(commands.DC_NOP, func(_ context.Context, _ *cedarserver.Conn) error {
		select {
		case served <- struct{}{}:
		default:
		}
		return cedarserver.KeepOpen()
	})
	_, allowPort, _ := net.SplitHostPort(allowAddr)
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        brokerAddr,
		Security:          plaintextSec(),
		Name:              "walled-ep",
		HeartbeatInterval: 30 * time.Second,
		Handler:           func(conn net.Conn, _ ccb.InboundMeta) { _ = srv.ServeConn(context.Background(), conn) },
		DialControl: func(_, address string, _ syscall.RawConn) error {
			_, port, _ := net.SplitHostPort(address)
			if port != allowPort {
				select {
				case refused <- address:
				default:
				}
				return errors.New("no outbound TCP from this node: refusing " + address)
			}
			return nil
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

// TestSpliceHelperInboundRendezvous is the falsifier for the splice-helper
// model: can an EP be reached inbound when the far end of the carrier is a dumb
// byte relay rather than a CCB broker?
//
// Registration is expected to work -- the helper is transparent, and the EP
// cannot tell a spliced broker from a local one. The open question is the
// return address: the broker tells the target to reverse-connect to MyAddress,
// and in streaming mode that is the broker's OWN address, which a restricted
// node cannot dial. This test walls the EP off from everything but the helper,
// so that failure is forced rather than hidden by a loopback-reachable broker.
func TestSpliceHelperInboundRendezvous(t *testing.T) {
	// The two addresses are mutually dependent -- the helper dials the broker,
	// and the broker must name the helper -- so the listener is opened first and
	// the server built around it once the helper's address is known. A real
	// deployment resolves this the other way: the helper announces its address
	// up the pipe once connected.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	outsideAddr := ln.Addr().String()
	helperAddr, stopHelper := startSpliceHelper(t, outsideAddr)
	defer stopHelper()

	srv, err := New(Config{
		PublicAddress:         outsideAddr,
		ReverseConnectAddress: helperAddr,
		Security:              plaintextSec(),
		RequestTimeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, stopOut := context.WithCancel(context.Background())
	defer stopOut()
	go func() { _ = srv.Serve(srvCtx, ln) }()

	served := make(chan struct{}, 1)
	refused := make(chan string, 4)
	epContact, stopEP := startWalledEP(t, helperAddr, helperAddr, served, refused)
	defer stopEP()

	t.Logf("ep_contact=%s  (outside=%s helper=%s)", epContact, outsideAddr, helperAddr)
	if strings.Count(epContact, "#") != 1 {
		t.Errorf("contact %q should be FLAT (<outside>#<id>) in the splice model", epContact)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, contactsFor(t, epContact), ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "walled-ep",
		Timeout:    10 * time.Second,
		// Force the streaming path. A flat contact gives a direct client no
		// reason to choose it (dialOne takes dialStandard), and the broker
		// cannot upgrade the mode on its own -- dialStandard is already waiting
		// on its own listener. Isolating that here so this test answers only
		// "does the spliced data path work"; the signalling is design work.
		ProxyReturnAddr: "<0.0.0.0:0>",
	})
	if err != nil {
		select {
		case addr := <-refused:
			t.Fatalf("CONFIRMED: the EP was told to reverse-connect to %s, which it cannot reach.\n"+
				"The broker mints its own address as MyAddress; on a restricted node only the\n"+
				"helper's address is dialable. Dial error: %v", addr, err)
		default:
			t.Fatalf("Dial %q failed, but the EP never refused a reverse-connect dial: %v", epContact, err)
		}
	}
	defer func() { _ = conn.Close() }()

	if err := endToEndDCNop(ctx, conn, epContact); err != nil {
		t.Fatalf("end-to-end DC_NOP through the splice helper: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("EP DC_NOP did not dispatch through the splice")
	}
}

// TestSpliceHelperExternalReturnAddress asks Brian's question: does the broker
// need to mint an address the EP can reach, or is its own external address
// enough?
//
// The claim is that the return address is not routing information at all. The
// broker already knows, from the CCBID, which carrier a target is behind; and
// the EP already knows the one address it can reach, because it registered
// through it. "Reverse-connect to MyAddress" only has to mean "come back to
// your broker" -- the address is a name for the peer, not a destination to
// resolve.
//
// So: the broker mints its OWN external address, which the walled EP cannot
// route to, and the EP dials through a carrier that ignores the address and
// reconnects to its broker. No ReverseConnectAddress, nothing announced up the
// pipe, no per-carrier state.
func TestSpliceHelperExternalReturnAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	outsideAddr := ln.Addr().String()
	helperAddr, stopHelper := startSpliceHelper(t, outsideAddr)
	defer stopHelper()

	// Note what is NOT set: no ReverseConnectAddress. The broker mints
	// proxyAddrSinful(), its own external address.
	srv, err := New(Config{
		PublicAddress:  outsideAddr,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, stopOut := context.WithCancel(context.Background())
	defer stopOut()
	go func() { _ = srv.Serve(srvCtx, ln) }()

	served := make(chan struct{}, 1)
	var dialed []string
	var dialMu sync.Mutex

	cedarSrv := cedarserver.New(plaintextSec())
	cedarSrv.Handle(commands.DC_NOP, func(_ context.Context, _ *cedarserver.Conn) error {
		select {
		case served <- struct{}{}:
		default:
		}
		return cedarserver.KeepOpen()
	})
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        helperAddr,
		Security:          plaintextSec(),
		Name:              "carrier-ep",
		HeartbeatInterval: 30 * time.Second,
		Handler:           func(conn net.Conn, _ ccb.InboundMeta) { _ = cedarSrv.ServeConn(context.Background(), conn) },
		// The whole hypothesis, in one function: whatever address the broker
		// names, go back to the broker. A real EP on a restricted node has
		// exactly one way out, and this is it.
		Dial: func(ctx context.Context, brokerAddr string) (net.Conn, error) {
			dialMu.Lock()
			dialed = append(dialed, brokerAddr)
			dialMu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, "tcp", helperAddr)
		},
	})
	epCtx, stopEP := context.WithCancel(context.Background())
	defer stopEP()
	go func() { _ = lis.Run(epCtx) }()

	var epContact string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if epContact = lis.Contact(); epContact != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if epContact == "" {
		t.Fatal("EP did not register through the splice helper")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, contactsFor(t, epContact), ccb.DialOptions{
		Security:        plaintextSec(),
		TargetDesc:      "carrier-ep",
		Timeout:         10 * time.Second,
		ProxyReturnAddr: "<0.0.0.0:0>", // mode signalling is a separate question (§3.3)
	})
	if err != nil {
		t.Fatalf("Dial %q with an EXTERNAL return address: %v", epContact, err)
	}
	defer func() { _ = conn.Close() }()

	if err := endToEndDCNop(ctx, conn, epContact); err != nil {
		t.Fatalf("end-to-end DC_NOP: %v", err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("EP DC_NOP did not dispatch")
	}

	dialMu.Lock()
	defer dialMu.Unlock()
	t.Logf("addresses the broker named, all ignored by the EP: %v", dialed)
	var sawExternal bool
	for _, a := range dialed {
		if strings.Contains(a, strings.Trim(outsideAddr, "<>")) {
			sawExternal = true
		}
	}
	if !sawExternal {
		t.Errorf("the EP was never handed the broker's external address %q (saw %v), "+
			"so this test did not exercise the claim", outsideAddr, dialed)
	}
}
