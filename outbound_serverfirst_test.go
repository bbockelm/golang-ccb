package ccbserver

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/ccb"
)

// The outbound proxy with a target that SPEAKS FIRST.
//
// Every other outbound test has the REQUESTER write first: outboundDCNop sends
// DC_NOP and the backend reacts, and the assertion is that the backend saw the
// command. A relay that never delivered a byte in the target -> requester
// direction would pass all of them.
//
// That is not a hypothetical shape. HTCondor's file transfer opens with
// FileTransfer::DoDownload calling s->decode() and then immediately reading --
// the target is the one that speaks, and the requester's first operation on the
// socket is a read.
//
// THESE TESTS PASS, and they do not reproduce #43. They were written to chase
// the theory that the opening of the target -> requester direction was being
// lost on the shared-port path; it is not. They are kept because the coverage
// gap they close is real on its own: without them, nothing here would notice a
// relay that only ever worked in one direction.
//
// Checked with mutation rather than assumed: removing the target -> requester
// copy from spliceConns fails both of these, and nothing else in the package.
// Note that in spliceConns(requesterConn, targetConn) it is pipe(c1, c2) that
// carries target -> requester -- removing the other one leaves both tests
// passing, which looks like a vacuous test and is a mis-aimed mutation.

// startGreeter listens on listenIP and, on accept, writes greeting BEFORE
// reading anything. That ordering is the whole point.
func startGreeter(t *testing.T, listenIP, greeting string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(listenIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if _, err := c.Write([]byte(greeting)); err != nil {
					return
				}
				// Stay open until the requester goes away. Closing here would
				// make a missing greeting indistinguishable from the relay
				// being torn down by our own close.
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// readGreeting reaches target through the broker's outbound proxy and reads,
// which is the first thing it does on the relayed conn.
func readGreeting(t *testing.T, brokerAddr, target, want string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := ccb.OutboundConnect(ctx, brokerAddr, target, ccb.OutboundOptions{
		Security: plaintextSec(),
		Name:     "outbound-serverfirst-test",
		Timeout:  8 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("OutboundConnect: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(want))
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read after %d bytes: %w", n, err)
	}
	if got := string(buf[:n]); got != want {
		return fmt.Errorf("got %q, want %q", got, want)
	}
	return nil
}

// The plain dial path: no shared port, target speaks first.
func TestOutboundProxyTargetSpeaksFirstPlain(t *testing.T) {
	targetIP := nonLoopbackIPv4(t)

	const greeting = "HELLO-FROM-TARGET"
	backendAddr, stopBackend := startGreeter(t, targetIP, greeting)
	defer stopBackend()

	brokerAddr, _, stopSrv := startOutboundBroker(t, []string{targetIP + "/32"})
	defer stopSrv()

	if err := readGreeting(t, brokerAddr, fmt.Sprintf("<%s>", backendAddr), greeting); err != nil {
		t.Fatalf("plain target that speaks first: %v", err)
	}
}

// The shared-port path, which is how every HTCondor daemon that matters is
// reached. Identical to the plain case except for the handoff.
func TestOutboundProxyTargetSpeaksFirstBehindSharedPort(t *testing.T) {
	targetIP := nonLoopbackIPv4(t)

	const greeting = "HELLO-FROM-TARGET"
	backendAddr, stopBackend := startGreeter(t, "127.0.0.1", greeting)
	defer stopBackend()

	// Named after a shadow's transfer socket, the case this was written for.
	const sock = "shadow_4035380_047a_1"
	sp := startFwdSharedPortServerOn(t, targetIP, map[string]string{sock: backendAddr})
	defer sp.Close()

	brokerAddr, _, stopSrv := startOutboundBroker(t, []string{targetIP + "/32"})
	defer stopSrv()

	target := fmt.Sprintf("<%s?sock=%s>", sp.addr(), sock)
	if err := readGreeting(t, brokerAddr, target, greeting); err != nil {
		t.Fatalf("shared-port target that speaks first: %v", err)
	}
}
