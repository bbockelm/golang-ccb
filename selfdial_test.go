package ccbserver

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
)

// Can a broker's outbound proxy dial the broker's OWN address?
//
// This is the one unproven link in the splice-helper model (docs/SPLICE_HELPER.md).
// A target behind a splice helper is told to reverse-connect to MyAddress, which
// in proxy mode is the broker's own rendezvous address. cedar targets ignore it
// and go back out through the broker they registered with (CCBProxyMode); a C++
// target has no such notion -- CCBListener::DoReversedCCBConnect dials MyAddress
// literally -- and reaches it by routing the dial through OUTBOUND_CCB_ADDRESS,
// which in this model is the splice helper. The broker therefore receives a
// proxy-connect naming itself.
//
// Nothing in the source refuses that: outboundTargetAllowed() refuses loopback
// and link-local, and RefuseLocalAddresses() refuses the same set at dial time,
// but neither knows the broker's own public address. These tests hold that
// reading to the fire, because "I read the code and found no check" is exactly
// the claim that is worth being wrong about.

// startSelfDialBroker is startOutboundBroker on a named (non-loopback) IP, so
// the broker's own address is not refused for being loopback -- that refusal
// would mask the question being asked.
func startSelfDialBroker(t *testing.T, listenIP string, allowlist []string) (addr string, rec *logCatcher, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(listenIP, "0"))
	if err != nil {
		t.Fatalf("listening on %s: %v", listenIP, err)
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

// TestBrokerProxyDialsItsOwnAddress: the broker splices a proxy-connect whose
// target is the broker itself, rather than refusing it or deadlocking against
// its own accept loop.
func TestBrokerProxyDialsItsOwnAddress(t *testing.T) {
	ip := nonLoopbackIPv4(t)
	brokerAddr, rec, stop := startSelfDialBroker(t, ip, []string{ip + "/32"})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := ccb.OutboundConnect(ctx, brokerAddr, "<"+brokerAddr+">", ccb.OutboundOptions{
		Security: plaintextSec(),
		Name:     "self-dial-test",
		Timeout:  8 * time.Second,
	})
	if err != nil {
		t.Fatalf("broker refused to proxy a dial to its own address %s: %v", brokerAddr, err)
	}
	defer func() { _ = conn.Close() }()

	if !rec.saw("proxy-connect splice established") {
		t.Error("the connect returned but the broker logged no splice; the far end may not be the broker")
	}
}

// TestBrokerProxyRefusesItsOwnLoopbackAddress is the control. The same request
// against a loopback-addressed broker must be refused, so a pass above cannot
// be read as "the allow-list and the loopback guard do nothing".
func TestBrokerProxyRefusesItsOwnLoopbackAddress(t *testing.T) {
	brokerAddr, _, stop := startOutboundBroker(t, []string{"127.0.0.1/32"})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := ccb.OutboundConnect(ctx, brokerAddr, "<"+brokerAddr+">", ccb.OutboundOptions{
		Security: plaintextSec(),
		Name:     "self-dial-loopback-test",
		Timeout:  8 * time.Second,
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("broker proxied a dial to its own loopback address; the SSRF guard did not fire")
	}
}
