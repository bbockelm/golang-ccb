package ccbserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/ccb"
)

// startLimitedServer starts a broker on loopback with lim in force. Loopback
// is limited like any other source unless lim says otherwise.
func startLimitedServer(t *testing.T, lim Limits, mod func(*Config)) (addr string, srv *Server, rec *logCatcher) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	rec = &logCatcher{}
	cfg := Config{
		PublicAddress:  addr,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		Limits:         lim,
		Logger:         slog.New(rec),
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(cancel)
	return addr, srv, rec
}

// once is a rate that admits one operation and, for the length of a test,
// no more.
var once = Rate{PerSecond: 0.0001, Burst: 1}

func dialEcho(t *testing.T, contact string, streaming bool) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	opts := ccb.DialOptions{
		Security:   plaintextSec(),
		ListenAddr: "127.0.0.1:0",
		TargetDesc: "echo-target",
		Timeout:    6 * time.Second,
	}
	if streaming {
		opts = ccb.DialOptions{
			Security:         plaintextSec(),
			ProxyReturnAddr:  "<10.9.8.7:0?ccbid=" + contact + ">",
			RequireStreaming: true,
			TargetDesc:       "echo-target",
			Timeout:          6 * time.Second,
		}
	}
	return ccb.Dial(ctx, contactsFor(t, contact), opts)
}

// TestRegisterRateLimitedEndToEnd: a source over its registration rate is
// not given a contact.
func TestRegisterRateLimitedEndToEnd(t *testing.T) {
	addr, _, rec := startLimitedServer(t, Limits{
		Default:       ClassLimits{Register: once},
		LimitLoopback: true,
	}, nil)
	_, stop := startEchoTarget(t, addr)
	defer stop()

	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        addr,
		Security:          plaintextSec(),
		Name:              "second",
		HeartbeatInterval: 30 * time.Second,
		Handler:           func(c net.Conn, _ ccb.InboundMeta) { _ = c.Close() },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = lis.Run(ctx) }()
	time.Sleep(1500 * time.Millisecond)
	if c := lis.Contact(); c != "" {
		t.Fatalf("second registration from one source got contact %q over a one-registration rate", c)
	}
	if !rec.saw("rate limit refusing") {
		rec.dump(t, "broker")
		t.Error("the broker did not log the refusal")
	}
}

// TestRequestRateLimitedEndToEnd: a request over the source's rate is
// answered with a failure that says why.
func TestRequestRateLimitedEndToEnd(t *testing.T) {
	addr, _, _ := startLimitedServer(t, Limits{
		Default:       ClassLimits{Request: once},
		LimitLoopback: true,
	}, nil)
	contact, stop := startEchoTarget(t, addr)
	defer stop()

	conn, err := dialEcho(t, contact, false)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	assertEcho(t, conn)
	_ = conn.Close()

	_, err = dialEcho(t, contact, false)
	if err == nil || !strings.Contains(err.Error(), "rate limited: request") {
		t.Fatalf("second request = %v, want a rate-limit refusal", err)
	}
}

// TestTargetRequestRateEndToEnd: the per-target rate protects one daemon,
// and SetLimits applies a new one to a daemon already registered.
func TestTargetRequestRateEndToEnd(t *testing.T) {
	addr, srv, _ := startLimitedServer(t, Limits{LimitLoopback: true}, nil)
	contact, stop := startEchoTarget(t, addr)
	defer stop()

	for i := 0; i < 3; i++ {
		conn, err := dialEcho(t, contact, false)
		if err != nil {
			t.Fatalf("unlimited request %d: %v", i, err)
		}
		_ = conn.Close()
	}
	if err := srv.SetLimits(Limits{Default: ClassLimits{TargetRequest: once}, LimitLoopback: true}); err != nil {
		t.Fatal(err)
	}
	conn, err := dialEcho(t, contact, false)
	if err != nil {
		t.Fatalf("first request after reconfig: %v", err)
	}
	_ = conn.Close()
	_, err = dialEcho(t, contact, false)
	if err == nil || !strings.Contains(err.Error(), "per-target") {
		t.Fatalf("second request after reconfig = %v, want a per-target refusal", err)
	}
}

// TestConnectionAdmissionEndToEnd: connections over a source's rate, and
// beyond its cap on unfinished handshakes, are closed before anything is
// read; a freed pending slot admits again.
func TestConnectionAdmissionEndToEnd(t *testing.T) {
	t.Run("rate", func(t *testing.T) {
		addr, _, _ := startLimitedServer(t, Limits{
			Default:       ClassLimits{Connect: Rate{PerSecond: 0.0001, Burst: 2}},
			LimitLoopback: true,
		}, nil)
		for i := 0; i < 2; i++ {
			c := rawConn(t, addr)
			if closedSoon(c, 300*time.Millisecond) {
				t.Fatalf("connection %d under the rate was closed", i)
			}
		}
		if !closedSoon(rawConn(t, addr), 5*time.Second) {
			t.Fatal("connection over the rate was not closed")
		}
	})
	t.Run("pending", func(t *testing.T) {
		addr, _, _ := startLimitedServer(t, Limits{
			Default:       ClassLimits{MaxPending: 1},
			LimitLoopback: true,
		}, nil)
		first := rawConn(t, addr)
		if closedSoon(first, 300*time.Millisecond) {
			t.Fatal("first pending connection was closed")
		}
		if !closedSoon(rawConn(t, addr), 5*time.Second) {
			t.Fatal("second pending connection from one source was not closed")
		}
		_ = first.Close()
		time.Sleep(200 * time.Millisecond)
		if closedSoon(rawConn(t, addr), 300*time.Millisecond) {
			t.Fatal("a connection after the first went away was closed")
		}
	})
	t.Run("loopback exempt by default", func(t *testing.T) {
		addr, _, _ := startLimitedServer(t, Limits{Default: ClassLimits{MaxPending: 1}}, nil)
		_ = rawConn(t, addr)
		if closedSoon(rawConn(t, addr), 300*time.Millisecond) {
			t.Fatal("a loopback connection was limited")
		}
	})
}

func rawConn(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// closedSoon reports whether the server closes c within d.
func closedSoon(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	var b [1]byte
	_, err := c.Read(b[:])
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return err != nil
}

// TestStreamingSpliceCapEndToEnd: a second relayed connection from a source
// at its MaxSplices is refused, and one is admitted again once the first
// relay ends.
func TestStreamingSpliceCapEndToEnd(t *testing.T) {
	addr, _, _ := startLimitedServer(t, Limits{
		Default:       ClassLimits{MaxSplices: 1},
		LimitLoopback: true,
	}, nil)
	contact, stop := startEchoTarget(t, addr)
	defer stop()

	first, err := dialEcho(t, contact, true)
	if err != nil {
		t.Fatalf("first relay: %v", err)
	}
	_, err = dialEcho(t, contact, true)
	if err == nil || !strings.Contains(err.Error(), "relayed connections") {
		t.Fatalf("second relay = %v, want a relayed-connections refusal", err)
	}
	assertEcho(t, first) // the echo target closes after one exchange
	_, _ = io.Copy(io.Discard, first)
	_ = first.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := dialEcho(t, contact, true)
		if err == nil {
			assertEcho(t, c)
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay after the first ended: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestOutboundProxyTargetNetworkCapEndToEnd: the outbound proxy charges the
// network it dials into, so a class covering the target caps relays into it
// even when the requester is exempt.
func TestOutboundProxyTargetNetworkCapEndToEnd(t *testing.T) {
	targetIP := nonLoopbackIPv4(t)
	served := make(chan struct{}, 4)
	target, stopTarget := startCedarDialTarget(t, targetIP, served)
	defer stopTarget()

	addr, _, rec := startLimitedServer(t, Limits{Classes: []NetworkClass{{
		Name:     "FRAGILE",
		Networks: []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(targetIP), 32)},
		Limits:   ClassLimits{MaxSplicesClass: 1},
	}}}, func(c *Config) {
		c.OutboundProxy = true
		c.OutboundTargetAllowlist = []string{targetIP}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sinful := "<" + target + ">"
	held, err := ccb.OutboundConnect(ctx, addr, sinful, ccb.OutboundOptions{Security: plaintextSec(), Name: "first", Timeout: 8 * time.Second})
	if err != nil {
		rec.dump(t, "broker")
		t.Fatalf("first relay: %v", err)
	}
	defer held.Close()

	_, err = ccb.OutboundConnect(ctx, addr, sinful, ccb.OutboundOptions{Security: plaintextSec(), Name: "second", Timeout: 8 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "class FRAGILE") {
		rec.dump(t, "broker")
		t.Fatalf("second relay into the class = %v, want a FRAGILE refusal", err)
	}
}
