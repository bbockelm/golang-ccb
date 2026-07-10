package ccbserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
)

// TestTargetIdleTimeout verifies a registered target that goes silent (no
// heartbeat) is reaped past TargetIdleTimeout: the CCB closes the persistent
// connection promptly, rather than leaking the registration.
func TestTargetIdleTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv, err := New(Config{
		PublicAddress:     addr,
		Security:          plaintextSec(),
		TargetIdleTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	rctx, rc := context.WithTimeout(context.Background(), 5*time.Second)
	defer rc()
	sec := plaintextSec()
	sec.Command = commands.CCB_REGISTER
	cl, err := client.ConnectAndAuthenticate(rctx, addr, sec)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if err := ccb.WriteControlAd(rctx, cl.GetStream(), ccb.NewAd(map[string]any{
		ccb.AttrCommand: ccb.CommandRegister,
		ccb.AttrName:    "silent-target",
	})); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := ccb.ReadControlAd(rctx, cl.GetStream()); err != nil {
		t.Fatalf("register reply: %v", err)
	}

	// Registered; now go silent. The CCB must reap us and close the connection,
	// so a blocking read returns an error promptly (a fast server-side close, not
	// a slow client-side read timeout).
	_ = cl.GetStream().GetConnection().SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, err = ccb.ReadControlAd(rctx, cl.GetStream())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected the idle target to be reaped and its connection closed")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("connection not reaped promptly (%v); idle timeout not enforced", elapsed)
	}
}
