package ccbserver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-ccb/transport/wscarrier"
)

// TestUnauthenticatedCarrierStillTunnels is the load-bearing claim of
// CCB_CARRIER_AUTH = none: with no credential on the upgrade at all, an inside
// CCB still registers upstream and a nested EP contact still forms. The
// identity comes from the CEDAR handshake on the first command, which happens
// inside the carrier and never puts a credential on the wire.
func TestUnauthenticatedCarrierStillTunnels(t *testing.T) {
	carrierURL := fmt.Sprintf("ws://127.0.0.1:%d/ccb/tunnel", freePort(t))

	outLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	outsideAddr := outLn.Addr().String()
	outsideSrv, err := New(Config{
		PublicAddress:  outsideAddr,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		CarrierListen:  carrierURL,
		// No CarrierTokenVerify at all.
		CarrierUnauthenticated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	octx, ocancel := context.WithCancel(context.Background())
	defer ocancel()
	go func() { _ = outsideSrv.Serve(octx, outLn) }()

	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	insideAddr := inLn.Addr().String()
	insideSrv, err := New(Config{
		PublicAddress:  insideAddr,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		Upstream: &UpstreamConfig{
			BrokerAddr:        carrierURL,
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
		CarrierUnauthenticated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ictx, icancel := context.WithCancel(context.Background())
	defer icancel()
	go func() { _ = insideSrv.Serve(ictx, inLn) }()

	rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer rcancel()
	if err := insideSrv.WaitTunnelReady(rctx); err != nil {
		t.Fatalf("inside CCB never registered over an unauthenticated carrier: %v", err)
	}
	if tc := insideSrv.TunnelContact(); !strings.HasPrefix(tc, outsideAddr+"#") {
		t.Fatalf("tunnel contact %q does not carry the outside address %q", tc, outsideAddr)
	}

	served := make(chan struct{}, 1)
	epContact, stopEP := startRegisteredCedarEP(t, insideAddr, served)
	defer stopEP()
	if strings.Count(epContact, "#") < 2 {
		t.Fatalf("EP contact %q is not nested", epContact)
	}
}

// TestUnauthenticatedCarrierStillAuthorizes: opening a carrier is not
// permission to do anything. An anonymous peer that gets through the upgrade
// must still be refused by the ALLOW_/DENY_ policy, which is what actually
// guards the broker once the token is gone.
func TestUnauthenticatedCarrierStillAuthorizes(t *testing.T) {
	carrierURL := fmt.Sprintf("ws://127.0.0.1:%d/ccb/tunnel", freePort(t))

	outLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The authorizer runs on the broker's accept goroutine while the test body
	// reads the result, so this needs a lock -- the race detector catches it in
	// CI even though a local run without -race does not.
	var askedMu sync.Mutex
	var asked []string
	outsideSrv, err := New(Config{
		PublicAddress:          outLn.Addr().String(),
		Security:               plaintextSec(),
		RequestTimeout:         5 * time.Second,
		CarrierListen:          carrierURL,
		CarrierUnauthenticated: true,
		// Refuse everything, as a policy with no matching entry does.
		Authorizer: func(perm, peerAddr, _ string) bool {
			askedMu.Lock()
			asked = append(asked, perm+" from "+peerAddr)
			askedMu.Unlock()
			return false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	octx, ocancel := context.WithCancel(context.Background())
	defer ocancel()
	go func() { _ = outsideSrv.Serve(octx, outLn) }()

	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	insideSrv, err := New(Config{
		PublicAddress:  inLn.Addr().String(),
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		Upstream: &UpstreamConfig{
			BrokerAddr:        carrierURL,
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
		CarrierUnauthenticated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ictx, icancel := context.WithCancel(context.Background())
	defer icancel()
	go func() { _ = insideSrv.Serve(ictx, inLn) }()

	// Registration must never complete: the upgrade succeeds, the command does
	// not.
	rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer rcancel()
	if err := insideSrv.WaitTunnelReady(rctx); err == nil {
		t.Fatal("registration succeeded through a deny-all authorizer; the carrier bypassed authorization")
	}
	askedMu.Lock()
	consulted := len(asked)
	askedMu.Unlock()
	if consulted == 0 {
		t.Fatal("the authorizer was never consulted for a carrier connection")
	}
}

// TestCarrierListenRejectsSilentlyUnauthenticated: a ws:// listener with no
// verifier and no explicit opt-in must be an error, not an open door.
func TestCarrierListenRejectsSilentlyUnauthenticated(t *testing.T) {
	carrierURL := fmt.Sprintf("ws://127.0.0.1:%d/ccb/tunnel", freePort(t))
	srv, err := New(Config{
		PublicAddress:  "127.0.0.1:1",
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		CarrierListen:  carrierURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.carrierNetListener(carrierRef{scheme: "ws", url: carrierURL}); err == nil {
		t.Fatal("a ws:// carrier listener was built with neither a verifier nor CarrierUnauthenticated")
	}
}

// TestCarrierUnauthenticatedOverridesVerifier: when the operator asks for no
// upgrade credential, a verifier left configured must not quietly re-impose
// one -- otherwise the knob would appear to work while nodes without a token
// still failed to dial.
func TestCarrierUnauthenticatedOverridesVerifier(t *testing.T) {
	carrierURL := fmt.Sprintf("ws://127.0.0.1:%d/ccb/tunnel", freePort(t))
	srv, err := New(Config{
		PublicAddress:  "127.0.0.1:1",
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		CarrierListen:  carrierURL,
		CarrierTokenVerify: func(context.Context, string) (string, error) {
			return "", fmt.Errorf("this verifier must not be consulted")
		},
		CarrierUnauthenticated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := srv.carrierNetListener(carrierRef{scheme: "ws", url: carrierURL})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A dial presenting nothing must be accepted by the always-failing verifier
	// being out of the path.
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			go func() { _ = c.Close() }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialCarrierURL(ctx, carrierURL)
	if err != nil {
		t.Fatalf("dial with no credential was refused: %v", err)
	}
	defer func() { go func() { _ = c.Close() }() }()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never accepted the unauthenticated pipe")
	}
}

// dialCarrierURL opens a carrier pipe presenting no credential.
func dialCarrierURL(ctx context.Context, url string) (net.Conn, error) {
	return wscarrier.Dial(ctx, wscarrier.DialConfig{URL: url, Unauthenticated: true})
}
