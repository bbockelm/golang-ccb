package ccbserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
)

// TestReconnectReusesCCBID drives a real registration, drops the target's
// persistent connection server-side, and verifies the target reclaims its
// original CCBID through the reconnect table (no new id minted), exercising the
// cookie/IP matching path in handleRegister.
func TestReconnectReusesCCBID(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	store := newMemoryStore()
	srv, err := New(Config{
		PublicAddress:  addr,
		Security:       plaintextSec(),
		ReconnectStore: store,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        addr,
		Security:          plaintextSec(),
		Name:              "reconnect-target",
		HeartbeatInterval: 30 * time.Second,
		ReconnectInterval: 100 * time.Millisecond,
		Handler:           func(c net.Conn) { c.Close() },
	})
	lctx, lcancel := context.WithCancel(context.Background())
	defer lcancel()
	go func() { _ = lis.Run(lctx) }()

	// Wait for the initial registration and capture its CCBID.
	contact := waitForContact(t, lis)
	id, ok := parseContactID(contact)
	if !ok {
		t.Fatalf("could not parse ccbid from %q", contact)
	}

	srv.mu.Lock()
	orig := srv.targets[id]
	startNextID := srv.nextID
	srv.mu.Unlock()
	if orig == nil {
		t.Fatalf("no live target for id %d after registration", id)
	}

	// Drop the target's persistent connection server-side to force a reconnect.
	orig.conn.Close()

	// Wait until the target has re-registered (a new target object under the
	// same id).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		cur := srv.targets[id]
		nextID := srv.nextID
		srv.mu.Unlock()
		if cur != nil && cur != orig {
			if nextID != startNextID {
				t.Errorf("reconnect minted a new CCBID: nextID %d -> %d", startNextID, nextID)
			}
			if lis.Contact() != contact {
				t.Errorf("contact changed across reconnect: %q -> %q", contact, lis.Contact())
			}
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("target did not reconnect with the same CCBID in time")
}

func waitForContact(t *testing.T, lis *ccb.Listener) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c := lis.Contact(); c != "" {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("listener did not register in time")
	return ""
}
