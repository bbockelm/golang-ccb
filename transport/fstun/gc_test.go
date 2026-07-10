package fstun

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stopForTest simulates the local process dying uncleanly: it stops emitting any
// further frames (heartbeats/ACKs) WITHOUT sending a FIN, so the peer must detect
// the silence via its idle timeout rather than a clean close.
func (c *Conn) stopForTest() { c.w.close() }

func TestDoorbellRungOnDial(t *testing.T) {
	cfg := fastCfg(t.TempDir())
	pipePair(t, cfg) // establishes a pipe (acceptor discovers via the doorbell)
	if _, err := os.Stat(filepath.Join(cfg.Root, doorbellName)); err != nil {
		t.Fatalf("doorbell file not created by Dial: %v", err)
	}
}

// TestAcceptorReapsClosedTunnel verifies the outside/acceptor (root owner) removes
// a tunnel's subtree once the pipe is fully closed.
func TestAcceptorReapsClosedTunnel(t *testing.T) {
	cfg := fastCfg(t.TempDir())
	ln, err := Listen(cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accCh := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accCh <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ini, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	var acc net.Conn
	select {
	case acc = <-accCh:
	case <-time.After(10 * time.Second):
		t.Fatal("no Accept")
	}

	// Exchange a byte so both sides are fully live, then note the subtree.
	if _, err := ini.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := acc.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	connDir := filepath.Join(cfg.Root, connIDOf(t, cfg.Root))

	// Fully close both ends -> the acceptor's pipe becomes terminal -> reap.
	_ = ini.Close()
	_ = acc.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(connDir); os.IsNotExist(err) {
			return // reaped
		}
		if time.Now().After(deadline) {
			t.Fatalf("acceptor did not reap closed tunnel subtree %s", connDir)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestAcceptorReapsIdleTunnel verifies a tunnel that goes silent (no heartbeats /
// ACKs) past IdleTimeout is reaped by the acceptor, not leaked.
func TestAcceptorReapsIdleTunnel(t *testing.T) {
	cfg := fastCfg(t.TempDir())
	cfg.Heartbeat = 20 * time.Millisecond
	cfg.IdleTimeout = 300 * time.Millisecond

	ln, err := Listen(cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	accCh := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accCh <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ini, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	select {
	case <-accCh:
	case <-time.After(10 * time.Second):
		t.Fatal("no Accept")
	}
	connDir := filepath.Join(cfg.Root, connIDOf(t, cfg.Root))

	// Simulate a silently-dead initiator: stop its loops so it emits no more
	// heartbeats, without a clean FIN (mimicking a partition).
	ini.stopForTest()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(connDir); os.IsNotExist(err) {
			return // acceptor idle-reaped it
		}
		if time.Now().After(deadline) {
			t.Fatalf("acceptor did not reap idle tunnel subtree %s", connDir)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestInitiatorReapsFailedDial verifies the client removes its own subtree when a
// dial never establishes (no acceptor), so a failed attempt does not leak.
func TestInitiatorReapsFailedDial(t *testing.T) {
	cfg := fastCfg(t.TempDir())
	cfg.HandshakeTimeout = 300 * time.Millisecond // no acceptor -> quick timeout

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, cfg); err == nil {
		t.Fatal("expected Dial to fail with no acceptor")
	}

	entries, err := os.ReadDir(cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Fatalf("failed dial leaked subtree %q", e.Name())
		}
	}
}
