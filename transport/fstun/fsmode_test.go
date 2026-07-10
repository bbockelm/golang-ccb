package fstun

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDetectNetworkFSLocalIsFalse(t *testing.T) {
	// A test temp dir is always on a local filesystem, so detection must not
	// enable the network-mode overhead.
	if detectNetworkFS(t.TempDir()) {
		t.Fatal("detectNetworkFS reported a temp dir as a network filesystem")
	}
}

func boolPtr(b bool) *bool { return &b }

// TestForcedNetworkModeRoundTrip exercises the network-mode code paths (Nagle
// fsync batching on writes, close-to-open revalidation on reads) by forcing
// NetworkFS=true on the local test FS, including a transfer large enough to roll
// segments. Data integrity must be identical to local mode.
func TestForcedNetworkModeRoundTrip(t *testing.T) {
	cfg := fastCfg(t.TempDir())
	cfg.NetworkFS = boolPtr(true)
	cfg.FlushInterval = 3 * time.Millisecond
	cfg.SegmentSize = 64 << 10 // force rotation (and close-to-open across segments)
	cfg.MaxFrame = 8 << 10
	cfg.Window = 128 << 10

	ini, acc := pipePair(t, cfg)

	// Quick duplex sanity first.
	if _, err := ini.Write([]byte("net-hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_ = acc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := acc.Read(buf); err != nil || string(buf[:n]) != "net-hello" {
		t.Fatalf("duplex read = %q, %v", buf[:n], err)
	}

	const total = 2 << 20 // 2 MiB over ~32 segments
	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 0, total)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 32<<10)
		for len(got) < total {
			n, err := acc.Read(b)
			got = append(got, b[:n]...)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				t.Errorf("read: %v", err)
				return
			}
		}
	}()
	if _, err := ini.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch in network mode: got %d/%d bytes", len(got), total)
	}
}

// TestForcedNetworkModeMuxlessDial confirms Dial/Accept still establish under
// forced network mode (SYN fsync'd via syncNow, read close-to-open).
func TestForcedNetworkModeEstablish(t *testing.T) {
	cfg := fastCfg(t.TempDir())
	cfg.NetworkFS = boolPtr(true)

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
		t.Fatalf("Dial (network mode): %v", err)
	}
	defer func() { _ = ini.Close() }()
	select {
	case acc := <-accCh:
		_ = acc.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("no Accept in network mode")
	}
}
