package fstun

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fastCfg is a config tuned for fast tests: tiny poll interval, short heartbeat,
// generous idle timeout. Callers override SegmentSize/Window/MaxFrame as needed.
func fastCfg(root string) Config {
	return Config{
		Root:             root,
		PollInterval:     2 * time.Millisecond,
		Heartbeat:        100 * time.Millisecond,
		IdleTimeout:      30 * time.Second,
		HandshakeTimeout: 10 * time.Second,
	}
}

// pipePair dials an initiator and accepts the matching acceptor over one root.
func pipePair(t *testing.T, cfg Config) (initiator, acceptor net.Conn) {
	t.Helper()
	ln, err := Listen(cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		accCh <- c
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ini, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	select {
	case acceptor = <-accCh:
	case err := <-errCh:
		t.Fatalf("Accept: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for Accept")
	}
	t.Cleanup(func() { _ = ini.Close(); _ = acceptor.Close() })
	return ini, acceptor
}

func TestLoopbackDuplex(t *testing.T) {
	ini, acc := pipePair(t, fastCfg(t.TempDir()))

	// initiator -> acceptor
	if _, err := ini.Write([]byte("hello acceptor")); err != nil {
		t.Fatalf("ini write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := acc.Read(buf)
	if err != nil {
		t.Fatalf("acc read: %v", err)
	}
	if got := string(buf[:n]); got != "hello acceptor" {
		t.Fatalf("acc got %q", got)
	}

	// acceptor -> initiator
	if _, err := acc.Write([]byte("hello initiator")); err != nil {
		t.Fatalf("acc write: %v", err)
	}
	n, err = ini.Read(buf)
	if err != nil {
		t.Fatalf("ini read: %v", err)
	}
	if got := string(buf[:n]); got != "hello initiator" {
		t.Fatalf("ini got %q", got)
	}
}

func TestLargeTransferRotationReap(t *testing.T) {
	cfg := fastCfg(t.TempDir())
	cfg.SegmentSize = 64 << 10 // 64 KiB -> many segments
	cfg.MaxFrame = 8 << 10
	cfg.Window = 128 << 10

	ini, acc := pipePair(t, cfg)

	const total = 4 << 20 // 4 MiB, ~64 segments
	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, 0, total)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for len(got) < total {
			n, err := acc.Read(buf)
			got = append(got, buf[:n]...)
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
		t.Fatalf("payload mismatch: got %d bytes", len(got))
	}

	// Reaping: the initiator's c2s direction should not still hold all ~64
	// segments once the acceptor has ACKed its consumption. Give ACKs a moment.
	deadline := time.Now().Add(5 * time.Second)
	c2s := filepath.Join(cfg.Root, connIDOf(t, cfg.Root), "c2s")
	for {
		segs := countSegs(t, c2s)
		if segs <= 4 { // a small tail remains unreaped; that's fine
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected reaping to reduce c2s segments, still have %d", segs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestHalfCloseEOF(t *testing.T) {
	ini, acc := pipePair(t, fastCfg(t.TempDir()))

	msg := []byte("final message before close")
	if _, err := ini.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := ini.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := io.ReadAll(acc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q want %q", got, msg)
	}
}

func TestSlowReaderBackpressureIntegrity(t *testing.T) {
	cfg := fastCfg(t.TempDir())
	cfg.SegmentSize = 32 << 10
	cfg.MaxFrame = 4 << 10
	cfg.Window = 16 << 10 // tiny window forces the writer to stall on a slow reader

	ini, acc := pipePair(t, cfg)

	const total = 512 << 10
	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, 0, total)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 3000)
		for len(got) < total {
			n, err := acc.Read(buf)
			got = append(got, buf[:n]...)
			time.Sleep(2 * time.Millisecond) // deliberately slow consumer
			if err != nil {
				return
			}
		}
	}()

	if _, err := ini.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("slow reader did not drain in time")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch under backpressure: got %d/%d", len(got), total)
	}
}

func TestReadDeadline(t *testing.T) {
	ini, _ := pipePair(t, fastCfg(t.TempDir()))
	if err := ini.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_, err := ini.Read(buf)
	var te interface{ Timeout() bool }
	if !errors.As(err, &te) || !te.Timeout() {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

// TestDecodeFrameTornTail verifies the reader treats a partially-written frame as
// incomplete (wait), and reads it once the tail arrives -- the core NFS
// partial-visibility tolerance.
func TestDecodeFrameTornTail(t *testing.T) {
	f := frame{typ: frameDATA, seq: 7, dataOff: 100, payload: []byte("some payload bytes")}
	full := f.appendTo(nil)

	for cut := 1; cut < len(full); cut++ {
		if _, _, err := decodeFrame(full[:cut]); !errors.Is(err, errIncompleteFrame) {
			t.Fatalf("cut=%d: expected incomplete, got %v", cut, err)
		}
	}
	dec, n, err := decodeFrame(full)
	if err != nil {
		t.Fatalf("full decode: %v", err)
	}
	if n != len(full) || dec.seq != 7 || dec.dataOff != 100 || string(dec.payload) != "some payload bytes" {
		t.Fatalf("bad decode: n=%d %+v", n, dec)
	}

	// A corrupt (bit-flipped) but fully-present frame is fatal, not incomplete.
	corrupt := append([]byte(nil), full...)
	corrupt[headerLen] ^= 0xFF
	if _, _, err := decodeFrame(corrupt); !errors.Is(err, errCorruptFrame) {
		t.Fatalf("expected corrupt, got %v", err)
	}
}

// connIDOf returns the single conn-id subdirectory under root (the test creates
// exactly one pipe).
func connIDOf(t *testing.T, root string) string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			return e.Name()
		}
	}
	t.Fatal("no conn-id subdir found")
	return ""
}

func countSegs(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".seg" {
			n++
		}
	}
	return n
}
