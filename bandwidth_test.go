package ccbserver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
)

// A repeating 0..255 ramp: the byte at global stream offset o is byte(o%256).
// writeBuf is 256-aligned so writing it repeatedly reproduces the ramp; ramp has
// a 256-byte tail so a reader can compare any offset-aligned slice by rotation.
var (
	bwWriteBuf = func() []byte {
		b := make([]byte, 64*1024)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}()
	bwRamp = func() []byte {
		b := make([]byte, 64*1024+256)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}()
)

// blast runs a full-duplex bulk transfer on conn: it writes size bytes of the
// ramp while concurrently reading size bytes and verifying they are the ramp.
// Returns when both directions finish (or errors).
func blast(conn net.Conn, size int64) error {
	var wg sync.WaitGroup
	wg.Add(2)
	var werr, rerr error

	go func() { // writer
		defer wg.Done()
		remaining := size
		for remaining > 0 {
			n := int64(len(bwWriteBuf))
			if n > remaining {
				n = remaining
			}
			if _, e := conn.Write(bwWriteBuf[:n]); e != nil {
				werr = e
				return
			}
			remaining -= n
		}
	}()

	go func() { // reader + verifier
		defer wg.Done()
		buf := make([]byte, 64*1024)
		var off int64
		for off < size {
			n, e := conn.Read(buf)
			if n > 0 {
				start := int(off % 256)
				if !bytes.Equal(buf[:n], bwRamp[start:start+n]) {
					rerr = fmt.Errorf("relayed data corrupted at offset %d", off)
					return
				}
				off += int64(n)
			}
			if e != nil {
				if e == io.EOF && off == size {
					return
				}
				rerr = fmt.Errorf("read at offset %d/%d: %w", off, size, e)
				return
			}
		}
	}()

	wg.Wait()
	if werr != nil {
		return fmt.Errorf("write: %w", werr)
	}
	return rerr
}

// startBulkTarget is a plain TCP server (the exit CCB dials it) that runs the
// full-duplex blast on each accepted connection.
func startBulkTarget(t *testing.T, listenIP string, size int64) (addr string, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(listenIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = blast(conn, size)
				select {
				case done <- struct{}{}:
				default:
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// outboundChain builds a chain of n CCBs (exit + n-1 inside CCBs) permitting
// targetIP, and returns the entry broker the requester dials.
func outboundChain(t *testing.T, n int, targetIP string) (entry string, cancel func()) {
	t.Helper()
	exit, _, stopExit := startOutboundBroker(t, []string{targetIP + "/32"})
	stops := []func(){stopExit}
	entry = exit
	for i := 1; i < n; i++ {
		inside, _, stopIn := startInsideBroker(t, entry) // next hop = current entry
		stops = append(stops, stopIn)
		entry = inside
	}
	return entry, func() {
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}
}

// TestOutboundBandwidth relays a bulk, full-duplex byte stream across 1-, 2-, and
// 3-CCB chains and reports throughput -- the Go analogue of the C++ bandwidth
// tester, exercising the splice relay under load (not just a control round trip).
// Size defaults to 16 MiB per direction; override with CCB_BW_MIB.
func TestOutboundBandwidth(t *testing.T) {
	mib := int64(16)
	if v := os.Getenv("CCB_BW_MIB"); v != "" {
		if p, err := strconv.ParseInt(v, 10, 64); err == nil && p > 0 {
			mib = p
		}
	}
	size := mib << 20
	targetIP := nonLoopbackIPv4(t)

	for _, n := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("%dCCB", n), func(t *testing.T) {
			tgtAddr, stopTgt := startBulkTarget(t, targetIP, size)
			defer stopTgt()
			entry, stopChain := outboundChain(t, n, targetIP)
			defer stopChain()

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			conn, err := ccb.OutboundConnect(ctx, entry, "<"+tgtAddr+">", ccb.OutboundOptions{
				Security: plaintextSec(),
				Name:     "bw",
				Timeout:  30 * time.Second,
			})
			if err != nil {
				t.Fatalf("OutboundConnect through %d CCB(s): %v", n, err)
			}
			defer func() { _ = conn.Close() }()

			start := time.Now()
			if err := blast(conn, size); err != nil {
				t.Fatalf("bulk relay through %d CCB(s): %v", n, err)
			}
			elapsed := time.Since(start)
			mbps := float64(2*size) / (1024 * 1024) / elapsed.Seconds() // both directions
			t.Logf("%d-CCB chain: %d MiB each way in %v => %.0f MiB/s aggregate (full-duplex)",
				n, mib, elapsed.Round(time.Millisecond), mbps)
		})
	}
}
