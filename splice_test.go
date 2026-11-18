package ccbserver

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-ccb/transport/carrier"
)

// dialPair returns the relay's two connections plus the two peer connections,
// so a test can drive both ends of a splice over real sockets.
func dialPair(t *testing.T) (relayA, relayB, peerA, peerB net.Conn) {
	t.Helper()
	mk := func() (net.Conn, net.Conn) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		type res struct {
			c   net.Conn
			err error
		}
		ch := make(chan res, 1)
		go func() {
			c, err := ln.Accept()
			ch <- res{c, err}
		}()
		dialed, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		got := <-ch
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.c, dialed
	}
	relayA, peerA = mk()
	relayB, peerB = mk()
	t.Cleanup(func() {
		for _, c := range []net.Conn{relayA, relayB, peerA, peerB} {
			_ = c.Close()
		}
	})
	return relayA, relayB, peerA, peerB
}

// TestSpliceDeliversRepliesAfterOnePeerFinishesSending is the relay's core
// obligation: a peer that has finished sending and is waiting for an answer must
// still receive it.
//
// This is the shape of every CEDAR exchange through the relay -- the requester
// writes its command and then only reads -- and the relay used to tear both
// connections down the moment the requester's direction went quiet, discarding
// the reply in flight the other way.
func TestSpliceDeliversRepliesAfterOnePeerFinishesSending(t *testing.T) {
	const payload = 256 * 1024

	for round := range 20 {
		relayA, relayB, peerA, peerB := dialPair(t)
		go spliceConns(relayA, relayB)

		// Peer A: finished sending, now only reading -- a CEDAR requester
		// waiting for the post-auth reply.
		if err := peerA.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}

		// Peer B answers and hangs up immediately, the way a server does when
		// its command handler returns.
		want := bytes.Repeat([]byte("reply"), payload/5)
		werr := make(chan error, 1)
		go func() {
			_, err := peerB.Write(want)
			_ = peerB.Close()
			werr <- err
		}()

		_ = peerA.SetReadDeadline(time.Now().Add(20 * time.Second))
		got, err := io.ReadAll(peerA)
		if err != nil {
			t.Fatalf("round %d: reading the reply: %v", round, err)
		}
		if err := <-werr; err != nil {
			t.Fatalf("round %d: writing the reply: %v", round, err)
		}
		if len(got) != len(want) {
			t.Fatalf("round %d: received %d of %d reply bytes; the relay tore down before draining",
				round, len(got), len(want))
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round %d: reply corrupted in the relay", round)
		}
	}
}

// TestSpliceClosesWhenBothDirectionsEnd: the relay must not leak. Both peers
// hang up, so spliceConns returns promptly rather than sitting out its drain
// grace.
func TestSpliceClosesWhenBothDirectionsEnd(t *testing.T) {
	relayA, relayB, peerA, peerB := dialPair(t)
	done := make(chan struct{})
	go func() { spliceConns(relayA, relayB); close(done) }()

	_ = peerA.Close()
	_ = peerB.Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("spliceConns did not return after both peers closed")
	}
}

// TestSpliceDoesNotWaitForeverOnAnAbandonedPeer: a peer that half-closes and
// then neither reads nor closes must not pin the relay indefinitely. The grace
// is long, so this only checks that the wait is bounded at all -- by closing the
// surviving peer and seeing the relay finish well inside it.
func TestSpliceDoesNotWaitForeverOnAnAbandonedPeer(t *testing.T) {
	relayA, relayB, peerA, peerB := dialPair(t)
	done := make(chan struct{})
	go func() { spliceConns(relayA, relayB); close(done) }()

	if err := peerA.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("the relay gave up while a peer was still able to receive")
	case <-time.After(250 * time.Millisecond):
	}

	_ = peerB.Close()
	_ = peerA.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("spliceConns did not return once both peers were gone")
	}
}

// The byte counts are the point of the stats: they are what separates a relay
// that carried the payload from one torn down early, which is the distinction
// an operator cannot make from either client's log. See issue #42.
func TestSpliceStatsCountsBothDirections(t *testing.T) {
	relayA, relayB, peerA, peerB := dialPair(t)

	done := make(chan spliceStats, 1)
	go func() { done <- spliceConns(relayA, relayB) }()

	// peerA is the requester side, peerB the target side.
	toTarget := bytes.Repeat([]byte("q"), 4096)
	toRequester := bytes.Repeat([]byte("r"), 2480) // the issue's sandbox size

	go func() {
		_, _ = peerA.Write(toTarget)
		if cw, ok := peerA.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		_, _ = peerB.Write(toRequester)
		if cw, ok := peerB.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	gotTarget, err := io.ReadAll(peerB)
	if err != nil {
		t.Fatalf("reading at the target: %v", err)
	}
	gotRequester, err := io.ReadAll(peerA)
	if err != nil {
		t.Fatalf("reading at the requester: %v", err)
	}
	if !bytes.Equal(gotTarget, toTarget) || !bytes.Equal(gotRequester, toRequester) {
		t.Fatalf("relay did not carry both payloads intact (%d/%d to target, %d/%d to requester)",
			len(gotTarget), len(toTarget), len(gotRequester), len(toRequester))
	}

	select {
	case st := <-done:
		if st.ToTarget != int64(len(toTarget)) {
			t.Errorf("ToTarget = %d, want %d", st.ToTarget, len(toTarget))
		}
		if st.ToRequester != int64(len(toRequester)) {
			t.Errorf("ToRequester = %d, want %d", st.ToRequester, len(toRequester))
		}
		if !st.OK() {
			t.Errorf("a relay that carried both payloads reported not-OK: %s", st.Reason())
		}
		if st.Reason() != "eof" {
			t.Errorf("Reason() = %q, want %q", st.Reason(), "eof")
		}
		if st.Duration <= 0 {
			t.Error("Duration was not measured")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("spliceConns did not return")
	}
}

// A relay torn down after a few bytes must be distinguishable from one that
// carried the payload -- that is the whole complaint in issue #42.
func TestSpliceStatsDistinguishesAnEarlyTeardown(t *testing.T) {
	relayA, relayB, peerA, peerB := dialPair(t)

	done := make(chan spliceStats, 1)
	go func() { done <- spliceConns(relayA, relayB) }()

	// The requester sends four bytes and the target hangs up without reading
	// the rest, as a daemon refusing the connection would.
	if _, err := peerA.Write([]byte("abcd")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(peerB, buf); err != nil {
		t.Fatalf("target read: %v", err)
	}
	_ = peerB.Close()
	_ = peerA.Close()

	select {
	case st := <-done:
		if st.ToTarget != 4 {
			t.Errorf("ToTarget = %d, want 4 -- the count is what makes an early teardown visible", st.ToTarget)
		}
		if st.ToRequester != 0 {
			t.Errorf("ToRequester = %d, want 0", st.ToRequester)
		}
		t.Logf("early teardown reported as: ok=%v reason=%q %v", st.OK(), st.Reason(), st.LogArgs())
	case <-time.After(10 * time.Second):
		t.Fatal("spliceConns did not return")
	}
}

// LogArgs is what an operator actually reads; it must carry all four facts the
// issue asks for.
func TestSpliceStatsLogArgs(t *testing.T) {
	st := spliceStats{ToRequester: 2480, ToTarget: 1048576, Duration: 4100 * time.Millisecond}
	args := st.LogArgs()
	want := map[string]bool{"bytes_to_target": false, "bytes_to_requester": false, "duration": false, "reason": false}
	for i := 0; i+1 < len(args); i += 2 {
		k, ok := args[i].(string)
		if !ok {
			t.Fatalf("LogArgs key %d is not a string: %v", i, args[i])
		}
		if _, expected := want[k]; !expected {
			t.Errorf("unexpected key %q", k)
		}
		want[k] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("LogArgs is missing %q", k)
		}
	}
	if st.Reason() != "eof" {
		t.Errorf("a clean relay reads as %q, want %q", st.Reason(), "eof")
	}

	failed := spliceStats{ToTarget: 4, Err: io.ErrUnexpectedEOF, Side: "to target"}
	if failed.OK() {
		t.Error("a relay with a copy error reported OK")
	}
	if failed.Reason() != "to target: "+io.ErrUnexpectedEOF.Error() {
		t.Errorf("Reason() = %q; it must name the side and the error", failed.Reason())
	}

	cut := spliceStats{Truncated: true, Side: "to requester"}
	if cut.OK() {
		t.Error("a truncated relay reported OK")
	}
	if cut.Reason() == "eof" {
		t.Error("a truncated relay reads as a clean eof")
	}
}

// A transport with no CloseWrite -- a yamux stream over a carrier, which has
// Close but not CloseWrite -- cannot tell the far peer the sender has
// finished. The peer waits, the drain grace expires, and the relay truncates.
// The stats must name that, because a 30-second stall with no explanation is
// exactly the kind of silence issue #42 is about.
func TestSpliceStatsNamesATransportThatCannotHalfClose(t *testing.T) {
	st := spliceStats{Truncated: true, NoHalfClose: true, Side: "to target"}
	if st.OK() {
		t.Error("a truncated relay reported OK")
	}
	reason := st.Reason()
	for _, want := range []string{"half-close", "never told"} {
		if !strings.Contains(reason, want) {
			t.Errorf("Reason() = %q; it does not mention %q", reason, want)
		}
	}

	// Without the half-close detail it must still say what happened, just
	// without claiming a cause it does not know.
	plain := spliceStats{Truncated: true, Side: "to target"}
	if strings.Contains(plain.Reason(), "half-close") {
		t.Errorf("Reason() = %q; it blames half-close for a relay where that was not observed", plain.Reason())
	}
}

// A plain TCP relay does support half-close, so nothing should claim otherwise.
func TestSpliceOverTCPReportsHalfCloseWorking(t *testing.T) {
	relayA, relayB, peerA, peerB := dialPair(t)
	done := make(chan spliceStats, 1)
	go func() { done <- spliceConns(relayA, relayB) }()

	_ = peerA.Close()
	_ = peerB.Close()

	select {
	case st := <-done:
		if st.NoHalfClose {
			t.Error("a TCP relay reported that it could not half-close")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("spliceConns did not return")
	}
}

// A truncated relay must name the direction that stalled, not "a direction":
// the point of the line is to send an operator to one side of the relay.
func TestSpliceTruncationNamesTheStalledDirection(t *testing.T) {
	for _, tc := range []struct{ finishedFirst, wantStalled string }{
		{sideToTarget, sideToRequester},
		{sideToRequester, sideToTarget},
	} {
		if got := otherSide(tc.finishedFirst); got != tc.wantStalled {
			t.Errorf("otherSide(%q) = %q, want %q", tc.finishedFirst, got, tc.wantStalled)
		}
	}
	if got := otherSide(""); got != "a direction" {
		t.Errorf("otherSide of an unknown side = %q; it must not name a side it does not know", got)
	}

	st := spliceStats{Truncated: true, Side: sideToTarget}
	if !strings.Contains(st.Reason(), sideToTarget) {
		t.Errorf("Reason() = %q; it does not name the stalled direction", st.Reason())
	}
}

// onePipeListener yields a single connection, so a test can build a carrier
// session without a real network listener.
type onePipeListener struct {
	ch   chan net.Conn
	once sync.Once
}

func (l *onePipeListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (l *onePipeListener) Close() error   { l.once.Do(func() { close(l.ch) }); return nil }
func (l *onePipeListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "pipe" }
func (dummyAddr) String() string  { return "pipe" }

// The relay half-closes a connection only if it satisfies closeWriter. A
// carrier stream did not, so every relay over a carrier left its peer waiting
// for an EOF that never came, until the drain grace expired and truncated the
// transfer. Control traffic survives that; a file transfer does not.
//
// This is the contract between the two packages, which is where the bug lived:
// each side was reasonable on its own.
func TestCarrierStreamSatisfiesTheRelayHalfCloseContract(t *testing.T) {
	pipeA, pipeB := net.Pipe()
	ln := &onePipeListener{ch: make(chan net.Conn, 1)}
	ln.ch <- pipeB
	ml := carrier.NewMuxListener(ln)
	defer func() { _ = ml.Close() }()

	md, err := carrier.NewMuxDialer(pipeA)
	if err != nil {
		t.Fatalf("NewMuxDialer: %v", err)
	}
	defer func() { _ = md.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dialed, err := md.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Opening is lazy on the wire; write so the far side accepts.
	if _, err := dialed.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	accepted, err := ml.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	for name, c := range map[string]net.Conn{"dialed": dialed, "accepted": accepted} {
		if _, ok := c.(closeWriter); !ok {
			t.Errorf("a %s carrier stream (%T) does not satisfy closeWriter, so the relay cannot half-close it", name, c)
		}
	}
}

// A relay whose destination has no ReadFrom -- a yamux stream over a carrier,
// or anything else that is not a plain TCP socket -- must still carry bytes.
//
// This exists because counting them nearly broke it: io.Copy calls dst.ReadFrom
// and returns the result with no fallback, so a counting wrapper that reported
// "unsupported" relayed nothing at all. Every other test here uses dialPair,
// which is TCP on both sides and takes the fast path, so none of them could
// see it.
//
// noReadFrom models the real shape -- a working socket whose ReadFrom is not
// reachable -- rather than net.Pipe, whose lack of buffering and of CloseWrite
// would make the test about net.Pipe instead of about the relay.
func TestSpliceCarriesBytesWithoutAReadFromFastPath(t *testing.T) {
	relayA, relayB, peerA, peerB := dialPair(t)

	if _, ok := any(noReadFrom{relayB}).(io.ReaderFrom); ok {
		t.Fatal("noReadFrom still exposes ReadFrom; the test would take the fast path it means to avoid")
	}

	done := make(chan spliceStats, 1)
	go func() { done <- spliceConns(noReadFrom{relayA}, noReadFrom{relayB}) }()

	toTarget := bytes.Repeat([]byte("Q"), 256<<10)
	toRequester := bytes.Repeat([]byte("R"), 2480)

	go func() {
		_, _ = peerA.Write(toTarget)
		_ = peerA.(interface{ CloseWrite() error }).CloseWrite()
	}()
	go func() {
		_, _ = peerB.Write(toRequester)
		_ = peerB.(interface{ CloseWrite() error }).CloseWrite()
	}()

	var gotTarget, gotRequester []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); gotTarget, _ = io.ReadAll(peerB) }()
	go func() { defer wg.Done(); gotRequester, _ = io.ReadAll(peerA) }()
	wg.Wait()

	if !bytes.Equal(gotTarget, toTarget) {
		t.Errorf("target received %d bytes, want %d -- the relay dropped them", len(gotTarget), len(toTarget))
	}
	if !bytes.Equal(gotRequester, toRequester) {
		t.Errorf("requester received %d bytes, want %d", len(gotRequester), len(toRequester))
	}

	select {
	case st := <-done:
		if st.ToTarget != int64(len(toTarget)) {
			t.Errorf("ToTarget = %d, want %d", st.ToTarget, len(toTarget))
		}
		if st.ToRequester != int64(len(toRequester)) {
			t.Errorf("ToRequester = %d, want %d", st.ToRequester, len(toRequester))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("spliceConns did not return")
	}
}

// noReadFrom hides a connection's ReadFrom while keeping it otherwise intact,
// standing in for a carrier stream. net.Conn carries neither ReadFrom nor
// CloseWrite, so embedding it drops the first (as intended) and the second
// (which has to be put back, or the relay could not half-close).
type noReadFrom struct{ net.Conn }

func (c noReadFrom) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
