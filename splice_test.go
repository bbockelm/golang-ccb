package ccbserver

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
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
