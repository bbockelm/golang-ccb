package ccbserver

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/security"
)

// At/above ccb.StreamingMinVersion so the test broker advertises streaming support.
const testStreamingVersion = "$CondorVersion: 25.12.0 2026-06-21 BuildID: test $"

// plaintextSec returns an un-authenticated, un-encrypted security config (for
// in-process tests). encryptionNever keeps the CCB control channel plaintext.
func plaintextSec() *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{},
		Authentication: security.SecurityNever,
		Encryption:     security.SecurityNever,
		Integrity:      security.SecurityNever,
		RemoteVersion:  testStreamingVersion,
	}
}

// startTestServer starts a CCB server on a random localhost port.
func startTestServer(t *testing.T) (addr string, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	srv, err := New(Config{
		PublicAddress:  addr,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return addr, c
}

// startEchoTarget registers a CCB listener whose handler echoes 4 bytes.
func startEchoTarget(t *testing.T, brokerAddr string) (contact string, cancel func()) {
	t.Helper()
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        brokerAddr,
		Security:          plaintextSec(),
		Name:              "echo-target",
		HeartbeatInterval: 30 * time.Second,
		Handler: func(conn net.Conn, _ ccb.InboundMeta) {
			defer conn.Close()
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			_, _ = conn.Write(buf)
		},
	})
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = lis.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if contact = lis.Contact(); contact != "" {
			return contact, c
		}
		time.Sleep(10 * time.Millisecond)
	}
	c()
	t.Fatal("target did not register in time")
	return "", c
}

func contactsFor(t *testing.T, contact string) []addresses.CCBContact {
	t.Helper()
	broker, id, ok := addresses.SplitCCBContact(contact)
	if !ok {
		t.Fatalf("bad contact %q", contact)
	}
	return []addresses.CCBContact{{BrokerAddr: broker, CCBID: id, Raw: contact}}
}

func TestStandardReverseConnect(t *testing.T) {
	brokerAddr, stopSrv := startTestServer(t)
	defer stopSrv()
	contact, stopTgt := startEchoTarget(t, brokerAddr)
	defer stopTgt()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	conn, err := ccb.Dial(ctx, contactsFor(t, contact), ccb.DialOptions{
		Security:   plaintextSec(),
		ListenAddr: "127.0.0.1:0",
		TargetDesc: "echo-target",
		Timeout:    6 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}

func TestStreamingProxyReverseConnect(t *testing.T) {
	brokerAddr, stopSrv := startTestServer(t)
	defer stopSrv()
	contact, stopTgt := startEchoTarget(t, brokerAddr)
	defer stopTgt()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// The requester is "private": advertise a CCB-routed return address so the
	// broker engages proxy mode, and require streaming.
	proxyReturn := "<10.9.8.7:0?ccbid=" + contact + ">"
	conn, err := ccb.Dial(ctx, contactsFor(t, contact), ccb.DialOptions{
		Security:         plaintextSec(),
		ProxyReturnAddr:  proxyReturn,
		RequireStreaming: true,
		TargetDesc:       "echo-target",
		Timeout:          6 * time.Second,
	})
	if err != nil {
		t.Fatalf("proxy Dial: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}

// TestStreamingGateFailsFast verifies a private requester fails fast against a
// broker that does not advertise a streaming-capable version.
func TestStreamingGateFailsFast(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	oldVerSec := plaintextSec()
	oldVerSec.RemoteVersion = "$CondorVersion: 24.0.0 2024-01-01 BuildID: old $"
	srv, err := New(Config{PublicAddress: addr, Security: oldVerSec, RequestTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	defer c()
	go func() { _ = srv.Serve(ctx, ln) }()
	contact, stopTgt := startEchoTarget(t, addr)
	defer stopTgt()

	dctx, dcancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer dcancel()
	_, err = ccb.Dial(dctx, contactsFor(t, contact), ccb.DialOptions{
		Security:         plaintextSec(),
		ProxyReturnAddr:  "<10.9.8.7:0?ccbid=" + contact + ">",
		RequireStreaming: true,
		Timeout:          3 * time.Second,
	})
	var sue *ccb.StreamingUnsupportedError
	if err == nil {
		t.Fatal("expected streaming-unsupported error, got nil")
	}
	if !asStreamingUnsupported(err, &sue) {
		t.Fatalf("expected StreamingUnsupportedError, got %v", err)
	}
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if err := conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err == nil {
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want ping", string(buf))
	}
}

// asStreamingUnsupported reports whether err wraps a *ccb.StreamingUnsupportedError.
// It uses errors.As so it traverses both single (%w) wrapping and the
// errors.Join([]error) that ccb.Dial uses to aggregate per-broker failures.
func asStreamingUnsupported(err error, target **ccb.StreamingUnsupportedError) bool {
	return errors.As(err, target)
}
