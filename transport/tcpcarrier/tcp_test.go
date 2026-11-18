package tcpcarrier

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialAndListenCarryBytes(t *testing.T) {
	ln, err := Listen(ListenConfig{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = server.Close() }()

	want := []byte("carrier pipe")
	go func() { _, _ = client.Write(want) }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The endpoint has no TLS and no transport credential, so an operator who binds
// it beyond loopback has to be told: the argument for accepting an
// unauthenticated carrier rests on it being inside something else (an SSH
// tunnel, a VPN), and nothing in the config says whether it is.
func TestListenWarnsBeyondLoopback(t *testing.T) {
	for _, tc := range []struct {
		name, addr string
		wantWarn   bool
	}{
		{"loopback is silent", "127.0.0.1:0", false},
		{"wildcard warns", "0.0.0.0:0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			log := slog.New(slog.NewTextHandler(&buf, nil))
			ln, err := Listen(ListenConfig{Addr: tc.addr, Logger: log})
			if err != nil {
				t.Fatalf("Listen(%q): %v", tc.addr, err)
			}
			defer func() { _ = ln.Close() }()
			warned := strings.Contains(buf.String(), "beyond loopback")
			if warned != tc.wantWarn {
				t.Errorf("Listen(%q) warned=%v, want %v (log: %s)", tc.addr, warned, tc.wantWarn, buf.String())
			}
		})
	}
}

func TestListenReportsABadAddress(t *testing.T) {
	if _, err := Listen(ListenConfig{Addr: "definitely not an address"}); err == nil {
		t.Fatal("Listen accepted a malformed address")
	}
}

func TestDialReportsARefusedConnection(t *testing.T) {
	// Bind and release, so the port is almost certainly closed.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := Dial(ctx, addr); err == nil {
		t.Fatal("Dial to a closed port returned no error")
	} else if !strings.Contains(err.Error(), "tcpcarrier") {
		t.Errorf("error %q does not name the carrier", err)
	}
}
