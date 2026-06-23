package ccbserver

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// fwdSharedPortServer is a minimal real shared-port server for tests: it reads a
// SHARED_PORT_CONNECT request, looks up the target backend by sock id, and
// transparently splices the connection through. This mirrors what HTCondor's
// shared_port server does (byte-forwarding rather than the production fd-pass).
type fwdSharedPortServer struct {
	ln       net.Listener
	backends map[string]string // sock id -> backend "host:port"
}

func startFwdSharedPortServer(t *testing.T, backends map[string]string) *fwdSharedPortServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fwdSharedPortServer{ln: ln, backends: backends}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

func (s *fwdSharedPortServer) addr() string { return s.ln.Addr().String() }
func (s *fwdSharedPortServer) Close()       { _ = s.ln.Close() }

func (s *fwdSharedPortServer) handle(conn net.Conn) {
	ctx := context.Background()
	st := stream.NewStream(conn)
	msg := message.NewMessageFromStream(st)

	// Parse the SHARED_PORT_CONNECT request (consumes exactly that message; the
	// stream does no read-ahead, so the bytes after it remain on conn).
	cmd, err := msg.GetInt32(ctx)
	if err != nil || cmd != int32(commands.SHARED_PORT_CONNECT) {
		conn.Close()
		return
	}
	sock, err := msg.GetString(ctx)
	if err != nil {
		conn.Close()
		return
	}
	if _, err := msg.GetString(ctx); err != nil { // client name
		conn.Close()
		return
	}
	if _, err := msg.GetInt64(ctx); err != nil { // deadline
		conn.Close()
		return
	}
	if _, err := msg.GetInt32(ctx); err != nil { // more_args
		conn.Close()
		return
	}

	backend, ok := s.backends[sock]
	if !ok {
		conn.Close()
		return
	}
	bconn, err := net.Dial("tcp", backend)
	if err != nil {
		conn.Close()
		return
	}
	// Transparent splice in both directions until either side closes.
	go func() { _, _ = io.Copy(bconn, conn); bconn.Close() }()
	_, _ = io.Copy(conn, bconn)
	conn.Close()
}

// TestCCBBehindSharedPort exercises the requester reaching a broker that is only
// reachable through a shared-port server: the CCB advertises a shared-port
// contact ("<sp-addr>?sock=ccb#id"), and ccb.Dial must route the request
// through the shared-port server to the broker, then complete a standard
// reverse-connect to the (reachable) requester.
func TestCCBBehindSharedPort(t *testing.T) {
	// CCB backend listener (the broker's own command socket).
	ccbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ccbAddr := ccbLn.Addr().String()

	// Shared-port server that forwards sock "ccb" to the CCB backend.
	sp := startFwdSharedPortServer(t, map[string]string{"ccb": ccbAddr})
	defer sp.Close()

	// The broker advertises itself via the shared-port server.
	pub := sp.addr() + "?sock=ccb"
	srv, err := New(Config{
		PublicAddress:  pub,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ccbLn)

	// A target registers directly with the CCB backend; its contact carries the
	// shared-port broker address.
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        ccbAddr,
		Security:          plaintextSec(),
		Name:              "sp-echo-target",
		HeartbeatInterval: 30 * time.Second,
		Handler: func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 4)
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			_, _ = c.Write(buf)
		},
	})
	lctx, lcancel := context.WithCancel(context.Background())
	defer lcancel()
	go lis.Run(lctx)

	contact := waitForContact(t, lis)
	broker, _, ok := addresses.SplitCCBContact(contact)
	if !ok || broker != pub {
		t.Fatalf("expected broker %q in contact, got %q", pub, contact)
	}

	// The requester reaches the broker only through the shared-port server.
	dctx, dcancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer dcancel()
	conn, err := ccb.Dial(dctx, contactsFor(t, contact), ccb.DialOptions{
		Security:   plaintextSec(),
		ListenAddr: "127.0.0.1:0",
		TargetDesc: "sp-echo-target",
		Timeout:    6 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial via shared-port broker: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}
