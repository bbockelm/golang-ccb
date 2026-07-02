package ccbserver

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/golang-htcondor/authz"
)

// testCfg is a minimal authz.ConfigGetter backed by a map.
type testCfg map[string]string

func (c testCfg) Get(k string) (string, bool) { v, ok := c[k]; return v, ok }

// startTestServerWithAuthz starts a CCB server enforcing the given ALLOW_/DENY_
// configuration.
func startTestServerWithAuthz(t *testing.T, cfg testCfg) (addr string, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	policy, err := authz.NewPolicy(cfg, "CCB")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		PublicAddress:  addr,
		Security:       plaintextSec(),
		Authz:          policy,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return addr, c
}

// TestAuthzAllowsConfiguredPeer verifies the authorization gate does not break
// the happy path: with DAEMON and READ granted, a target registers and a
// requester completes a reverse-connect echo through the broker.
func TestAuthzAllowsConfiguredPeer(t *testing.T) {
	brokerAddr, stopSrv := startTestServerWithAuthz(t, testCfg{
		"ALLOW_DAEMON": "*",
		"ALLOW_READ":   "*",
	})
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

// TestAuthzDeniesRegister verifies that a target whose IP is not permitted at
// the DAEMON (nor any ADVERTISE_*) level cannot register: ALLOW_DAEMON is
// restricted to a subnet that excludes loopback, so the listener never obtains
// a contact.
func TestAuthzDeniesRegister(t *testing.T) {
	brokerAddr, stopSrv := startTestServerWithAuthz(t, testCfg{
		"ALLOW_DAEMON": "10.0.0.0/8", // excludes 127.0.0.1
	})
	defer stopSrv()

	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        brokerAddr,
		Security:          plaintextSec(),
		Name:              "denied-target",
		HeartbeatInterval: 30 * time.Second,
		Handler: func(conn net.Conn) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		},
	})
	ctx, c := context.WithCancel(context.Background())
	defer c()
	go func() { _ = lis.Run(ctx) }()

	// Give the listener time to attempt (and be denied) registration; it must
	// never obtain a contact.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if contact := lis.Contact(); contact != "" {
			t.Fatalf("registration should have been denied, but got contact %q", contact)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
