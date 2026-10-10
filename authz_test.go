package ccbserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
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
		Authorizer:     policy.Authorize,
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
		Handler: func(conn net.Conn, _ ccb.InboundMeta) {
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

// startTestServerWithAuthorizer starts a CCB server whose Authorizer is az.
func startTestServerWithAuthorizer(t *testing.T, az func(perm, peerAddr, user string) bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		PublicAddress:  ln.Addr().String(),
		Security:       plaintextSec(),
		Authorizer:     az,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String()
}

// TestAuthzUnauthenticatedPeer verifies that a peer which did not authenticate
// is authorized as unauthenticated@unmapped -- by the command server and by the
// CCB handlers' own checks alike, never as "" (which an ALLOW_ list treats as
// any user) -- so an ALLOW_ entry naming that identity admits it and one naming
// only an authenticated identity does not.
func TestAuthzUnauthenticatedPeer(t *testing.T) {
	const unauth = cedarserver.UnauthenticatedFQU
	policy, err := authz.NewPolicy(testCfg{
		"ALLOW_DAEMON": unauth + "/127.0.0.1",
		"ALLOW_READ":   unauth,
	}, "CCB")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	users := map[string]int{}
	brokerAddr := startTestServerWithAuthorizer(t, func(perm, peerAddr, user string) bool {
		mu.Lock()
		users[user]++
		mu.Unlock()
		return policy.Authorize(perm, peerAddr, user)
	})
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

	mu.Lock()
	defer mu.Unlock()
	if users[unauth] == 0 {
		t.Errorf("no authorization as %q; got %v", unauth, users)
	}
	for u, n := range users {
		if u != unauth {
			t.Errorf("authorized as %q %d times, want only %q", u, n, unauth)
		}
	}
}

// sendRegister sends one unauthenticated CCB_REGISTER to the broker at addr and
// returns nil if it was assigned a CCBID.
func sendRegister(t *testing.T, addr string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sec := plaintextSec()
	sec.Command = ccb.CommandRegister
	cl, err := client.ConnectAndAuthenticate(ctx, addr, sec)
	if err != nil {
		return err
	}
	defer cl.Close()
	if err := ccb.WriteControlAd(ctx, cl.GetStream(), ccb.NewAd(map[string]any{ccb.AttrName: "probe"})); err != nil {
		return err
	}
	reply, err := ccb.ReadControlAd(ctx, cl.GetStream())
	if err != nil {
		return err
	}
	if ccb.AdString(reply, ccb.AttrCCBID) == "" {
		return fmt.Errorf("register reply has no CCBID: %v", reply)
	}
	return nil
}

// TestAuthzUnauthenticatedPeerNotAdmittedAsUser verifies that an ALLOW_ list
// naming only an authenticated identity refuses a peer that did not
// authenticate (DENIED at the handshake), while one naming
// unauthenticated@unmapped admits it.
func TestAuthzUnauthenticatedPeerNotAdmittedAsUser(t *testing.T) {
	for _, tc := range []struct {
		allow string
		admit bool
	}{
		{"condor@pool/*", false},
		{cedarserver.UnauthenticatedFQU + "/*", true},
	} {
		t.Run(tc.allow, func(t *testing.T) {
			brokerAddr, stopSrv := startTestServerWithAuthz(t, testCfg{"ALLOW_DAEMON": tc.allow})
			defer stopSrv()
			err := sendRegister(t, brokerAddr)
			if tc.admit {
				if err != nil {
					t.Fatalf("register refused: %v", err)
				}
				return
			}
			var ae *security.AuthorizationError
			if !errors.As(err, &ae) || ae.ReturnCode != "DENIED" {
				t.Fatalf("register: got %v, want DENIED", err)
			}
		})
	}
}

// TestRequesterIdentity verifies the audit string names the identity the
// requester is authorized as: its full user@domain if it authenticated, and
// unauthenticated@unmapped otherwise, whatever identity the session records.
func TestRequesterIdentity(t *testing.T) {
	const addr = "192.0.2.7:4321"
	for _, tc := range []struct {
		name string
		neg  *security.SecurityNegotiation
		want string
	}{
		{"raw", nil, "unauthenticated@unmapped at " + addr},
		{"unauthenticated", &security.SecurityNegotiation{}, "unauthenticated@unmapped at " + addr},
		{"unauthenticated with recorded user", &security.SecurityNegotiation{User: "alice@pool"}, "unauthenticated@unmapped at " + addr},
		{"authenticated", &security.SecurityNegotiation{User: "alice@pool", Authentication: true}, "alice@pool at " + addr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &cedarserver.Conn{RemoteAddr: addr, Negotiation: tc.neg}
			if got := requesterIdentity(c); got != tc.want {
				t.Errorf("requesterIdentity = %q, want %q", got, tc.want)
			}
		})
	}
}
