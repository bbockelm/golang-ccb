package ccbserver

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/ccb"
)

func echoHandler(conn net.Conn, _ ccb.InboundMeta) {
	defer conn.Close()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	_, _ = conn.Write(buf)
}

// allContacts converts a listener's contact strings into CCBContacts.
func allContacts(t *testing.T, contacts []string) []addresses.CCBContact {
	t.Helper()
	out := make([]addresses.CCBContact, 0, len(contacts))
	for _, c := range contacts {
		broker, id, ok := addresses.SplitCCBContact(c)
		if !ok {
			t.Fatalf("bad contact %q", c)
		}
		out = append(out, addresses.CCBContact{BrokerAddr: broker, CCBID: id, Raw: c})
	}
	return out
}

func waitRegistered(t *testing.T, lis *ccb.Listener, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if lis.NumRegistered() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener registered with %d brokers, want %d", lis.NumRegistered(), n)
}

// TestMultiBrokerListener registers one target with two CCB servers and
// verifies it gets a contact from each, and is reachable via either.
func TestMultiBrokerListener(t *testing.T) {
	brokerA, stopA := startTestServer(t)
	defer stopA()
	brokerB, stopB := startTestServer(t)
	defer stopB()

	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddrs:       []string{brokerA, brokerB},
		Security:          plaintextSec(),
		Name:              "multi-echo",
		HeartbeatInterval: 30 * time.Second,
		Handler:           echoHandler,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = lis.Run(ctx) }()

	waitRegistered(t, lis, 2)
	contacts := lis.Contacts()
	if len(contacts) != 2 {
		t.Fatalf("got %d contacts, want 2: %v", len(contacts), contacts)
	}

	// Each broker's contact must independently reach the target.
	for i, contact := range contacts {
		dctx, dcancel := context.WithTimeout(context.Background(), 8*time.Second)
		conn, err := ccb.Dial(dctx, allContacts(t, []string{contact}), ccb.DialOptions{
			Security:   plaintextSec(),
			ListenAddr: "127.0.0.1:0",
			Timeout:    6 * time.Second,
		})
		if err != nil {
			dcancel()
			t.Fatalf("dial via broker %d (%s): %v", i, contact, err)
		}
		assertEcho(t, conn)
		conn.Close()
		dcancel()
	}
}

// TestHappyEyeballsAcrossBrokers verifies a requester given both of a target's
// CCB contacts still reaches it when one broker is down, via the other.
func TestHappyEyeballsAcrossBrokers(t *testing.T) {
	brokerA, stopA := startTestServer(t)
	defer stopA()
	brokerB, stopB := startTestServer(t)
	defer stopB()

	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddrs:       []string{brokerA, brokerB},
		Security:          plaintextSec(),
		Name:              "multi-echo",
		HeartbeatInterval: 30 * time.Second,
		Handler:           echoHandler,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = lis.Run(ctx) }()

	waitRegistered(t, lis, 2)
	contacts := allContacts(t, lis.Contacts())

	// Take broker A down. Its contact is now stale; happy-eyeballs must still
	// reach the target through broker B.
	stopA()

	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	start := time.Now()
	conn, err := ccb.Dial(dctx, contacts, ccb.DialOptions{
		Security:   plaintextSec(),
		ListenAddr: "127.0.0.1:0",
		Stagger:    50 * time.Millisecond,
		Timeout:    8 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial with one broker down: %v", err)
	}
	defer conn.Close()
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("dial took %v with one broker down; happy-eyeballs did not fail over promptly", elapsed)
	}
	assertEcho(t, conn)
}
