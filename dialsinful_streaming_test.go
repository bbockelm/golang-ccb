package ccbserver

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// logCatcher is a slog.Handler that records log messages so a test can assert
// the broker actually established a streaming splice (rather than inferring it
// from configuration).
type logCatcher struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logCatcher) Enabled(context.Context, slog.Level) bool { return true }
func (l *logCatcher) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	l.msgs = append(l.msgs, r.Message)
	l.mu.Unlock()
	return nil
}
func (l *logCatcher) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logCatcher) WithGroup(string) slog.Handler       { return l }

func (l *logCatcher) saw(msg string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.msgs {
		if m == msg {
			return true
		}
	}
	return false
}

// startTestServerWithLog starts a CCB broker whose operational logs are captured
// by the returned recorder.
func startTestServerWithLog(t *testing.T) (addr string, rec *logCatcher, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	rec = &logCatcher{}
	srv, err := New(Config{
		PublicAddress:  addr,
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		Logger:         slog.New(rec),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go srv.Serve(ctx, ln)
	return addr, rec, c
}

// startCedarTarget registers a CCB listener whose reverse-connected sockets are
// served by a real CEDAR command server handling DC_NOP. Unlike the raw-echo
// target used elsewhere, this exercises a full DC_AUTHENTICATE handshake over
// the relay, so a successful DC_NOP dispatch proves the end-to-end CEDAR
// security ran through the broker's byte splice. The handler signals served.
func startCedarTarget(t *testing.T, brokerAddr string, served chan<- struct{}) (contact string, cancel func()) {
	t.Helper()
	srv := cedarserver.New(plaintextSec())
	srv.Handle(commands.DC_NOP, func(ctx context.Context, c *cedarserver.Conn) error {
		select {
		case served <- struct{}{}:
		default:
		}
		return nil
	})

	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        brokerAddr,
		Security:          plaintextSec(),
		Name:              "cedar-target",
		HeartbeatInterval: 30 * time.Second,
		Handler: func(conn net.Conn) {
			// ServeConn takes ownership of (and closes) the spliced connection.
			_ = srv.ServeConn(context.Background(), conn)
		},
	})
	ctx, c := context.WithCancel(context.Background())
	go lis.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if contact = lis.Contact(); contact != "" {
			return contact, c
		}
		time.Sleep(10 * time.Millisecond)
	}
	c()
	t.Fatal("cedar target did not register in time")
	return "", c
}

// TestDialSinfulStreaming drives the real top-level client entry point
// (htcondor.DialSinful) through the broker in streaming/proxy mode: a private
// requester (its own return address is CCB-routed, streaming required) reaches a
// private CEDAR-server target. Success is verified end-to-end and from the
// broker's own log, never inferred from configuration:
//   - DialSinful must authenticate (the DC_AUTHENTICATE handshake bytes flow
//     both ways through the broker's splice),
//   - the target's DC_NOP handler must run (the command dispatched through the
//     relay), and
//   - the broker must log that it established a proxy splice.
func TestDialSinfulStreaming(t *testing.T) {
	brokerAddr, rec, stopSrv := startTestServerWithLog(t)
	defer stopSrv()

	served := make(chan struct{}, 1)
	contact, stopTgt := startCedarTarget(t, brokerAddr, served)
	defer stopTgt()

	// The target's sinful carries the broker contact as its ccbid, so the client
	// routes via CCB. The requester advertises its own CCB-routed return address
	// and requires streaming, so the broker must proxy (private-to-private).
	targetSinful := "<10.9.8.7:0?ccbid=" + contact + ">"
	myReturn := "<10.9.8.6:0?ccbid=" + contact + ">"

	sec := plaintextSec()
	sec.Command = commands.DC_NOP

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cl, err := htcondor.DialSinful(ctx, targetSinful, sec, &htcondor.DialOptions{
		CCBReturnAddr:       myReturn,
		CCBRequireStreaming: true,
		Timeout:             8 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialSinful (streaming): %v", err)
	}
	defer cl.Close()

	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("target DC_NOP handler did not run; command did not dispatch through the streaming relay")
	}

	if !rec.saw("proxy splice established") {
		t.Fatal("broker did not log a streaming proxy splice")
	}
}
