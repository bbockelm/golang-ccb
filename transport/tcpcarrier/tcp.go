// Package tcpcarrier carries CCB tunnel pipes over plain TCP: one TCP
// connection is one carrier byte pipe, with yamux layered on top by
// transport/carrier exactly as for every other carrier.
//
// It exists because a relayed carrier needs somewhere to land. `ssh -W
// broker:9700 bastion` hands the inside broker a byte stream and nothing of
// ours runs on the bastion, so the outside broker must accept a bare pipe --
// which its CEDAR port cannot do, since that port expects one CEDAR connection
// per socket, not a multiplexed carrier. The same endpoint is what an `ssh -L`
// forward, a kubectl port-forward or socat delivers.
//
// It is also the simplest carrier there is, which makes it the right fixture
// for testing everything layered above a pipe.
//
// # Security
//
// A tcp:// carrier authenticates nobody. That is the same posture as a
// WebSocket carrier in CCB_CARRIER_AUTH = none mode, and rests on the same
// argument (docs/CARRIER_AUTH.md §6): the identity every authorization decision
// uses comes from the CEDAR handshake on the first command, not from the
// transport. What the transport must still do is bound what an unauthenticated
// peer can consume, which is carrier.LimitListener plus MuxListener's
// first-stream probation.
//
// The difference from the WebSocket carrier is that there is no TLS, so this
// endpoint belongs inside something that provides confidentiality -- an SSH
// tunnel, a VPN, a loopback address -- and not on the open internet. Listen says
// so when the bind address is not loopback.
package tcpcarrier

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/bbockelm/golang-ccb/transport/carrier"
)

// ListenConfig configures the acceptor side.
type ListenConfig struct {
	// Addr is the bind address, "host:port" ("127.0.0.1:9700", ":9700").
	Addr string
	// MaxSessions caps concurrently-held pipes; zero uses the carrier default.
	MaxSessions int
	// MaxPerSource caps pipes from one peer address; zero disables the cap,
	// which is right when several inside brokers share one relay host.
	MaxPerSource int
	// Logger receives accept-path warnings.
	Logger *slog.Logger
}

// Listen accepts carrier pipes on cfg.Addr.
func Listen(cfg ListenConfig) (net.Listener, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("tcpcarrier: listening on %q: %w", cfg.Addr, err)
	}
	if !isLoopback(ln.Addr()) {
		log.Warn("the tcp:// carrier is listening beyond loopback: it offers no TLS and no transport credential, so put it behind an SSH tunnel, a VPN or a firewall rather than on a public address",
			"addr", ln.Addr().String())
	}
	return carrier.NewLimitListener(ln, log, cfg.MaxSessions, cfg.MaxPerSource), nil
}

// Dial establishes one carrier pipe to a tcpcarrier listener.
func Dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcpcarrier: dialing %q: %w", addr, err)
	}
	return c, nil
}

// isLoopback reports whether every address the listener answers on is a
// loopback address. A wildcard bind ("[::]:9700") is not.
func isLoopback(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
