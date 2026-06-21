// Command golang-ccb runs an HTCondor Condor Connection Broker (CCB) server as
// a Go daemon. It is intended to behave like the CCB embedded in the
// condor_collector: it loads its policy from the HTCondor configuration, runs
// under condor_master (DC_SET_READY / DC_CHILDALIVE), and accepts connections
// either on a shared-port endpoint inherited from the master or on a TCP socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"

	ccbserver "github.com/bbockelm/golang-ccb"
)

// streamingVersionString advertises a CondorVersion at or above the streaming
// support threshold so streaming-capable requesters proceed.
const streamingVersionString = "$CondorVersion: 25.12.0 2026-06-21 BuildID: golang-ccb GitSHA: dev $"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "golang-ccb:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":9618", "fallback TCP listen address when not inheriting a shared-port endpoint")
	public := flag.String("public", "", "public address advertised in CCB contacts (host:port); defaults to the TCP listen address")
	flag.Parse()

	// Bootstrap config, logging, and condor_master integration.
	d, err := daemon.New(daemon.Options{Subsys: "CCB"})
	if err != nil {
		return err
	}
	log := d.Logger()

	// Command-socket listener: the shared-port endpoint inherited from
	// condor_master if present, otherwise a plain TCP bind.
	ln, err := d.Listener(func() (net.Listener, error) {
		return net.Listen("tcp", *listen)
	})
	if err != nil {
		return err
	}
	defer ln.Close()

	// Address advertised inside CCB contact strings ("<public>#<id>").
	pub := *public
	if pub == "" {
		if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
			pub = tcp.String()
		} else {
			// A shared-port (Unix socket) listener has no routable address of
			// its own; the advertised contact must be the broker's command
			// sinful. TODO: derive it from the collector address + sock id.
			return fmt.Errorf("running behind shared port: pass -public <host:port> (the broker's advertised address)")
		}
	}

	// Server security policy from the HTCondor configuration (SEC_* knobs), so
	// this broker authenticates clients with the same policy and keys as the
	// collector's CCB: GetServerSecurityConfig loads the server-side credentials
	// (SSL server cert/key, token signing keys, trust domain) needed to *verify*
	// presented authentications. CCB sessions are authenticated but NOT
	// encrypted: the proxy splices bytes, and the two real peers run their own
	// end-to-end CEDAR security over the relay.
	//
	sec, err := htcondor.GetServerSecurityConfig(d.Config(), ccb.CommandRegister, "DAEMON")
	if err != nil {
		return fmt.Errorf("building security config: %w", err)
	}
	sec.Encryption = security.SecurityNever
	sec.RemoteVersion = streamingVersionString

	// Per-command authorization from the HTCondor ALLOW_/DENY_ knobs, so a peer
	// that authenticates must also be authorized for CCB_REGISTER (DAEMON) /
	// CCB_REQUEST (READ), exactly like the collector's CCB.
	policy, err := authz.NewPolicy(d.Config(), "CCB")
	if err != nil {
		return fmt.Errorf("building authorization policy: %w", err)
	}

	srv, err := ccbserver.New(ccbserver.Config{
		PublicAddress: pub,
		Security:      sec,
		Authz:         policy,
		Logger:        d.Slog(),
	})
	if err != nil {
		return fmt.Errorf("creating CCB server: %w", err)
	}

	log.Info(logging.DestinationGeneral, "golang-ccb starting",
		"public", pub, "listen", ln.Addr().String(), "under_master", d.UnderMaster())

	return d.Serve(context.Background(), ln, srv.Serve)
}
