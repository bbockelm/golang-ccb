// Command htc-ccb-splice is the far end of a CCB carrier, as a byte relay.
//
// It accepts local TCP connections and copies each onto its own stream of the
// carrier it was started with. That is all it does. It speaks no CEDAR, parses
// no ClassAds, reads no HTCondor configuration and holds no credentials: every
// daemon that reaches it runs one end-to-end CEDAR session with the outside
// broker, which is where authentication and authorization happen.
//
// It is meant to be staged onto a host and run over an SSH session, so the
// carrier is its own stdin and stdout. Being a relay rather than a broker is
// what makes that cheap -- nothing has to be configured on the far host, and a
// compromise of this binary yields a pipe, not a broker identity.
//
// Contrast an inside CCB (htc-ccb at the far end of a cmd: carrier, or
// -carrier-stdio): a real broker that terminates CEDAR, enforces HTCondor's
// authorization policy and needs a configuration of its own on that host. It
// is still the right far end where you want the authorization boundary near
// the daemons; this is the right one where you are staging onto a host rather
// than administering it. See docs/SPLICE_HELPER.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/bbockelm/golang-ccb/transport/cmdcarrier"
	"github.com/bbockelm/golang-ccb/transport/splice"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "htc-ccb-splice:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", defaultListen(),
		"local address daemons on this host reach this helper at. It is the address they put in their CCB configuration, and the only one they need. CCB_SPLICE_LISTEN sets it, which is how a staged helper is told.")
	verbose := flag.Bool("v", false, "log each relayed connection")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	// Logs go to stderr: stdout is the carrier, and a stray line written there
	// would be framed as yamux and kill the session.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("stdin is a terminal, so there is no carrier to the outside CCB; " +
			"this command is started by an outside broker over a transport that gives it a pipe, " +
			"typically `ssh host htc-ccb-splice`, and is not run interactively")
	}
	pipe, err := cmdcarrier.Stdio(log)
	if err != nil {
		return err
	}

	h, err := splice.Start(splice.Config{Listen: *listen, Pipe: pipe, Log: log})
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err = h.Serve(ctx)
	if errors.Is(err, context.Canceled) {
		log.Info("shutting down")
		return nil
	}
	return err
}

// defaultListen prefers the staged configuration. A helper crosses an SSH
// session with `env -i`, so an environment variable is how the broker that
// started it passes anything at all.
func defaultListen() string {
	if v := os.Getenv("CCB_SPLICE_LISTEN"); v != "" {
		return v
	}
	// Loopback by default: the common case is daemons on this same host, and a
	// wildcard bind would offer the pool's inside to anything that can route
	// here. A helper serving other hosts is told so explicitly.
	return "127.0.0.1:9618"
}
