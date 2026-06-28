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
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sessioncache"
	"github.com/bbockelm/golang-htcondor/sessioncache/sqlite"

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

	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Session-cache persistence is built before the daemon so the daemon can
	// restore it (into the global CEDAR session cache) during New, before
	// serving. The caller owns Close.
	sessionStore, err := buildSessionStore(cfg)
	if err != nil {
		return err
	}
	if sessionStore != nil {
		defer sessionStore.Close()
	}

	// Bootstrap logging and condor_master integration; restores the session
	// cache when sessionStore is set.
	d, err := daemon.New(daemon.Options{Subsys: "CCB", Config: cfg, SessionStore: sessionStore})
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
		} else if sinful, ok := d.AdvertisedSinful(); ok {
			// A shared-port (Unix socket) listener has no routable address of
			// its own; advertise the broker's shared-port command sinful
			// (the shared-port server host:port routed to our sock id).
			pub = sinful
			log.Info(logging.DestinationGeneral, "advertising shared-port CCB contact",
				"address", pub, "sock", d.SharedPortName())
		} else {
			return fmt.Errorf("running behind shared port but could not derive an advertised address; pass -public <host:port?sock=name>")
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

	// Reconnect persistence: when CCB_RECONNECT_FILE is configured, registered
	// targets keep their CCBID (and advertised sinful) across drops and broker
	// restarts. The SQLite store batches writes (~50ms) so a burst of
	// registrations does not fsync per connection.
	var store ccbserver.ReconnectStore
	if path, ok := d.Config().Get("CCB_RECONNECT_FILE"); ok && path != "" {
		store, err = ccbserver.OpenSQLiteReconnectStore(path, 50*time.Millisecond, d.Slog())
		if err != nil {
			return fmt.Errorf("opening reconnect store: %w", err)
		}
		defer store.Close()
		log.Info(logging.DestinationGeneral, "ccb reconnect persistence enabled", "file", path)
	}

	srv, err := ccbserver.New(ccbserver.Config{
		PublicAddress:       pub,
		Security:            sec,
		Authz:               policy,
		ReconnectStore:      store,
		ReconnectAllowAnyIP: configBool(d.Config(), "CCB_RECONNECT_ALLOWED_FROM_ANY_IP", false),
		Logger:              d.Slog(),
	})
	if err != nil {
		return fmt.Errorf("creating CCB server: %w", err)
	}

	log.Info(logging.DestinationGeneral, "golang-ccb starting",
		"public", pub, "listen", ln.Addr().String(), "under_master", d.UnderMaster())

	return d.Serve(context.Background(), ln, srv.Serve)
}

// buildSessionStore constructs the encrypted session-cache store when
// CCB_SESSION_CACHE_FILE is configured, wrapping its DEK under the pool signing
// keys. Returns (nil, nil) when persistence is not enabled.
func buildSessionStore(cfg *config.Config) (sessioncache.SessionStore, error) {
	path, ok := cfg.Get("CCB_SESSION_CACHE_FILE")
	if !ok || path == "" {
		return nil, nil
	}
	keyMap, err := htcondor.LoadSigningKeys(cfg)
	if err != nil {
		return nil, fmt.Errorf("loading signing keys for session cache: %w", err)
	}
	keys := make([]sqlite.SigningKey, 0, len(keyMap))
	for id, material := range keyMap {
		keys = append(keys, sqlite.SigningKey{ID: id, Material: material})
	}
	store, err := sqlite.Open(path, keys, slog.Default())
	if err != nil {
		return nil, fmt.Errorf("opening session cache store: %w", err)
	}
	slog.Default().Info("ccb session cache persistence enabled", "file", path, "signing_keys", len(keys))
	return store, nil
}

// configBool reads an HTCondor-style boolean knob, returning def if unset or
// unrecognized.
func configBool(cfg interface{ Get(string) (string, bool) }, key string, def bool) bool {
	v, ok := cfg.Get(key)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "t", "yes", "y", "1":
		return true
	case "false", "f", "no", "n", "0":
		return false
	}
	return def
}
