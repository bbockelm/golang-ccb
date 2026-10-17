// Command golang-ccb runs an HTCondor Condor Connection Broker (CCB) server as
// a Go daemon. It is intended to behave like the CCB embedded in the
// condor_collector: it loads its policy from the HTCondor configuration, runs
// under condor_master (DC_SET_READY / DC_CHILDALIVE), and accepts connections
// either on a shared-port endpoint inherited from the master or on a TCP socket.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sessioncache"
	"github.com/bbockelm/golang-htcondor/sessioncache/sqlite"

	ccbserver "github.com/bbockelm/golang-ccb"
)

// streamingVersionString advertises a CondorVersion at or above the streaming
// support threshold so streaming-capable requesters proceed.
//
// Derived from cedar's own ccb.StreamingMinVersion rather than written out.
// A hardcoded version silently falls below the gate the moment cedar raises
// it, and the symptom is remote: nested routing fails with "entry broker does
// not support streaming" even though this broker implements it. That is
// exactly what a literal 25.12.0 did when cedar moved the minimum to 25.13.0.
var streamingVersionString = fmt.Sprintf(
	"$CondorVersion: %s 2026-06-21 BuildID: golang-ccb GitSHA: dev $",
	ccb.StreamingMinVersion,
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "golang-ccb:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":9618", "public TCP listen address for CCB contacts; when running under condor_master it is bound IN ADDITION to the inherited command socket, otherwise it is the sole command port")
	public := flag.String("public", "", "public address advertised in CCB contacts (host:port); defaults to the TCP listen address")
	// condor_master appends these standard DaemonCore flags when it launches a
	// daemon that is not in its built-in list (see masterDaemon.cpp); accept them
	// so flag.Parse() does not reject our launch. -local-name additionally scopes
	// config lookups (CCB.<key> / <local-name>.<key> beat the bare key).
	localName := flag.String("local-name", "", "HTCondor subsystem local-name; passed by condor_master. Used as a config-lookup prefix.")
	_ = flag.String("sock", "", "HTCondor shared-port endpoint name; passed by condor_master. Accepted for compatibility; the endpoint fd is inherited via CONDOR_INHERIT.")
	flag.Parse()

	// Did the operator explicitly set -listen? Only then do we bind it as an extra public
	// port alongside an inherited command socket; left at its default we preserve the
	// pre-existing behavior (advertise the shared-port sinful, bind no extra TCP port) so a
	// pure shared-port deployment does not collide with the shared-port server's own port.
	listenExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "listen" {
			listenExplicit = true
		}
	})

	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "CCB", LocalName: *localName})
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Bootstrap logging and condor_master integration. New drops privileges to
	// the condor user (when started as root), so anything opened after this owns
	// its files as condor.
	d, err := daemon.New(daemon.Options{Subsys: "CCB", Config: cfg})
	if err != nil {
		return err
	}
	log := d.Logger()
	// Route the cedar security/server package's slog output to the daemon log so
	// handshake diagnostics land in CcbLog rather than a discarded stderr.
	slog.SetDefault(d.Slog())

	// Session-cache persistence: open the store *after* New so its database file
	// is condor-owned (not root-owned), then restore + arrange snapshots. The
	// signing keys it reads are root-owned and loaded as root via droppriv.
	//
	// The session cache is advisory — it only lets clients resume sessions across
	// a restart. If it cannot be opened or restored (missing signing keys,
	// unwritable path, ...), log and run without it rather than refusing to start.
	// sharedStore, when the session cache is a shared SQLite database, lets the
	// CCB reconnect store persist into the *same* physical file, encrypted under
	// the same key (see the reconnect wiring below).
	var sharedStore sqlite.SharedStore
	if sessionStore, err := buildSessionStore(cfg); err != nil {
		log.Warn(logging.DestinationGeneral, "session-cache persistence unavailable; continuing without it", "error", err)
	} else if sessionStore != nil {
		defer sessionStore.Close()
		if err := d.EnableSessionPersistence(sessionStore, 0); err != nil {
			log.Warn(logging.DestinationGeneral, "restoring the session cache failed; continuing without restored sessions", "error", err)
		}
		if ss, ok := sessionStore.(sqlite.SharedStore); ok {
			sharedStore = ss
		}
	}

	// Command-socket listener: the shared-port endpoint (or pre-created command socket,
	// issue #119) inherited from condor_master if present, otherwise a plain TCP bind of
	// -listen.
	ln, err := d.Listener(func() (net.Listener, error) {
		return net.Listen("tcp", *listen)
	})
	if err != nil {
		return err
	}
	defer ln.Close()
	lns := []net.Listener{ln}

	// A CCB advertises a directly-dialable public address that external EPs and clients
	// connect to (the "<public>#<id>" in CCB contacts). Under condor_master the inherited
	// socket is the pool-managed command port -- typically a shared-port Unix socket with no
	// routable address of its own -- so we ALSO bind the -listen TCP port and serve the
	// broker on both: the inherited socket carries managed DC traffic, the public TCP port
	// carries CCB contacts. Standalone, ln already IS the -listen bind, so we do not bind it
	// twice (that would EADDRINUSE).
	directLn := ln
	if d.AdoptedInheritedListener() && listenExplicit {
		pubLn, err := net.Listen("tcp", *listen)
		if err != nil {
			return fmt.Errorf("binding public CCB port %q: %w", *listen, err)
		}
		defer pubLn.Close()
		lns = append(lns, pubLn)
		directLn = pubLn
		log.Info(logging.DestinationGeneral, "listening on both the inherited command socket and the public CCB port",
			"inherited", ln.Addr().String(), "public", pubLn.Addr().String())
	}

	// Address advertised inside CCB contact strings ("<public>#<id>").
	pub := *public
	if pub == "" {
		if tcp, ok := directLn.Addr().(*net.TCPAddr); ok {
			pub = tcp.String()
			// A wildcard bind (0.0.0.0 / ::) is not a routable contact address; EPs cannot
			// dial it. Warn so the operator supplies -public (or TCP_FORWARDING_HOST).
			if tcp.IP == nil || tcp.IP.IsUnspecified() {
				log.Warn(logging.DestinationGeneral,
					"advertising a wildcard CCB address; external peers cannot dial it -- pass -public <routable-host:port>",
					"address", pub)
			}
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
	// presented authentications; d.ServerSecurityConfig adds this daemon's
	// shared-port id, which an HTCondor 25.14+ FS client's channel binding names.
	// This is the policy of a command registered at no level; newBroker has
	// every other command negotiate under its own level's SEC_<level>_*, as the
	// collector's CCB does (CCB_REGISTER at DAEMON, CCB_REQUEST at READ). A
	// relayed connection is spliced as raw sockets after the broker's reply, so
	// the broker session's crypto never touches the relayed bytes; the two real
	// peers run their own end-to-end CEDAR security over the relay.
	sec, err := d.ServerSecurityConfig(ccb.CommandRegister, "DAEMON")
	if err != nil {
		return fmt.Errorf("building security config: %w", err)
	}
	sec.RemoteVersion = streamingVersionString

	// Reload the server's credentials (signing keys, SSL key/cert) on SIGHUP, the
	// HTCondor reconfigure convention, so a rotated key or renewed certificate is
	// picked up without a restart.
	if rl, ok := sec.Credentials.(htcondor.CredentialReloader); ok {
		d.OnReconfig(func(*config.Config) { rl.Reload() })
	}

	// Reconnect persistence lives in the *same* physical SQLite file as the
	// session cache (CCB_SESSION_CACHE_FILE), encrypted at rest under the same
	// key: registered targets keep their CCBID (and advertised sinful) across
	// drops and broker restarts. The store batches writes (~50ms) so a burst of
	// registrations does not fsync per connection. Without a shared session
	// database, reconnect state lives only for the process lifetime.
	var store ccbserver.ReconnectStore
	if sharedStore != nil {
		store, err = ccbserver.OpenSharedReconnectStore(
			sharedStore.SharedDB(), sharedStore.Seal, sharedStore.Unseal,
			50*time.Millisecond, d.Slog())
		if err != nil {
			return fmt.Errorf("opening reconnect store: %w", err)
		}
		defer store.Close()
		sessionFile, _ := d.Config().Get("CCB_SESSION_CACHE_FILE")
		log.Info(logging.DestinationGeneral, "ccb reconnect persistence enabled (shared, encrypted)", "file", sessionFile)
	}

	// Outbound-proxy (exit) mode: enable the CCB_PROXY_CONNECT handler and its
	// deny-by-default target allow-list from config. The exit dials targets
	// directly, so it needs no CCB client credentials.
	outboundProxy := configBool(d.Config(), "CCB_OUTBOUND_PROXY", false)
	var outboundAllowlist []string
	if v, ok := d.Config().Get("CCB_OUTBOUND_TARGET_ALLOWLIST"); ok {
		outboundAllowlist = ccb.SplitBrokerList(v)
	}

	// Inside-CCB roles: when CCB_OUTBOUND_NEXT_HOP is set this broker forwards
	// outbound proxy requests to that next hop AND registers upstream with it for
	// inbound tunneling (§5). Both make this broker a CCB *client* of the next hop,
	// so build a client-side security config (this daemon's own credentials)
	// under SEC_CLIENT_*, as an HTCondor daemon's CCB client does.
	var outboundNextHop string
	var nextHopSec *security.SecurityConfig
	var upstream *ccbserver.UpstreamConfig
	if hop, ok := d.Config().Get("CCB_OUTBOUND_NEXT_HOP"); ok && hop != "" {
		outboundNextHop = hop
		nextHopSec, err = htcondor.GetSecurityConfig(d.Config(), ccb.CommandRegister, "CLIENT")
		if err != nil {
			return fmt.Errorf("building next-hop client security config: %w", err)
		}
		nextHopSec.RemoteVersion = streamingVersionString
		readyFile, _ := d.Config().Get("CCB_TUNNEL_READY_FILE")
		upstream = &ccbserver.UpstreamConfig{
			BrokerAddr: hop,
			Security:   nextHopSec,
			ReadyFile:  readyFile,
		}
		log.Info(logging.DestinationGeneral, "inside CCB: tunneling through next hop",
			"next_hop", hop, "ready_file", readyFile)
	}

	// Non-TCP carrier wiring (see docs/TRANSPORTS.md). CCB_CARRIER_LISTEN makes
	// this (outside) CCB accept inside CCBs over a filesystem ("fs:<dir>") or
	// WebSocket ("ws://" / "wss://") carrier; a ws/wss Upstream/next-hop makes
	// this (inside) CCB dial one.
	cc, err := buildCarrierSettings(d.Config(), sec, outboundNextHop, upstream, d.Slog())
	if err != nil {
		return err
	}
	if cc.sciTokens != nil {
		d.OnReconfig(cc.sciTokens.load)
	}
	if isWSCarrier(cc.listen) {
		log.Info(logging.DestinationGeneral, "CCB carrier listener enabled", "carrier", cc.listen)
	}

	// CCB_DIAL_REFUSE_LOCAL_ADDRESSES refuses loopback and link-local
	// destinations in the reverse connects a requester's address directs (the
	// outbound proxy refuses them regardless).
	var dialControl func(network, address string, c syscall.RawConn) error
	if configBool(d.Config(), "CCB_DIAL_REFUSE_LOCAL_ADDRESSES", false) {
		dialControl = ccbserver.RefuseLocalAddresses
	}

	srv, az, err := newBroker(d, ccbserver.Config{
		PublicAddress:           pub,
		Security:                sec,
		ReconnectStore:          store,
		ReconnectAllowAnyIP:     configBool(d.Config(), "CCB_RECONNECT_ALLOWED_FROM_ANY_IP", false),
		OutboundProxy:           outboundProxy,
		OutboundTargetAllowlist: outboundAllowlist,
		OutboundNextHop:         outboundNextHop,
		OutboundNextHopSecurity: nextHopSec,
		Upstream:                upstream,
		CarrierListen:           cc.listen,
		CarrierTLS:              cc.tls,
		CarrierTokenVerify:      cc.verify,
		CarrierClientTLS:        cc.clientTLS,
		CarrierToken:            cc.token,
		CarrierTokenSource:      cc.tokenSource,
		DialControl:             dialControl,
		Logger:                  d.Slog(),
	})
	if err != nil {
		return err
	}

	log.Info(logging.DestinationGeneral, "golang-ccb starting",
		"public", pub, "listen", ln.Addr().String(), "listeners", len(lns), "under_master", d.UnderMaster())

	return serveBroker(context.Background(), d, srv, az, lns...)
}

// newBroker creates the CCB server with the daemon's ALLOW_/DENY_ policy and
// the DaemonCore commands (DC_NOP*, DC_RECONFIG, DC_OFF*) on its command
// socket. A peer must be authorized for the command it sends -- CCB_REGISTER
// (DAEMON or ADVERTISE_*) / CCB_REQUEST (READ), like the collector's CCB. The
// policy is rebuilt on every reconfig and has the holes C++ DaemonCore punches
// (condor_master's family session among them); the server consults it for
// every command, so a reload applies to the next one.
//
// Each command negotiates under the security policy of the first level it is
// registered at (d.InstallSecurityLevels), as DaemonCore does: CCB_REGISTER
// under SEC_DAEMON_*, CCB_REQUEST under SEC_READ_*, DC_RECONFIG under
// SEC_ADMINISTRATOR_*. Every level's policy advertises cfg.Security's
// RemoteVersion, which requesters gate streaming and outbound mode on.
func newBroker(d *daemon.Daemon, cfg ccbserver.Config) (*ccbserver.Server, *daemon.Authz, error) {
	az, err := d.NewAuthz(daemon.AuthzOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("building authorization policy: %w", err)
	}
	cfg.Authorizer = az.Authorize
	srv, err := ccbserver.New(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CCB server: %w", err)
	}
	cs := srv.CommandServer()
	d.RegisterDefaultCommands(cs)
	if err := d.InstallSecurityLevels(cs); err != nil {
		return nil, nil, fmt.Errorf("building per-level security policy: %w", err)
	}
	advertiseVersion(cs, cfg.Security.RemoteVersion)
	return srv, az, nil
}

// advertiseVersion makes every per-command policy cs selects advertise version
// as its RemoteVersion. The per-level policies are built from the
// configuration, which does not carry this broker's version.
func advertiseVersion(cs *cedarserver.Server, version string) {
	forCommand := cs.SecurityConfigForCommand
	if forCommand == nil || version == "" {
		return
	}
	cs.SecurityConfigForCommand = func(command int) *security.SecurityConfig {
		sc := forCommand(command)
		if sc == nil {
			return nil
		}
		c := *sc
		c.RemoteVersion = version
		return &c
	}
}

// serveBroker starts srv's background work and serves its command socket on
// every listener until d shuts down, logging each command the policy refuses.
func serveBroker(ctx context.Context, d *daemon.Daemon, srv *ccbserver.Server, az *daemon.Authz, lns ...net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv.StartBackground(ctx)
	return d.ServeListeners(ctx, az.Serve(srv.CommandServer(), d.Slog()), lns...)
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

// isWSCarrier reports whether addr names a WebSocket carrier (ws:// or wss://).
func isWSCarrier(addr string) bool {
	return strings.HasPrefix(addr, "ws://") || strings.HasPrefix(addr, "wss://")
}

// carrierSettings holds the resolved non-TCP carrier configuration for the CCB.
type carrierSettings struct {
	listen      string
	tls         *tls.Config
	verify      func(context.Context, string) (string, error)
	clientTLS   *tls.Config
	token       string
	tokenSource func(context.Context) (string, error)
	// sciTokens is the SciToken map file behind verify, reloaded on reconfig;
	// nil when there is no ws/wss listener.
	sciTokens *sciTokenMap
}

// buildCarrierSettings resolves the carrier knobs from config: the listener side
// (CCB_CARRIER_LISTEN + TLS + token verification for a ws/wss listener) and the
// client side (bearer token + CA for dialing a ws/wss upstream or next hop).
func buildCarrierSettings(cfg *config.Config, sec *security.SecurityConfig, outboundNextHop string, upstream *ccbserver.UpstreamConfig, log *slog.Logger) (carrierSettings, error) {
	var cc carrierSettings
	cc.listen, _ = cfg.Get("CCB_CARRIER_LISTEN")

	if isWSCarrier(cc.listen) {
		// Verify inside CCBs' bearer tokens: an HTCondor IDTOKEN (against our pool
		// signing key) or a SciToken mapped by CERTIFICATE_MAPFILE's SCITOKENS
		// lines. The SciToken settings go on a copy so the CEDAR command policy
		// in sec is unchanged.
		csec := *sec
		cc.sciTokens = applySciTokensConfig(cfg, &csec, log)
		cc.verify = ccbserver.BearerTokenVerifier(&csec)
		if strings.HasPrefix(cc.listen, "wss://") {
			certFile, _ := cfg.Get("CCB_CARRIER_TLS_CERT")
			keyFile, _ := cfg.Get("CCB_CARRIER_TLS_KEY")
			if certFile == "" || keyFile == "" {
				return cc, fmt.Errorf("CCB_CARRIER_LISTEN is wss:// but CCB_CARRIER_TLS_CERT / CCB_CARRIER_TLS_KEY are not set")
			}
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return cc, fmt.Errorf("loading carrier TLS cert/key: %w", err)
			}
			cc.tls = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
	}

	// Client side: token + CA for dialing a ws/wss upstream or next hop.
	if isWSCarrier(outboundNextHop) || (upstream != nil && isWSCarrier(upstream.BrokerAddr)) {
		if tok, ok := cfg.Get("CCB_CARRIER_TOKEN"); ok && tok != "" {
			cc.token = tok
		} else {
			cc.tokenSource = ccbserver.DiscoverBearerToken
		}
		if caFile, ok := cfg.Get("CCB_CARRIER_CA_FILE"); ok && caFile != "" {
			tlsc, err := loadCarrierClientTLS(caFile)
			if err != nil {
				return cc, fmt.Errorf("loading carrier CA file: %w", err)
			}
			cc.clientTLS = tlsc
		}
	}
	return cc, nil
}

// loadCarrierClientTLS builds a client TLS config trusting the CA bundle in
// caFile, for dialing a wss:// carrier whose server cert is not chained to a
// system root.
func loadCarrierClientTLS(caFile string) (*tls.Config, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}
	return &tls.Config{RootCAs: pool}, nil
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
