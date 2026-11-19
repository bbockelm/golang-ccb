// Command htc-ccb-relay is the far end of an SSH carrier: an inside CCB that
// reaches its pool only through the pipe it was started with.
//
// It is htc-ccb with everything a staged broker cannot use taken out, because
// the binary has to cross an SSH session before it can run. What it keeps is
// the part that matters on an execute host: the CCB server, upstream
// registration over the carrier, the outbound proxy, and HTCondor's own
// authorization policy. What it drops is anything whose state cannot outlive
// the process:
//
//   - The session cache. Its whole purpose is to let clients resume across a
//     restart; a process whose carrier is its own stdin does not restart, it
//     exits when the ssh session ends and is staged afresh next time.
//   - The shared reconnect store, for the same reason: a CCBID kept across a
//     restart that never happens.
//
// Both of those are SQLite, which is most of the difference in size. See
// docs/TRANSPORTS.md section 6.3.1.
//
// It is NOT a smaller htc-ccb for general use. It has one role and one
// carrier, and it will refuse anything else rather than half-work: a broker
// that silently ran without the persistence an administrator configured would
// be worse than one that would not start.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"

	"github.com/bbockelm/cedar/ccb"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"

	ccbserver "github.com/bbockelm/golang-ccb"
	"github.com/bbockelm/golang-ccb/transport/cmdcarrier"
)

// streamingVersionString must match htc-ccb's: a peer decides whether this
// broker can carry nested routing by parsing it, so a relay that reported an
// older version would be refused for streaming with no local symptom.
const streamingVersionString = "$CondorVersion: 25.13.0 2026-06-21 BuildID: relay $"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "htc-ccb-relay:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":9618", "TCP listen address for CCB contacts from daemons on this host. CCB_LISTEN sets it from the staged configuration, which is how a staged relay is told: the default collides on a host that already runs HTCondor.")
	public := flag.String("public", "", "address advertised in CCB contacts (host:port); defaults to the listen address. CCB_PUBLIC sets it from configuration.")
	localName := flag.String("local-name", "", "HTCondor subsystem local-name, used as a config-lookup prefix.")
	// Accepted so the command line a staging carrier derives is the same for
	// this binary and for htc-ccb: `<binary> -carrier-stdio`. Here it is the
	// only mode there is, so it is a no-op rather than a switch.
	carrierStdio := flag.Bool("carrier-stdio", false, "take stdin and stdout as the carrier to the outside CCB. This is the only mode this binary has; the flag is accepted so a staged command line is identical to htc-ccb's.")
	_ = flag.String("sock", "", "accepted for compatibility with condor_master; ignored.")
	flag.Parse()
	_ = carrierStdio

	listenExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "listen" {
			listenExplicit = true
		}
	})

	// Claim stdin and stdout before anything else can write to them. The pipe
	// carries a framed protocol, so one stray line on stdout -- a config
	// loader's warning, a banner -- corrupts it, and the symptom is an
	// unintelligible yamux error at the far end rather than anything naming
	// this process. Claiming also points stdout at stderr, so a later stray
	// write is harmless.
	pipe, err := cmdcarrier.Stdio(nil)
	if err != nil {
		return err
	}

	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "CCB", LocalName: *localName})
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	d, err := daemon.New(daemon.Options{Subsys: "CCB", Config: cfg})
	if err != nil {
		return err
	}
	log := d.Logger()
	slog.SetDefault(d.Slog())

	// Refuse the knobs this binary cannot honour, rather than ignoring them.
	// An administrator who staged a configuration asking for session
	// persistence has made a request this binary does not implement; running
	// anyway would hide that until they went looking for sessions that were
	// never there.
	if err := refuseUnsupported(cfg); err != nil {
		return err
	}

	if !listenExplicit {
		if v, ok := cfg.Get("CCB_LISTEN"); ok && v != "" {
			*listen = v
		}
	}
	if *public == "" {
		if v, ok := cfg.Get("CCB_PUBLIC"); ok {
			*public = v
		}
	}

	ln, err := d.Listener(func() (net.Listener, error) {
		return net.Listen("tcp", *listen)
	})
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	pub := *public
	if pub == "" {
		pub = ln.Addr().String()
	}

	// Server credentials verify the daemons on this host that register with
	// this relay; client credentials are what it presents to the next hop.
	//
	// d.ServerSecurityConfig, and with exactly the arguments htc-ccb passes:
	// it loads the server-side credentials AND adds this daemon's shared-port
	// id, which an HTCondor 25.14+ FS client's channel binding names. Calling
	// the underlying htcondor.GetServerSecurityConfig here instead would be a
	// place for the two binaries' security policy to drift apart silently,
	// which is the last thing that should differ between them.
	srvSec, err := d.ServerSecurityConfig(ccb.CommandRegister, "DAEMON")
	if err != nil {
		return fmt.Errorf("building server security config: %w", err)
	}
	srvSec.RemoteVersion = streamingVersionString

	// Reload signing keys and SSL material on SIGHUP, the HTCondor
	// reconfigure convention. A staged relay rarely sees one, but a long-lived
	// carrier outliving a key rotation is exactly when it would matter.
	if rl, ok := srvSec.Credentials.(htcondor.CredentialReloader); ok {
		d.OnReconfig(func(*config.Config) { rl.Reload() })
	}
	clientSec, err := htcondor.GetSecurityConfig(cfg, ccb.CommandRegister, "CLIENT")
	if err != nil {
		return fmt.Errorf("building next-hop client security config: %w", err)
	}
	clientSec.RemoteVersion = streamingVersionString

	var outboundAllowlist []string
	if v, ok := cfg.Get("CCB_OUTBOUND_TARGET_ALLOWLIST"); ok {
		outboundAllowlist = ccb.SplitBrokerList(v)
	}
	var dialControl func(network, address string, c syscall.RawConn) error
	if configBool(cfg, "CCB_DIAL_REFUSE_LOCAL_ADDRESSES", false) {
		dialControl = ccbserver.RefuseLocalAddresses
	}
	readyFile, _ := cfg.Get("CCB_TUNNEL_READY_FILE")

	az, err := d.NewAuthz(daemon.AuthzOptions{})
	if err != nil {
		return fmt.Errorf("building authorization policy: %w", err)
	}
	srv, err := ccbserver.New(ccbserver.Config{
		PublicAddress:           pub,
		Security:                srvSec,
		Authorizer:              az.Authorize,
		OutboundProxy:           configBool(cfg, "CCB_OUTBOUND_PROXY", false),
		OutboundTargetAllowlist: outboundAllowlist,
		OutboundNextHop:         "stdio:",
		OutboundNextHopSecurity: clientSec,
		Upstream: &ccbserver.UpstreamConfig{
			BrokerAddr: "stdio:",
			Security:   clientSec,
			ReadyFile:  readyFile,
		},
		CarrierPipe: pipe,
		DialControl: dialControl,
		Logger:      d.Slog(),
	})
	if err != nil {
		return fmt.Errorf("creating CCB relay: %w", err)
	}
	cs := srv.CommandServer()
	d.RegisterDefaultCommands(cs)
	if err := d.InstallSecurityLevels(cs); err != nil {
		return fmt.Errorf("building per-level security policy: %w", err)
	}

	log.Info(logging.DestinationGeneral, "htc-ccb-relay starting",
		"public", pub, "listen", ln.Addr().String())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.StartBackground(ctx)
	// The carrier is this process's stdin. Once it cannot be re-established
	// the ssh session that started us has ended, so there is no way back to
	// the pool and no way for anyone to reach us: exit and let the parent see
	// it, rather than idling unreachably.
	go func() {
		select {
		case <-srv.CarrierExhausted():
			cancel()
		case <-ctx.Done():
		}
	}()
	return d.ServeListeners(ctx, az.Serve(srv.CommandServer(), d.Slog()), ln)
}

// refuseUnsupported rejects configuration this binary cannot carry out.
//
// Each of these works in htc-ccb. Staging the full binary is the answer when
// a site needs one, and the error says so, because "my setting did nothing"
// is the hardest kind of failure to chase from the far side of an ssh
// session.
func refuseUnsupported(cfg *config.Config) error {
	unsupported := []struct{ key, why string }{
		{"CCB_SESSION_CACHE_FILE", "this relay keeps no session cache: its carrier is its own stdin, so it does not outlive the ssh session that started it and has no restart to resume across"},
		{"CCB_CARRIER_LISTEN", "this relay is the inside end of one carrier and accepts none of its own"},
	}
	for _, u := range unsupported {
		if v, ok := cfg.Get(u.key); ok && v != "" {
			return fmt.Errorf("%s is set, and %s; stage htc-ccb instead of htc-ccb-relay if you need it", u.key, u.why)
		}
	}
	// A next hop other than the pipe would mean this process is not the far
	// end of a carrier at all.
	if v, ok := cfg.Get("CCB_OUTBOUND_NEXT_HOP"); ok && v != "" && v != "stdio:" && v != "stdio" {
		return fmt.Errorf("CCB_OUTBOUND_NEXT_HOP = %q, but this relay's carrier is always the pipe it was started with; stage htc-ccb if you need another carrier", v)
	}
	return nil
}

func configBool(cfg *config.Config, key string, def bool) bool {
	v, ok := cfg.Get(key)
	if !ok {
		return def
	}
	switch v {
	case "TRUE", "True", "true", "T", "t", "1", "YES", "Yes", "yes":
		return true
	case "FALSE", "False", "false", "F", "f", "0", "NO", "No", "no":
		return false
	}
	return def
}
