package ccbserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/golang-ccb/transport/carrier"
	"github.com/bbockelm/golang-ccb/transport/cmdcarrier"
	"github.com/bbockelm/golang-ccb/transport/fstun"
	"github.com/bbockelm/golang-ccb/transport/sshcarrier"
	"github.com/bbockelm/golang-ccb/transport/tcpcarrier"
	"github.com/bbockelm/golang-ccb/transport/wscarrier"
)

// A broker address may name a non-TCP carrier instead of a "host:port" Sinful.
// The scheme selects how this broker obtains its carrier byte pipe; which role
// it then plays over that pipe -- inside (Upstream.BrokerAddr,
// OutboundNextHop) or outside (CarrierListen) -- is decided by which knob the
// address appears in, not by the scheme. See docs/TRANSPORTS.md.
//
//	fs:<absolute-dir>          filesystem carrier, e.g. fs:/gpfs/pool/ccb-tunnel
//	ws://host:port/path        WebSocket carrier (plaintext; test/dev)
//	wss://host:port/path       WebSocket carrier over TLS (production)
//	tcp://host:port            raw carrier pipe over TCP (behind a tunnel)
//	cmd:<command line>         spawn a command; its stdin/stdout is the pipe
//	stdio:                     this process's own stdin/stdout is the pipe
//	ssh://[user@]host[:port]   an SSH session this broker opens itself
type carrierRef struct {
	scheme string // "fs", "ws" (ws:// and wss://), "tcp", "cmd", "stdio" or "ssh"
	path   string // filesystem root for scheme "fs"
	url    string // full ws/wss URL for scheme "ws"
	addr   string // host:port for scheme "tcp", host[:port] for "ssh"
	argv   string // the unparsed command line for scheme "cmd"
	user   string // login name for scheme "ssh", when the address carries one
	tls    bool   // wss (TLS)
}

// parseCarrierRef reports whether addr names a carrier, and if so parses it. A
// bare "host:port" (or shared-port) Sinful is not a carrier (ok == false) and
// keeps the default TCP path.
//
// The command line of a cmd: carrier is kept unparsed so that a carrierRef
// stays comparable (detectCarrier compares two refs for equality); it is parsed,
// and its errors reported, when the carrier is built.
func parseCarrierRef(addr string) (carrierRef, bool) {
	addr = strings.TrimSpace(addr)
	if p, ok := strings.CutPrefix(addr, "fs:"); ok {
		return carrierRef{scheme: "fs", path: p}, true
	}
	if strings.HasPrefix(addr, "wss://") {
		return carrierRef{scheme: "ws", url: addr, tls: true}, true
	}
	if strings.HasPrefix(addr, "ws://") {
		return carrierRef{scheme: "ws", url: addr}, true
	}
	if a, ok := strings.CutPrefix(addr, "tcp://"); ok {
		return carrierRef{scheme: "tcp", addr: a}, true
	}
	if c, ok := strings.CutPrefix(addr, "cmd:"); ok {
		return carrierRef{scheme: "cmd", argv: strings.TrimSpace(c)}, true
	}
	if rest, ok := strings.CutPrefix(addr, "ssh://"); ok {
		user, host := "", rest
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			user, host = rest[:at], rest[at+1:]
		}
		return carrierRef{scheme: "ssh", addr: strings.Trim(host, "/"), user: user}, true
	}
	// "stdio:" and a bare "stdio" both name the inherited pipe; there is
	// nothing after the scheme to get wrong.
	if addr == "stdio:" || addr == "stdio" {
		return carrierRef{scheme: "stdio"}, true
	}
	return carrierRef{}, false
}

func isCarrier(addr string) bool {
	_, ok := parseCarrierRef(addr)
	return ok
}

// spawns reports whether this carrier obtains its pipe by running a command or
// inheriting one, rather than by binding or dialing an address. Such a carrier
// has no notion of listening, so an outside broker configured with one obtains
// its pipes through a carrier.SourceListener instead of a network listener.
func (r carrierRef) spawns() bool {
	return r.scheme == "cmd" || r.scheme == "stdio" || r.scheme == "ssh"
}

// fstunConfig builds the fstun endpoint config for a carrier ref (defaults for
// everything but the root).
func (r carrierRef) fstunConfig() fstun.Config {
	return fstun.Config{Root: r.path}
}

func (r carrierRef) describe() string {
	switch r.scheme {
	case "ws":
		return "ws:" + r.url
	case "tcp":
		return "tcp://" + r.addr
	case "cmd":
		return "cmd:" + r.argv
	case "ssh":
		if r.user != "" {
			return "ssh://" + r.user + "@" + r.addr
		}
		return "ssh://" + r.addr
	case "stdio":
		return "stdio:"
	default:
		return r.scheme + ":" + r.path
	}
}

// carrierClient is an inside CCB's single, shared link to its outside CCB over a
// carrier: one pipe with a yamux client on top. Both the upstream registration
// and every outbound proxy-connect ride it as yamux streams. The session is
// established lazily on first dial and transparently re-established if it dies,
// so cedar's own reconnect loops recover a dropped carrier.
type carrierClient struct {
	ref carrierRef
	log *slog.Logger
	src carrier.PipeSource

	// WebSocket dial parameters (scheme "ws"); unused for the others.
	// prompter answers a server that wants something only a person can give.
	prompter        sshcarrier.Prompter
	token           string
	tokenSource     func(ctx context.Context) (string, error)
	clientTLS       *tls.Config
	unauthenticated bool
	proxy           func(*http.Request) (*url.URL, error)
	keepalive       time.Duration

	// gate holds this carrier's attempts when a login needs a person. The
	// operator console releases it; see operator.go.
	gate *carrier.HumanGate

	// exhausted is closed when the pipe source can never produce another pipe,
	// which for a stdio carrier means the parent that started this broker has
	// gone away.
	exhausted     chan struct{}
	exhaustedOnce sync.Once

	mu       sync.Mutex
	md       *carrier.MuxDialer
	lastPipe net.Conn
	done     bool
}

func newCarrierClient(ref carrierRef, cfg Config, log *slog.Logger) (*carrierClient, error) {
	c := &carrierClient{
		ref:             ref,
		log:             log,
		token:           cfg.CarrierToken,
		tokenSource:     cfg.CarrierTokenSource,
		clientTLS:       cfg.CarrierClientTLS,
		unauthenticated: cfg.CarrierUnauthenticated,
		proxy:           cfg.CarrierProxy,
		keepalive:       cfg.CarrierKeepalive,
		exhausted:       make(chan struct{}),
		gate:            &carrier.HumanGate{},
	}
	src, err := c.pipeSource(cfg)
	if err != nil {
		return nil, err
	}
	c.src = src
	return c, nil
}

// pipeSource builds the inside broker's source of carrier pipes. Every carrier
// but stdio obtains a fresh pipe on demand, so a dropped carrier is rebuilt by
// the next dial; stdio has exactly one pipe and cannot.
func (c *carrierClient) pipeSource(cfg Config) (carrier.PipeSource, error) {
	label := c.describe()
	switch c.ref.scheme {
	case "fs":
		return carrier.Dialing(label, func(ctx context.Context) (net.Conn, error) {
			return fstun.Dial(ctx, c.ref.fstunConfig())
		}), nil
	case "ws":
		return carrier.Dialing(label, func(ctx context.Context) (net.Conn, error) {
			return wscarrier.Dial(ctx, c.wsDialConfig())
		}), nil
	case "tcp":
		return carrier.Dialing(label, func(ctx context.Context) (net.Conn, error) {
			return tcpcarrier.Dial(ctx, c.ref.addr)
		}), nil
	case "cmd":
		dialCfg, err := c.cmdDialConfig(cfg)
		if err != nil {
			return nil, err
		}
		return carrier.Dialing(label, func(ctx context.Context) (net.Conn, error) {
			return cmdcarrier.Dial(ctx, dialCfg)
		}), nil
	case "ssh":
		sshCfg, stage, err := c.sshConfig(cfg)
		if err != nil {
			return nil, err
		}
		return carrier.Dialing(label, func(ctx context.Context) (net.Conn, error) {
			// Read the prompter here rather than capturing it: the console is
			// attached to the client after the source is built, so a captured
			// copy would be nil and the carrier would never ask anyone.
			sshCfg := sshCfg
			sshCfg.Prompter = c.prompter
			// A carrier parked for want of a person does not dial: the server
			// would ask the same question and there would still be nobody.
			// The operator console releases the gate when one turns up.
			if st, parked := c.gate.Parked(); parked {
				return nil, fmt.Errorf("carrier %s is waiting for an operator (%v ago): %w",
					c.describe(), st.Since.Round(time.Second), st.Reason)
			}
			var conn net.Conn
			if stage != nil {
				conn, err = sshcarrier.DialStaged(ctx, sshCfg, *stage)
			} else {
				conn, err = sshcarrier.Dial(ctx, sshCfg)
			}
			if err != nil && sshcarrier.NeedsHuman(err) {
				c.gate.Park(err)
			}
			return conn, err
		}), nil
	case "stdio":
		pipe := cfg.CarrierPipe
		if pipe == nil {
			// Nothing claimed the descriptors earlier (a library embedding this
			// server, a test). Claim them now; the daemon does it sooner.
			var err error
			if pipe, err = cmdcarrier.Stdio(c.log); err != nil {
				return nil, err
			}
		}
		return carrier.OnePipe(label, pipe), nil
	default:
		return nil, fmt.Errorf("ccbserver: unknown carrier scheme %q", c.ref.scheme)
	}
}

// cmdDialConfig parses and validates the configured command line once, at
// startup, so a typo is reported before anything depends on the carrier.
func (c *carrierClient) cmdDialConfig(cfg Config) (cmdcarrier.DialConfig, error) {
	argv, err := cmdcarrier.ParseArgv(c.ref.argv)
	if err != nil {
		return cmdcarrier.DialConfig{}, fmt.Errorf("ccbserver: carrier command: %w", err)
	}
	return cmdcarrier.DialConfig{
		Argv:           argv,
		Env:            cfg.CarrierCommandEnv,
		Dir:            cfg.CarrierCommandDir,
		Logger:         c.log,
		Label:          "cmd:" + c.ref.argv,
		TerminateGrace: cfg.CarrierCommandGrace,
	}, nil
}

// sshConfig builds the SSH dial parameters, and the staging plan when a binary
// is configured. Validated here, at startup, so a missing known_hosts or an
// unreadable key is reported before anything depends on the carrier.
func (c *carrierClient) sshConfig(cfg Config) (sshcarrier.Config, *sshcarrier.StageConfig, error) {
	sc := sshcarrier.Config{
		Addr:          c.ref.addr,
		User:          c.ref.user,
		KnownHosts:    cfg.CarrierSSH.KnownHosts,
		HostKeys:      cfg.CarrierSSH.HostKeys,
		IdentityFiles: cfg.CarrierSSH.IdentityFiles,
		Agent:         cfg.CarrierSSH.Agent,
		Command:       cfg.CarrierSSH.Command,
		Logger:        c.log,
	}
	if sc.User == "" {
		sc.User = cfg.CarrierSSH.User
	}
	// A carrier that cannot verify the host it is handing the tunnel to is not
	// a carrier worth having, so this is refused rather than defaulted.
	if len(sc.KnownHosts) == 0 && len(sc.HostKeys) == 0 {
		return sshcarrier.Config{}, nil, fmt.Errorf("ccbserver: an ssh:// carrier requires CCB_CARRIER_SSH_KNOWN_HOSTS or CCB_CARRIER_SSH_HOST_KEY")
	}
	if cfg.CarrierSSH.StageBinary == "" {
		if sc.Command == "" {
			return sshcarrier.Config{}, nil, fmt.Errorf("ccbserver: an ssh:// carrier needs either CCB_CARRIER_SSH_STAGE_BINARY or CCB_CARRIER_SSH_COMMAND")
		}
		return sc, nil, nil
	}
	return sc, &sshcarrier.StageConfig{
		Binary:       cfg.CarrierSSH.StageBinary,
		RemoteDir:    cfg.CarrierSSH.RemoteDir,
		CondorConfig: cfg.CarrierSSH.StageConfig,
		Logger:       c.log,
	}, nil
}

// wsDialConfig is the WebSocket dial parameters for this carrier, in one place
// so the dial and the route reported in logs cannot drift apart.
func (c *carrierClient) wsDialConfig() wscarrier.DialConfig {
	return wscarrier.DialConfig{
		URL:             c.ref.url,
		Token:           c.token,
		TokenSource:     c.tokenSource,
		TLS:             c.clientTLS,
		Proxy:           c.proxy,
		Unauthenticated: c.unauthenticated,
	}
}

// route describes how this carrier reaches its peer -- "direct" or "via
// <proxy>" -- for the session log. An operator (and a test) otherwise cannot
// tell a proxied carrier from one that silently ignored a configured proxy and
// dialed out directly, which on a node with no route out is the whole
// diagnosis. Empty for carriers with no notion of a route.
func (c *carrierClient) route() string {
	if c.ref.scheme != "ws" {
		return ""
	}
	proxyURL, err := c.wsDialConfig().ResolvedProxy()
	if err != nil {
		return "unresolved (" + err.Error() + ")"
	}
	return wscarrier.RouteDescription(proxyURL)
}

func (c *carrierClient) describe() string { return c.ref.describe() }

// canAskAnOperator reports whether this carrier has any way to put a question
// to a person. Only the embedded SSH carrier does: a cmd: carrier's ssh talks
// to its own terminal, which the broker does not have.
func (c *carrierClient) canAskAnOperator() bool { return c.ref.scheme == "ssh" }

// Exhausted is closed when this broker's carrier can never be re-established.
// Only a stdio carrier can reach that state: its pipe came from the process
// that started this one, and when it closes there is no way to obtain another.
func (c *carrierClient) Exhausted() <-chan struct{} { return c.exhausted }

func (c *carrierClient) markExhausted() {
	c.exhaustedOnce.Do(func() { close(c.exhausted) })
}

// dial is the ccb.BrokerDialer handed to cedar: it opens a fresh logical
// connection (a yamux stream) to the outside CCB over the shared pipe,
// establishing the pipe first if needed. brokerAddr is ignored -- the carrier is
// point-to-point.
func (c *carrierClient) dial(ctx context.Context, brokerAddr string) (net.Conn, error) {
	md, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	return md.Open(ctx)
}

// session returns a live yamux client session, establishing (or re-establishing)
// the underlying pipe if there is none or the previous one has died.
func (c *carrierClient) session(ctx context.Context) (*carrier.MuxDialer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return nil, net.ErrClosed
	}
	if c.md != nil && !c.md.Closed() {
		return c.md, nil
	}
	if c.md != nil {
		_ = c.md.Close()
		c.md = nil
	}
	pipe, err := c.src.Pipe(ctx)
	if err != nil {
		if errors.Is(err, carrier.ErrPipeExhausted) {
			c.log.Error("the carrier pipe has closed and cannot be re-established; this broker can no longer reach its outside CCB",
				"carrier", c.describe())
			c.markExhausted()
		}
		return nil, fmt.Errorf("carrier %s: obtaining pipe: %w", c.describe(), err)
	}

	md, err := carrier.NewMuxDialerKeepalive(pipe, c.keepalive)
	if err != nil {
		_ = pipe.Close()
		return nil, fmt.Errorf("carrier %s: yamux client: %w", c.describe(), err)
	}
	c.md = md
	c.lastPipe = pipe
	attrs := []any{"carrier", c.describe()}
	if r := c.route(); r != "" {
		attrs = append(attrs, "route", r)
	}
	c.log.Info("carrier session established", attrs...)
	return md, nil
}

// pipeDiagnostics describes why the underlying pipe is unhealthy, when the
// carrier is one that can say. For a cmd: carrier that is the child's exit
// status and its last stderr lines, which is the entire diagnosis for an ssh
// that was refused -- everything above the pipe sees only a closed connection.
// Empty when the carrier has nothing to add.
func (c *carrierClient) pipeDiagnostics() string {
	c.mu.Lock()
	pipe := c.lastPipe
	c.mu.Unlock()
	d, ok := pipe.(cmdcarrier.Diagnostics)
	if !ok {
		return ""
	}
	stderr := d.Stderr()
	exitErr, exited := d.Exited()
	switch {
	case exited && exitErr != nil && stderr != "":
		return fmt.Sprintf("the carrier command (%s) exited (%v); its last output was: %s", d.Program(), exitErr, stderr)
	case exited && exitErr != nil:
		return fmt.Sprintf("the carrier command (%s) exited (%v) without explaining why; run it by hand to see what it reports", d.Program(), exitErr)
	case exited:
		return fmt.Sprintf("the carrier command (%s) exited cleanly, closing the carrier", d.Program())
	case stderr != "":
		return fmt.Sprintf("the carrier command (%s) is running; its last output was: %s", d.Program(), stderr)
	default:
		return ""
	}
}

func (c *carrierClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done = true
	if c.md != nil {
		_ = c.md.Close()
		c.md = nil
	}
	if c.src != nil {
		_ = c.src.Close()
	}
}

// detectCarrier inspects the inside-CCB knobs (Upstream.BrokerAddr and
// OutboundNextHop) for a carrier scheme and, if present, returns a shared
// carrierClient. Both knobs typically point at the same outside CCB; if both name
// carriers they must name the same one (a single point-to-point pipe).
func (s *Server) detectCarrier() (*carrierClient, error) {
	var refs []carrierRef
	if s.cfg.Upstream != nil {
		if r, ok := parseCarrierRef(s.cfg.Upstream.BrokerAddr); ok {
			refs = append(refs, r)
		}
	}
	if r, ok := parseCarrierRef(s.cfg.OutboundNextHop); ok {
		refs = append(refs, r)
	}
	if len(refs) == 0 {
		return nil, nil
	}
	for _, r := range refs[1:] {
		if r != refs[0] {
			return nil, fmt.Errorf("ccbserver: Upstream and OutboundNextHop name different carriers (%v vs %v); a single carrier pipe is required", refs[0], r)
		}
	}
	// A stdio carrier is one pipe, so it can back one role. Configured on both
	// the inside and the outside knobs it would be handed to each of them, and
	// the two would interleave yamux frames on the same descriptors -- a
	// failure that looks like a corrupt peer rather than a misconfiguration.
	if refs[0].scheme == "stdio" {
		if lr, ok := parseCarrierRef(s.cfg.CarrierListen); ok && lr.scheme == "stdio" {
			return nil, fmt.Errorf("ccbserver: stdio: is configured as both this broker's carrier to its outside CCB and its CarrierListen; one inherited pipe cannot carry both roles")
		}
	}
	return newCarrierClient(refs[0], s.cfg, s.log)
}

// startCarrierListener runs an outside CCB's acceptor for inside CCBs arriving
// over a carrier: one byte pipe per inside CCB, yamux-server multiplexed into
// ordinary command streams served by the same cedar command loop as TCP.
//
// "Acceptor" is a role, not a direction. A cmd: or stdio: carrier obtains its
// pipes by running a command or inheriting one, which is how an outside broker
// reaches into a network it cannot dial into -- it runs ssh to the restricted
// side and the broker there plays the inside role over the same pipe.
func (s *Server) startCarrierListener(ctx context.Context) {
	ref, ok := parseCarrierRef(s.cfg.CarrierListen)
	if !ok {
		s.log.Error("CarrierListen is not a recognized carrier address", "value", s.cfg.CarrierListen)
		return
	}
	inner, err := s.carrierNetListener(ref)
	if err != nil {
		s.log.Error("failed to start carrier listener", "carrier", s.cfg.CarrierListen, "error", err)
		return
	}
	ml := carrier.NewMuxListener(inner, carrier.WithFirstStreamTimeout(s.pipeProbation()))
	go func() {
		<-ctx.Done()
		_ = ml.Close()
	}()
	go func() {
		s.log.Info("CCB carrier listener started", "carrier", ref.describe())
		if err := s.srv.Serve(ctx, ml); err != nil && ctx.Err() == nil {
			s.log.Error("carrier listener serve ended", "error", err)
		}
	}()
}

// carrierNetListener builds the underlying (pre-yamux) net.Listener for a carrier.
func (s *Server) carrierNetListener(ref carrierRef) (net.Listener, error) {
	if ref.spawns() {
		return s.spawningCarrierListener(ref)
	}
	switch ref.scheme {
	case "fs":
		return fstun.Listen(ref.fstunConfig())
	case "tcp":
		return tcpcarrier.Listen(tcpcarrier.ListenConfig{
			Addr:         ref.addr,
			MaxSessions:  s.cfg.CarrierMaxSessions,
			MaxPerSource: s.cfg.CarrierMaxPerSource,
			Logger:       s.log,
		})
	case "ws":
		if s.cfg.CarrierTokenVerify == nil && !s.cfg.CarrierUnauthenticated {
			return nil, fmt.Errorf("ccbserver: a WebSocket CarrierListen requires CarrierTokenVerify (or CarrierUnauthenticated)")
		}
		u, err := url.Parse(ref.url)
		if err != nil {
			return nil, fmt.Errorf("ccbserver: bad carrier URL %q: %w", ref.url, err)
		}
		if ref.tls && s.cfg.CarrierTLS == nil {
			return nil, fmt.Errorf("ccbserver: a wss:// CarrierListen requires CarrierTLS")
		}
		verify := s.cfg.CarrierTokenVerify
		if s.cfg.CarrierUnauthenticated {
			verify = nil // the knob wins over a verifier the daemon also built
		}
		return wscarrier.Listen(wscarrier.ListenConfig{
			Addr:                 u.Host,
			Path:                 u.Path,
			TLS:                  s.cfg.CarrierTLS,
			Verify:               verify,
			AllowUnauthenticated: s.cfg.CarrierUnauthenticated,
			MaxSessions:          s.cfg.CarrierMaxSessions,
			MaxPerSource:         s.cfg.CarrierMaxPerSource,
		})
	default:
		return nil, fmt.Errorf("ccbserver: unknown carrier scheme %q", ref.scheme)
	}
}

// spawningCarrierListener presents a cmd: or stdio: pipe source as a listener,
// so the outside role runs over it unchanged.
func (s *Server) spawningCarrierListener(ref carrierRef) (net.Listener, error) {
	// A carrierClient is the one place that knows how to build a pipe source
	// from a ref; the outside role needs the source, not the client.
	c := &carrierClient{ref: ref, log: s.log, exhausted: make(chan struct{})}
	src, err := c.pipeSource(s.cfg)
	if err != nil {
		return nil, err
	}
	// One pipe at a time: this source produces a pipe by running a command (or
	// has exactly one to give), so MuxListener's accept loop must be made to
	// wait for the live pipe to close rather than asking for another at once.
	ln := carrier.NewSourceListener(src, s.log, carrier.Backoff{
		Initial: s.cfg.CarrierRetryInitial,
		Max:     s.cfg.CarrierRetryMax,
	}, carrier.OnePipeAtATime())
	return &exhaustNotifier{Listener: ln, notify: s.markCarrierExhausted}, nil
}

// exhaustNotifier reports a listener whose pipe source can never yield another
// pipe. MuxListener treats every accept error the same way -- it stops -- so the
// distinction between "down for now" and "gone for good" has to be noticed
// here, on the way past.
type exhaustNotifier struct {
	net.Listener
	notify func()
}

func (l *exhaustNotifier) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if errors.Is(err, carrier.ErrPipeExhausted) {
		l.notify()
	}
	return c, err
}

// pipeProbation resolves how long an accepted carrier pipe may sit without
// opening a logical connection. A negative value disables the check.
func (s *Server) pipeProbation() time.Duration {
	if s.cfg.CarrierPipeProbationOff {
		return -1
	}
	if s.cfg.CarrierPipeProbation > 0 {
		return s.cfg.CarrierPipeProbation
	}
	return carrier.DefaultFirstStreamTimeout
}
