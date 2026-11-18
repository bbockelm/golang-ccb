package ccbserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"

	"github.com/bbockelm/golang-ccb/transport/cmdcarrier"
)

// The cmd: carrier runs a command whose stdin and stdout are the pipe. To test
// it without depending on ssh, nc or socat being installed, the test binary
// re-executes itself as the far end: TestMain dispatches on an environment
// variable before the testing framework has run (and so before it has written a
// byte to stdout, which would corrupt a carrier).
const (
	envStdioBroker = "CCB_TEST_STDIO_BROKER" // run as an inside broker over stdio; value is the file to write its address to
	envRelayTo     = "CCB_TEST_RELAY_TO"     // splice stdio to this TCP address, as `ssh -W host:port` does
)

func TestMain(m *testing.M) {
	switch {
	case os.Getenv(envStdioBroker) != "":
		os.Exit(runStdioBrokerChild(os.Getenv(envStdioBroker)))
	case os.Getenv(envRelayTo) != "":
		os.Exit(runRelayChild(os.Getenv(envRelayTo)))
	}
	os.Exit(m.Run())
}

// runStdioBrokerChild is an INSIDE broker whose carrier is the stdin/stdout it
// was started with -- what `htc-ccb -carrier-stdio` runs. It serves its own EPs
// over TCP and writes that address to addrFile so the parent test can find it.
func runStdioBrokerChild(addrFile string) int {
	pipe, err := cmdcarrier.Stdio(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stdio:", err)
		return 1
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		return 1
	}
	srv, err := New(Config{
		PublicAddress:  ln.Addr().String(),
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		CarrierPipe:    pipe,
		// Both halves ride the one inherited pipe: jobs on the cluster register
		// through it to become reachable, and dial out through it to reach the
		// world. OutboundNextHop and Upstream must name the same carrier, which
		// for stdio they necessarily do -- there is only one pipe.
		OutboundProxy:           true,
		OutboundNextHop:         "stdio:",
		OutboundNextHopSecurity: plaintextSec(),
		Upstream: &UpstreamConfig{
			BrokerAddr:        "stdio:",
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "New:", err)
		return 1
	}
	if err := os.WriteFile(addrFile, []byte(ln.Addr().String()), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "addr file:", err)
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Exit when the carrier goes away, exactly as the daemon does: the parent
	// that started us is gone and nothing can reach this broker again.
	go func() {
		<-srv.CarrierExhausted()
		cancel()
	}()
	_ = srv.Serve(ctx, ln)
	return 0
}

// runRelayChild splices stdin/stdout to a TCP address. This is what `ssh -W
// broker:port bastion` does, and the deployment it stands in for is the one
// with nothing of ours installed on the relay host.
func runRelayChild(addr string) int {
	pipe, err := cmdcarrier.Stdio(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stdio:", err)
		return 1
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "relay dial:", err)
		return 1
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, pipe); done <- struct{}{} }()
	go func() { _, _ = io.Copy(pipe, conn); done <- struct{}{} }()
	<-done
	return 0
}

// selfCommand is a cmd: carrier address that re-executes this test binary. The
// path is single-quoted because a temporary directory may contain a character
// ParseArgv would otherwise refuse.
func selfCommand(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if strings.ContainsRune(exe, '\'') {
		t.Skipf("test binary path %q cannot be quoted for a cmd: carrier", exe)
	}
	return "cmd:'" + exe + "'"
}

// freeTCPAddr reserves a port by binding it and letting it go. The carrier
// listener binds a configured address rather than reporting an ephemeral one,
// so a test has to name a port it believes is free.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// startInsideCCB starts an inside CCB whose upstream link is the named carrier.
// It still serves its own local EPs over TCP.
func startInsideCCB(t *testing.T, carrierAddr string) (addr string, srv *Server, cancel func()) {
	t.Helper()
	return startInsideCCBEnv(t, carrierAddr, nil)
}

func startInsideCCBEnv(t *testing.T, carrierAddr string, env []string) (addr string, srv *Server, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err = New(Config{
		PublicAddress:     ln.Addr().String(),
		Security:          plaintextSec(),
		RequestTimeout:    5 * time.Second,
		CarrierCommandEnv: env,
		Logger:            testLogger(t),
		Upstream: &UpstreamConfig{
			BrokerAddr:        carrierAddr,
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String(), srv, c
}

func waitTunnelReady(t *testing.T, srv *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.WaitTunnelReady(ctx); err != nil {
		t.Fatalf("the inside broker never registered upstream over the carrier: %v", err)
	}
}

// testLogger sends broker logs to the test's output, which is where a carrier
// command's stderr ends up too.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func waitForFile(t *testing.T, path string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return string(b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s was not written within %s", path, within)
	return ""
}

// startOutsideCCB starts an outside CCB facing the pool over TCP and accepting
// inside CCBs over the carrier named by carrierListen.
func startOutsideCCB(t *testing.T, carrierListen string, env []string) (tcpAddr string, cancel func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		PublicAddress:     ln.Addr().String(),
		Security:          plaintextSec(),
		RequestTimeout:    5 * time.Second,
		CarrierListen:     carrierListen,
		CarrierCommandEnv: env,
		Logger:            testLogger(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String(), c
}

// tunnelThrough is the shared assertion: an EP registered with the inside
// broker is reachable, end to end, by a pool client that dials the nested
// contact through the outside broker. It is what every carrier has to deliver,
// and it exercises the carrier in both directions -- registration outbound,
// reverse-connect inbound.
func tunnelThrough(t *testing.T, outsideAddr, insideAddr string) {
	t.Helper()
	served := make(chan struct{}, 1)
	epContact, stopEP := startRegisteredCedarEP(t, insideAddr, served)
	defer stopEP()

	if strings.Count(epContact, "#") < 2 {
		t.Fatalf("EP contact %q is not nested (want <outside>#<inside>#<ep>)", epContact)
	}
	if !strings.HasPrefix(epContact, outsideAddr+"#") {
		t.Fatalf("EP contact %q does not start at the outside broker %q", epContact, outsideAddr)
	}
	t.Logf("nested contact: %s", epContact)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := ccb.Dial(ctx, contactsFor(t, epContact), ccb.DialOptions{
		Security:   plaintextSec(),
		TargetDesc: "tunneled-ep",
		Timeout:    15 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial nested contact %q: %v", epContact, err)
	}
	defer func() { _ = conn.Close() }()

	if err := endToEndDCNop(ctx, conn, epContact); err != nil {
		t.Fatalf("end-to-end DC_NOP through the tunnel: %v", err)
	}
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("the EP's DC_NOP never dispatched through the tunnel")
	}
}

// A raw TCP carrier is the simplest pipe there is, and the landing point for
// every relayed carrier: `ssh -W`, `ssh -L`, kubectl port-forward and socat all
// deliver a bare byte stream that the broker's CEDAR port cannot accept,
// because that port expects one CEDAR connection per socket rather than a
// multiplexed carrier.
func TestInboundTunnelOverTCPCarrier(t *testing.T) {
	carrierAddr := freeTCPAddr(t)
	outsideAddr, stopOut := startOutsideCCB(t, "tcp://"+carrierAddr, nil)
	defer stopOut()

	insideAddr, insideSrv, stopIn := startInsideCCB(t, "tcp://"+carrierAddr)
	defer stopIn()

	waitTunnelReady(t, insideSrv)
	tunnelThrough(t, outsideAddr, insideAddr)
}

// The deployment with nothing of ours on the relay host: the inside broker runs
// a command that reaches the outside broker's raw pipe, which is what `ssh -W
// outside:9700 bastion` is. The command here splices stdio to TCP, as ssh -W
// does.
func TestInboundTunnelOverCmdRelayCarrier(t *testing.T) {
	carrierAddr := freeTCPAddr(t)
	outsideAddr, stopOut := startOutsideCCB(t, "tcp://"+carrierAddr, nil)
	defer stopOut()

	insideAddr, insideSrv, stopIn := startInsideCCBEnv(t, selfCommand(t),
		append(os.Environ(), envRelayTo+"="+carrierAddr))
	defer stopIn()

	waitTunnelReady(t, insideSrv)
	tunnelThrough(t, outsideAddr, insideAddr)
}

// The inverted topology, and the reason the pipe source is separate from the
// role: the OUTSIDE broker reaches into the restricted network by running a
// command, and the broker at the far end plays the INSIDE role over the very
// same pipe. Nobody dials the inside broker and the inside broker dials nobody;
// the carrier is a process the outside broker started.
func TestInboundTunnelOverCmdStdioCarrierInverted(t *testing.T) {
	addrFile := t.TempDir() + "/inside-addr"
	outsideAddr, stopOut := startOutsideCCB(t, selfCommand(t),
		append(os.Environ(), envStdioBroker+"="+addrFile))
	defer stopOut()

	insideAddr := waitForFile(t, addrFile, 30*time.Second)
	t.Logf("inside broker (started by the outside broker over the carrier) serves EPs at %s", insideAddr)

	tunnelThrough(t, outsideAddr, insideAddr)
}

// The operator-facing payoff of keeping the child's stderr: an ssh that was
// refused reaches everything above the pipe as a closed connection and nothing
// else, so -carrier-check must say what the command actually reported.
func TestCarrierCheckReportsTheCommandsOwnError(t *testing.T) {
	srv, err := New(Config{
		PublicAddress:  "127.0.0.1:9618",
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		Logger:         testLogger(t),
		Upstream: &UpstreamConfig{
			// Stands in for an ssh that authenticates and is refused: it says
			// why on stderr and exits non-zero, which is all ssh does.
			BrokerAddr:        "cmd:/bin/sh -c 'echo \"Permission denied (publickey).\" >&2; exit 255'",
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := srv.CheckCarrier(ctx)
	if res.OK() {
		t.Fatal("the carrier check passed against a command that exits immediately")
	}
	report := res.String()
	for _, want := range []string{"Permission denied (publickey).", "exit status 255"} {
		if !strings.Contains(report, want) {
			t.Errorf("the carrier-check report does not mention %q.\nreport:\n%s", want, report)
		}
	}
}

// A carrier that is merely down is retried forever; only a stdio carrier can
// become unreachable for good, and the broker has to notice so it can exit
// rather than idle with no route in or out.
func TestStdioCarrierExhaustionIsSignalled(t *testing.T) {
	local, remote := net.Pipe()
	srv, err := New(Config{
		PublicAddress:  "127.0.0.1:9618",
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		Logger:         testLogger(t),
		CarrierPipe:    local,
		Upstream: &UpstreamConfig{
			BrokerAddr:        "stdio:",
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	select {
	case <-srv.CarrierExhausted():
		t.Fatal("the carrier was reported exhausted before it was even used")
	default:
	}

	// Take the one pipe, then lose it. Nothing can produce another.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := srv.carrier.session(ctx); err != nil {
		t.Fatalf("establishing the stdio session: %v", err)
	}
	_ = remote.Close()
	_ = local.Close()

	// The next dial finds the session dead and the source empty.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := srv.carrier.session(ctx); err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-srv.CarrierExhausted():
	case <-time.After(5 * time.Second):
		t.Fatal("a stdio carrier whose pipe closed never reported itself exhausted")
	}
}

// The inverted topology with the REAL binary: the outside broker reaches into
// the restricted side by running `htc-ccb -carrier-stdio`, and that process
// plays the inside role over the pipe it was started with. Nobody dials it and
// it dials nobody.
//
// This is also the only test that covers the -carrier-stdio flag itself, and
// the one invariant the daemon has to hold that no in-process test can check:
// not one byte of log output reaches stdout, because stdout is the pipe.
func TestCarrierStdioFlagOnTheRealBinary(t *testing.T) {
	bin := buildCCBBinary(t)
	dir := t.TempDir()
	insidePort := freePort(t)
	insideAddr := fmt.Sprintf("127.0.0.1:%d", insidePort)

	cfgPath := filepath.Join(dir, "condor_config")
	cfg := fmt.Sprintf(`LOG = %s
LOCK = %s
RUN = %s
SPOOL = %s
SEC_DEFAULT_AUTHENTICATION = NEVER
SEC_DEFAULT_ENCRYPTION = NEVER
SEC_DEFAULT_INTEGRITY = NEVER
ALLOW_DAEMON = *
ALLOW_READ = *
`, dir, dir, dir, dir)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	command := fmt.Sprintf("cmd:'%s' -carrier-stdio -listen %s -public %s", bin, insideAddr, insideAddr)
	outsideAddr, stopOut := startOutsideCCB(t, command, append(os.Environ(), "CONDOR_CONFIG="+cfgPath))
	defer stopOut()

	// The inside broker is up once it is serving its own EPs.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", insideAddr, time.Second)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	tunnelThrough(t, outsideAddr, insideAddr)

	// Nothing but carrier frames may cross stdout. The daemon logs to CcbLog,
	// and it points fd 1 at fd 2 before it loads config, so even a stray write
	// lands there instead.
	logPath := filepath.Join(dir, "CcbLog")
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("the inside broker wrote no log at %s: %v", logPath, err)
	}
	if !strings.Contains(string(logged), "carrier session established") {
		t.Errorf("CcbLog does not show the stdio carrier coming up:\n%s", logged)
	}
	if !strings.Contains(string(logged), "next_hop=stdio:") {
		t.Errorf("-carrier-stdio did not put the broker in the inside role:\n%s", logged)
	}
}

// The topology this carrier exists for, in the direction that matters most: a
// well-known broker OUTSIDE a cluster reaches in over SSH, the broker it starts
// on the login host is what jobs on the compute nodes talk to, and their
// traffic leaves through the pipe the outside broker opened.
//
// Nothing on the cluster dials out and nothing from outside dials in. The one
// connection is the `ssh` the outside broker ran, and it carries both
// directions: this test drives the outbound one (a job reaching the world),
// where TestInboundTunnelOverCmdStdioCarrierInverted drives the inbound one (a
// pool client reaching a job).
//
// Like every other outbound-proxy test here it needs a non-loopback target,
// because the exit hop refuses local addresses unconditionally -- which is also
// why it inherits their flakiness on a host whose non-loopback address moves.
func TestOutboundThroughCmdStdioCarrierInverted(t *testing.T) {
	targetIP := reachableNonLoopbackIPv4(t)

	// Stands in for the collector, AP or anything else beyond the cluster.
	served := make(chan struct{}, 1)
	targetAddr, stopTgt := startCedarDialTarget(t, targetIP, served)
	defer stopTgt()

	// The outside broker: reaches into the cluster by running a command, and is
	// the exit that dials the target.
	outLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	outsideRec := &logCatcher{}
	addrFile := t.TempDir() + "/inside-addr"
	outsideSrv, err := New(Config{
		PublicAddress:           outLn.Addr().String(),
		Security:                plaintextSec(),
		RequestTimeout:          5 * time.Second,
		OutboundProxy:           true,
		OutboundTargetAllowlist: []string{targetIP + "/32"},
		CarrierListen:           selfCommand(t),
		CarrierCommandEnv:       append(os.Environ(), envStdioBroker+"="+addrFile),
		Logger:                  slog.New(outsideRec),
	})
	if err != nil {
		t.Fatal(err)
	}
	octx, ocancel := context.WithCancel(context.Background())
	defer ocancel()
	go func() { _ = outsideSrv.Serve(octx, outLn) }()

	// The broker on the login host, started by the outside one over the pipe.
	insideAddr := waitForFile(t, addrFile, 30*time.Second)
	t.Logf("login-host broker (started from outside) serves the cluster at %s", insideAddr)

	// A job on a compute node: it can reach the login host and nothing else.
	if err := outboundDCNopRetrying(t, insideAddr, targetAddr); err != nil {
		t.Fatalf("a job's outbound connection through the SSH-opened tunnel: %v", err)
	}
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("the target never saw the job's command; it did not dispatch through the tunnel")
	}
	if !outsideRec.saw("proxy-connect splice established") {
		t.Fatal("the outside broker did not splice the job's connection to the target")
	}
}

// The allow-list still governs what jobs may reach. A carrier that moved
// opaque bytes while bypassing the exit's policy would be a hole, and the
// inverted topology routes through a different path to reach that policy.
func TestOutboundAllowlistAppliesThroughCmdStdioCarrier(t *testing.T) {
	targetIP := reachableNonLoopbackIPv4(t)

	served := make(chan struct{}, 1)
	targetAddr, stopTgt := startCedarDialTarget(t, targetIP, served)
	defer stopTgt()

	outLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addrFile := t.TempDir() + "/inside-addr"
	outsideSrv, err := New(Config{
		PublicAddress:  outLn.Addr().String(),
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		OutboundProxy:  true,
		// Allows something else entirely, so this target is refused.
		OutboundTargetAllowlist: []string{"192.0.2.1/32"},
		CarrierListen:           selfCommand(t),
		CarrierCommandEnv:       append(os.Environ(), envStdioBroker+"="+addrFile),
		Logger:                  testLogger(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	octx, ocancel := context.WithCancel(context.Background())
	defer ocancel()
	go func() { _ = outsideSrv.Serve(octx, outLn) }()

	insideAddr := waitForFile(t, addrFile, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := outboundDCNop(ctx, insideAddr, "<"+targetAddr+">"); err == nil {
		t.Fatal("a target outside the allow-list was reached through the carrier")
	}
	select {
	case <-served:
		t.Fatal("the refused target was dialed anyway")
	case <-time.After(time.Second):
	}
}

// reachableNonLoopbackIPv4 is nonLoopbackIPv4 with the address actually
// checked before it is used.
//
// The exit hop refuses loopback unconditionally, so an outbound-proxy test
// needs a real address -- but a host can offer several, and one of them need
// not work: a VPN or overlay interface (Tailscale's 100.64/10 is global
// unicast as far as net.IP is concerned) can be listed, accepted by bind, and
// still not carry a connection back to itself. nonLoopbackIPv4 returns the
// first candidate it sees, so on such a host it hands the test a dud and the
// failure arrives much later, as a proxy-connect that never answers.
//
// Binding and dialing each candidate costs milliseconds and removes that whole
// class. It does NOT fix everything: on the same host an address that passes
// this check can still stall a connection made a moment later, which is what
// outboundDCNopRetrying below exists for.
func reachableNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot list interfaces: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() {
			continue
		}
		if roundTrips(ip.String()) {
			return ip.String()
		}
		t.Logf("skipping %s: it accepts a bind but does not carry a connection back to itself", ip)
	}
	t.Skip("no non-loopback IPv4 address on this host carries a connection to itself")
	return ""
}

// roundTrips reports whether a listener bound to ip can be dialed at ip.
func roundTrips(ip string) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return false
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// outboundDCNopRetrying runs a job's outbound connection, retrying a stalled
// attempt with a fresh deadline.
//
// The retry is for the environment, not the carrier. On a host with an overlay
// interface a connection to a non-loopback address of its own can stall for
// no reason the test can see or control, and every outbound-proxy test here
// inherits it: measured over 12 runs on one such host, this test failed once
// and the pre-existing fs-carrier equivalent -- same outbound path, different
// carrier, still one attempt -- failed seven times.
//
// It does not weaken what the test proves. A carrier that could not forward a
// proxy-connect would fail all three attempts, every run; only a transient
// stall is absorbed. If all three fail the test still fails, and the error
// says so.
func outboundDCNopRetrying(t *testing.T, insideAddr, targetAddr string) error {
	t.Helper()
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = outboundDCNop(ctx, insideAddr, "<"+targetAddr+">")
		cancel()
		if err == nil {
			if attempt > 1 {
				t.Logf("the job's outbound connection succeeded on attempt %d", attempt)
			}
			return nil
		}
		t.Logf("attempt %d stalled: %v", attempt, err)
	}
	return fmt.Errorf("three attempts failed, last: %w", err)
}

// stdio: is a pipe, not a role: it works on CCB_CARRIER_LISTEN (outside) as
// well as on the inside knobs. The two ends of one pipe must take DIFFERENT
// roles -- one runs the yamux client, the other the server -- which is why an
// administrator cannot point one `-carrier-stdio` broker at another and expect
// a tunnel. This drives both halves over a single pipe to show the pairing
// that does work.
func TestStdioCarrierInTheOutsideRole(t *testing.T) {
	outPipe, inPipe := net.Pipe()

	outLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	outsideSrv, err := New(Config{
		PublicAddress:  outLn.Addr().String(),
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		CarrierListen:  "stdio:", // outside role over the inherited pipe
		CarrierPipe:    outPipe,
		Logger:         testLogger(t),
	})
	if err != nil {
		t.Fatalf("outside broker: %v", err)
	}
	octx, ocancel := context.WithCancel(context.Background())
	defer ocancel()
	go func() { _ = outsideSrv.Serve(octx, outLn) }()

	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	insideSrv, err := New(Config{
		PublicAddress:  inLn.Addr().String(),
		Security:       plaintextSec(),
		RequestTimeout: 5 * time.Second,
		CarrierPipe:    inPipe, // inside role over the other end
		Upstream: &UpstreamConfig{
			BrokerAddr:        "stdio:",
			Security:          plaintextSec(),
			HeartbeatInterval: 30 * time.Second,
		},
		Logger: testLogger(t),
	})
	if err != nil {
		t.Fatalf("inside broker: %v", err)
	}
	ictx, icancel := context.WithCancel(context.Background())
	defer icancel()
	go func() { _ = insideSrv.Serve(ictx, inLn) }()

	waitTunnelReady(t, insideSrv)
	if tc := insideSrv.TunnelContact(); !strings.HasPrefix(tc, outLn.Addr().String()+"#") {
		t.Fatalf("tunnel contact %q does not carry the outside broker's address", tc)
	}
	tunnelThrough(t, outLn.Addr().String(), inLn.Addr().String())
}
