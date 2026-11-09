//go:build squide2e

// Package squide2e is the container tier of the tunneled-EP test: a real squid,
// a worker node with no route off its network, and the brokers between them.
//
// The fast tiers (transport/wscarrier and the package e2e tests) prove the
// protocol with an in-process CONNECT proxy. They cannot prove the deployment,
// because the things that decide whether a site deployment works are squid's
// own: which ports it will CONNECT to, which destinations it approves, whether
// it demands credentials, and what it logs. This tier runs against the real
// thing and checks that the advice the health check gives matches what squid
// actually does.
//
// It runs only inside the compose topology (see docker-compose.yml), where the
// `ep` service has no gateway to the network the broker is on. That isolation is
// structural rather than configured, which is why TestNodeHasNoRouteOut runs
// first: if it ever passes a direct connection, every assertion after it is
// vacuous.
package squide2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

const (
	sharedDir   = "/shared"
	ccbBinary   = "/usr/local/bin/golang-ccb"
	carrierHost = "ccb.offsite.test"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func carrierURL() string { return env("CARRIER_URL", "wss://"+carrierHost+"/ccb/tunnel") }
func proxyURL() string   { return env("PROXY_URL", "http://squid:3128") }
func squidLog() string   { return env("SQUID_LOG", "/squidlogs/access.log") }
func targetAddr() string { return env("TARGET_ADDR", carrierHost+":9700") }

// outsidePublic is the address the outside broker advertises in contacts, which
// a nested contact must name.
func outsidePublic() string { return env("OUTSIDE_PUBLIC", carrierHost+":9618") }

func TestMain(m *testing.M) {
	// Outside the compose topology there is no shared volume, and waiting for
	// one would just hang for the timeout -- including for -test.list. Say so
	// at once instead, because a stray local run is a mistake, not a failure.
	if _, err := os.Stat(sharedDir); err != nil {
		fmt.Fprintf(os.Stderr,
			"squid e2e: %s is not present, so this is not the compose topology.\n"+
				"Run it with:  cd test/e2e-squid && docker compose up --build --abort-on-container-exit --exit-code-from ep\n",
			sharedDir)
		os.Exit(2)
	}
	if err := waitForMaterial(2 * time.Minute); err != nil {
		fmt.Fprintln(os.Stderr, "squid e2e: the offsite container never published its material:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// waitForMaterial blocks until the offsite container has published the CA and
// the pool signing key. The containers start concurrently and nothing else
// orders them.
func waitForMaterial(within time.Duration) error {
	deadline := time.Now().Add(within)
	marker := filepath.Join(sharedDir, "material.ready")
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("%s did not appear within %s", marker, within)
}

// TestNodeHasNoRouteOut is the premise everything else rests on. The `ep`
// service sits on a Docker network declared `internal: true`, so it has no
// gateway to the network the broker is on and no DNS entry for it either --
// name resolution happens at the proxy, inside the CONNECT, which is how a real
// restricted node behaves.
//
// If this test ever passes a direct connection, the topology has been broken and
// every "it worked through the proxy" assertion below would be satisfied by a
// carrier that ignored the proxy entirely.
func TestNodeHasNoRouteOut(t *testing.T) {
	if _, err := net.LookupHost(carrierHost); err == nil {
		t.Fatalf("%s resolves from the worker node; it must only be resolvable at the proxy", carrierHost)
	}

	// Belt and braces: even given an address, there must be no route. Ask the
	// proxy's resolver for one and try it directly.
	for _, hostport := range []string{carrierHost + ":443", outsidePublic()} {
		conn, err := net.DialTimeout("tcp", hostport, 5*time.Second)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("direct connection to %s succeeded; the worker node is not isolated", hostport)
		}
		t.Logf("no direct route to %s (%v) -- as required", hostport, err)
	}
}

// mintToken issues an HTCondor IDTOKEN against the shared pool signing key, the
// way a pilot would be handed one.
func mintToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	tok, err := security.GenerateJWT(
		filepath.Join(sharedDir, "passwords.d"), "POOL",
		"pilot@offsite.test", "offsite.test",
		now.Unix(), now.Add(time.Hour).Unix(), nil,
	)
	if err != nil {
		t.Fatalf("minting an IDTOKEN: %v", err)
	}
	return tok
}

// insideConfig writes a condor_config for the node's inside broker. nextHop
// overrides the carrier endpoint so a test can point it somewhere squid refuses.
func insideConfig(t *testing.T, dir, nextHop string) string {
	t.Helper()
	if nextHop == "" {
		nextHop = carrierURL()
	}
	cfg := fmt.Sprintf(`LOG = %[1]s
LOCK = %[1]s
RUN = %[1]s
SPOOL = %[1]s
EXECUTE = %[1]s
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_ENCRYPTION = OPTIONAL
SEC_DEFAULT_INTEGRITY = OPTIONAL
ALLOW_DAEMON = *
ALLOW_READ = *
CCB_OUTBOUND_PROXY = TRUE
CCB_OUTBOUND_NEXT_HOP = %[2]s
CCB_OUTBOUND_TARGET_ALLOWLIST = 0.0.0.0/0
CCB_CARRIER_PROXY = %[3]s
CCB_CARRIER_CA_FILE = %[4]s/ca.pem
CCB_CARRIER_TOKEN = %[5]s
CCB_TUNNEL_READY_FILE = %[1]s/tunnel_ready
CCB_CARRIER_READY_TIMEOUT = 60
`, dir, nextHop, proxyURL(), sharedDir, mintToken(t))

	path := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// carrierCheck runs `golang-ccb -carrier-check` against a config and returns its
// report and whether it passed.
func carrierCheck(t *testing.T, nextHop string) (report string, ok bool) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := insideConfig(t, dir, nextHop)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ccbBinary, "-listen", "127.0.0.1:0", "-carrier-check")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+cfgPath)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// TestCarrierCheckPassesThroughSquid: every stage green against a real proxy.
func TestCarrierCheckPassesThroughSquid(t *testing.T) {
	report, ok := carrierCheck(t, "")
	t.Logf("carrier-check report:\n%s", report)
	if !ok {
		t.Fatalf("carrier check failed against the real proxy")
	}
	for _, want := range []string{"tcp-reachable", "proxy-connect", "tls", "websocket-upgrade", "far-broker-cedar"} {
		if !strings.Contains(report, want) {
			t.Errorf("report does not mention the %s stage", want)
		}
	}
	if !strings.Contains(report, "via "+proxyURL()) {
		t.Errorf("report does not name the proxy route")
	}
	if strings.Contains(report, "FAIL") {
		t.Errorf("report contains a failing stage")
	}
}

// TestSquidDeniesCarrierOnNonSSLPort is the single most likely first failure at
// a real site, and the reason the outside broker's carrier must listen on 443: a
// stock squid.conf carries `http_access deny CONNECT !SSL_ports`.
//
// It also checks the health check's ADVICE against what squid really sends. The
// advice is only worth having if it names the rule that actually fired.
func TestSquidDeniesCarrierOnNonSSLPort(t *testing.T) {
	report, ok := carrierCheck(t, "wss://"+carrierHost+":9618/ccb/tunnel")
	t.Logf("carrier-check report:\n%s", report)
	if ok {
		t.Fatal("squid tunneled CONNECT to a non-443 port; the SSL_ports rule is not in effect, so this test proves nothing")
	}
	if !strings.Contains(report, "proxy-connect") || !strings.Contains(report, "FAIL") {
		t.Fatalf("the failure was not reported against the proxy-connect stage")
	}
	if !strings.Contains(report, "443") {
		t.Errorf("the advice does not point at the port policy, which is the actual cause")
	}
}

// TestSquidDeniesUnapprovedDestination: the site approves destinations by name.
func TestSquidDeniesUnapprovedDestination(t *testing.T) {
	report, ok := carrierCheck(t, "wss://not-approved.offsite.test/ccb/tunnel")
	t.Logf("carrier-check report:\n%s", report)
	if ok {
		t.Fatal("squid tunneled to an unapproved destination")
	}
	if !strings.Contains(report, "proxy-connect") {
		t.Errorf("the failure was not reported against the proxy-connect stage")
	}
}

// insideBroker starts the node's inside broker and waits for it to register
// upstream through squid.
func insideBroker(t *testing.T) (addr string, logDir string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := insideConfig(t, dir, "")
	addr = "127.0.0.1:9800"

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, ccbBinary, "-listen", addr, "-public", addr)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+cfgPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("starting the inside broker: %v", err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })

	// The ready file is written once upstream registration completes, which is
	// the only signal that means contacts will nest.
	ready := filepath.Join(dir, "tunnel_ready")
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			return addr, dir
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("the inside broker never registered upstream through squid (no %s)", ready)
	return "", ""
}

// TestTunneledEPThroughSquid is the whole point: a node with no route out runs a
// broker, registers an EP behind it, and the EP's advertised contact names the
// OUTSIDE broker -- so the pool can reach it -- while its own outbound
// connections reach an offsite target. Both directions, through real squid, over
// one connection.
func TestTunneledEPThroughSquid(t *testing.T) {
	brokerAddr, _ := insideBroker(t)

	// Baseline AFTER the carrier is up. Two things make an absolute count the
	// wrong measure: the startup health check deliberately opens its own
	// short-lived connection to probe the upgrade, and squid logs a tunnel only
	// when it CLOSES, so the live one is not in the log yet. What matters is
	// that nothing opens another once the node is working.
	established := countTunnels(t)

	// Inbound side: an EP registering with the local broker must be given a
	// nested contact naming the outside broker.
	contact := registerEP(t, brokerAddr)
	t.Logf("EP contact: %s", contact)
	if strings.Count(contact, "#") < 2 {
		t.Fatalf("EP contact %q is not nested; the pool could not reach it", contact)
	}
	if !strings.HasPrefix(contact, outsidePublic()+"#") {
		t.Fatalf("EP contact %q does not name the outside broker %q", contact, outsidePublic())
	}

	// Outbound side: several independent connections to an offsite target,
	// relayed inside broker -> squid -> outside broker -> dial.
	const rounds = 3
	for i := range rounds {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		err := outboundDCNop(ctx, brokerAddr, "<"+targetAddr()+">")
		cancel()
		if err != nil {
			t.Fatalf("outbound round %d through the tunnel: %v", i, err)
		}
	}

	// The node's entire footprint, inbound and outbound, is one proxied
	// connection: that is what a site throttling socket counts is buying. Measure
	// it where a site would -- the live sockets leaving the node -- which is also
	// what the administrator's guide tells them to check with ss(1).
	if live := establishedToProxy(t); live != 1 {
		t.Errorf("the node holds %d connections to the proxy while working, want exactly 1", live)
	}

	// And nothing re-dialled: no further tunnel completed while the node worked.
	if opened := countTunnels(t) - established; opened != 0 {
		t.Errorf("squid completed %d more tunnels while the node was working; "+
			"the carrier should have carried everything over the one it had", opened)
	}
}

// establishedToProxy counts this container's ESTABLISHED TCP connections to the
// proxy. /proc/net/tcp is per network namespace, so it covers every process on
// the "node", which is the footprint a site actually cares about -- and the
// measurement an administrator makes with `ss -tn state established`.
func establishedToProxy(t *testing.T) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(proxyURL(), "http://"))
	if err != nil {
		t.Fatalf("parsing %q: %v", proxyURL(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("proxy port %q: %v", portStr, err)
	}
	// /proc/net/tcp renders the remote endpoint as HEXADDR:HEXPORT, and state 01
	// is ESTABLISHED.
	wantPort := fmt.Sprintf("%04X", port)

	total := 0
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue // tcp6 may be absent
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "01" {
				continue
			}
			if i := strings.LastIndex(f[2], ":"); i >= 0 && f[2][i+1:] == wantPort {
				total++
			}
		}
	}
	return total
}

// registerEP registers a CEDAR listener with the local broker and returns the
// contact it is given.
func registerEP(t *testing.T, brokerAddr string) string {
	t.Helper()
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        brokerAddr,
		Security:          plaintextSec(),
		Name:              "squid-e2e-ep",
		HeartbeatInterval: 30 * time.Second,
		Handler:           func(conn net.Conn, _ ccb.InboundMeta) { _ = conn.Close() },
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = lis.Run(ctx) }()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if c := lis.Contact(); c != "" {
			return c
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the EP never received a contact from the inside broker")
	return ""
}

func plaintextSec() *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{},
		Authentication: security.SecurityNever,
		Encryption:     security.SecurityNever,
		Integrity:      security.SecurityNever,
		RemoteVersion:  "$CondorVersion: 25.13.0 2026-06-21 BuildID: e2e $",
	}
}

// outboundDCNop asks the broker to reach target and runs an end-to-end CEDAR
// handshake over the relayed connection.
func outboundDCNop(ctx context.Context, brokerAddr, target string) error {
	conn, err := ccb.OutboundConnect(ctx, brokerAddr, target, ccb.OutboundOptions{
		Security: plaintextSec(),
		Name:     "squid-e2e",
		Timeout:  30 * time.Second,
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	s := stream.NewStream(conn)
	s.SetPeerAddr(target)
	cfg := *plaintextSec()
	cfg.Command = commands.DC_NOP
	_, err = security.NewAuthenticator(&cfg, s).ClientHandshake(ctx)
	return err
}

// countTunnels counts squid's successful CONNECT tunnels to the carrier
// endpoint. squid's own log is the independent witness here: it is the only
// party that can say the traffic went through the proxy rather than around it.
func countTunnels(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(squidLog())
	if err != nil {
		if os.IsNotExist(err) {
			return 0 // nothing has been logged yet
		}
		t.Fatalf("reading %s: %v", squidLog(), err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "TCP_TUNNEL") && strings.Contains(line, carrierHost+":443") {
			n++
		}
	}
	return n
}
