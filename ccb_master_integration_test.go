package ccbserver_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestGoCCBUnderCondorMaster runs the Go CCB as the pool's CCB daemon under a
// real condor_master, with the collector's built-in CCB disabled, a
// non-trivial security policy (authentication REQUIRED via FS + IDTOKENS), and
// a CCB-routed execute node. It then submits a real job and waits for it to
// complete: the submit side is public but the startd is only reachable through
// the Go CCB, so the shadow->startd connection is brokered by the Go CCB. Job
// completion proves the Go CCB serves C++ daemons seamlessly.
//
// It runs under two policies the startd registers (CCB_REGISTER, at DAEMON)
// under: integrity required with encryption optional, and encryption required
// as `use security:recommended` sets it.
func TestGoCCBUnderCondorMaster(t *testing.T) {
	for _, tc := range []struct {
		name, policy string
	}{
		{"integrity", "SEC_DEFAULT_INTEGRITY = REQUIRED\nSEC_DEFAULT_ENCRYPTION = OPTIONAL"},
		{"encryption", "SEC_DEFAULT_INTEGRITY = REQUIRED\nSEC_DEFAULT_ENCRYPTION = REQUIRED"},
	} {
		t.Run(tc.name, func(t *testing.T) { testGoCCBUnderCondorMaster(t, tc.policy) })
	}
}

func testGoCCBUnderCondorMaster(t *testing.T, policy string) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}
	if _, err := exec.LookPath("condor_submit"); err != nil {
		t.Skip("condor_submit not found in PATH, skipping integration test")
	}

	tmp := t.TempDir()

	// Build the Go CCB binary the master will launch as the CCB daemon.
	ccbBin := filepath.Join(tmp, "golang-ccb")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", ccbBin, "./cmd/golang-ccb")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building golang-ccb: %v\n%s", err, out)
	}

	// A non-trivial security policy: authentication REQUIRED (FS + IDTOKENS), with
	// a real pool signing key for IDTOKENS. This is the credential material the Go
	// CCB verifies registrations against.
	passwordDir := filepath.Join(tmp, "passwords.d")
	if err := os.MkdirAll(passwordDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := security.GeneratePoolSigningKey(filepath.Join(passwordDir, "POOL")); err != nil {
		t.Fatalf("generating pool signing key: %v", err)
	}

	// Fixed TCP ports so daemons can name the collector and CCB statically. This
	// pool runs WITHOUT shared_port: the private-network partitioning that forces
	// CCB routing only works when each daemon has its own port (shared_port would
	// place every daemon behind one directly-reachable address).
	collectorPort := freePort(t)
	ccbPort := freePort(t)
	ccbAddr := fmt.Sprintf("127.0.0.1:%d", ccbPort)

	extra := fmt.Sprintf(`
# --- No shared port: give the collector a fixed, statically-nameable port ---
USE_SHARED_PORT = False
COLLECTOR_HOST = 127.0.0.1:%d

# --- Run the Go CCB as the pool's CCB daemon, and disable the collector's ---
ENABLE_CCB_SERVER = False
DAEMON_LIST = MASTER, CCB, COLLECTOR, NEGOTIATOR, SCHEDD, STARTD
CCB = %s
CCB_ARGS = -listen %s -public %s
# The Go CCB runs on a fixed TCP port (not shared_port), because forcing CCB
# routing on a single loopback host requires each daemon to have its own port
# (see USE_SHARED_PORT = False above). It is therefore a master-managed daemon
# on a static address rather than a shared-port DaemonCore daemon.
CCB_LOG = $(LOG)/CcbLog
CCB_DEBUG = D_FULLDEBUG D_SECURITY
MAX_CCB_LOG = 10000000

# --- Force the execute node behind the Go CCB ---
# The collector/negotiator/schedd/shadow stay on the default network and are
# directly reachable; the startd is on a private network and CCB-routed, so the
# shadow must reach it through the Go CCB (standard connection reversal).
PRIVATE_NETWORK_NAME = NET_DEFAULT
STARTD.PRIVATE_NETWORK_NAME = NET_EXEC
STARTD.CCB_ADDRESS = %s
ENABLE_IPV6 = FALSE
# The daemons and the Go CCB start together; retry CCB registration quickly
# after the inevitable startup race rather than the 60s default.
CCB_RECONNECT_TIME = 2
STARTD_DEBUG = D_FULLDEBUG D_NETWORK D_SECURITY D_HOSTNAME

# --- Non-trivial security ---
SEC_DEFAULT_AUTHENTICATION = REQUIRED
%s
SEC_DEFAULT_AUTHENTICATION_METHODS = FS, IDTOKENS
SEC_CLIENT_AUTHENTICATION_METHODS = FS, IDTOKENS
SEC_PASSWORD_DIRECTORY = %s
SEC_TOKEN_POOL_SIGNING_KEY_FILE = %s
TRUST_DOMAIN = ccb.test

# --- A tiny, fast vanilla job works ---
START = TRUE
SUSPEND = FALSE
CONTINUE = TRUE
PREEMPT = FALSE
KILL = FALSE
RUNBENCHMARKS = FALSE
`, collectorPort, ccbBin, ccbAddr, ccbAddr, ccbAddr, policy, passwordDir, filepath.Join(passwordDir, "POOL"))

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()

	configFile := h.GetConfigFile()
	logDir := h.GetLogDir()
	// The harness log dir lives under t.TempDir() and is deleted when the test
	// ends; preserve a copy to a stable path so the daemon logs can be inspected.
	defer saveLogs(t, logDir)

	// The startd must come up and register (it can only reach the collector, and
	// be reached, through the Go CCB path once CCB-routed).
	if err := h.WaitForStartd(90 * time.Second); err != nil {
		dumpLog(t, filepath.Join(logDir, "CcbLog"))
		dumpLog(t, filepath.Join(logDir, "StartLog"))
		t.Fatalf("startd did not become available via the Go CCB: %v", err)
	}

	// Probe the Go CCB's advertised port and see which process/address owns it.
	if c, derr := net.DialTimeout("tcp", ccbAddr, 2*time.Second); derr != nil {
		t.Logf("PROBE: cannot reach Go CCB at %s: %v", ccbAddr, derr)
	} else {
		_ = c.Close()
		t.Logf("PROBE: reached Go CCB at %s", ccbAddr)
	}
	if lsof, lerr := exec.LookPath("lsof"); lerr == nil {
		out, _ := exec.Command(lsof, "-nP", fmt.Sprintf("-iTCP:%d", ccbPort)).CombinedOutput()
		t.Logf("lsof -iTCP:%d:\n%s", ccbPort, out)
	}

	// Confirm the Go CCB actually served the pool: its log should show a daemon
	// registering (the startd) and/or a request being brokered.
	assertGoCCBActive(t, logDir)

	// Submit a trivial vanilla job and wait for it to complete. The shadow runs
	// on the (public) submit side and must reach the CCB-routed startd through
	// the Go CCB; completion proves the brokered connection works end to end.
	//
	// Force the executable (and thus a real file transfer) to exercise the CCB's
	// brokered file-transfer data path — an important, complex code path where the
	// shadow streams the sandbox to the CCB-routed starter. We transfer a small
	// shell script rather than /bin/sleep itself: macOS refuses to exec a *copied*
	// system Mach-O binary (SIP/code-signing) and stalls the starter, but a
	// transferred shell script runs fine and execs the system sleep in place.
	jobScript := filepath.Join(tmp, "ccb_job.sh")
	if err := os.WriteFile(jobScript, []byte("#!/bin/sh\nexec /bin/sleep \"$@\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	submitFile := filepath.Join(tmp, "job.sub")
	logFile := filepath.Join(tmp, "job.log")
	subContents := fmt.Sprintf(`
universe = vanilla
executable = %s
arguments = 1
log = %s
output = %s
error = %s
should_transfer_files = YES
transfer_executable = true
when_to_transfer_output = ON_EXIT
queue 1
`, jobScript, logFile, filepath.Join(tmp, "job.out"), filepath.Join(tmp, "job.err"))
	if err := os.WriteFile(submitFile, []byte(subContents), 0600); err != nil {
		t.Fatal(err)
	}

	runCondor(t, configFile, 60*time.Second, "condor_submit", submitFile)

	// condor_wait blocks until the job completes (or times out).
	runCondor(t, configFile, 180*time.Second, "condor_wait", "-wait", "150", logFile)

	// Sanity: the job log should record a termination event.
	if data, err := os.ReadFile(logFile); err != nil {
		t.Fatalf("reading job log: %v", err)
	} else if !strings.Contains(string(data), "Job terminated") {
		dumpLog(t, filepath.Join(logDir, "CcbLog"))
		dumpLog(t, filepath.Join(logDir, "ShadowLog"))
		t.Fatalf("job did not terminate normally; log:\n%s", data)
	}
	t.Log("job completed: shadow reached the CCB-routed startd through the Go CCB")
}

// freePort returns a currently-free TCP port on the loopback interface.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// assertGoCCBActive checks the Go CCB log shows it served the pool.
func assertGoCCBActive(t *testing.T, logDir string) {
	t.Helper()
	ccbLog := filepath.Join(logDir, "CcbLog")
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(ccbLog)
		if err == nil && strings.Contains(string(data), "target registered") {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	dumpLog(t, ccbLog)
	dumpLog(t, filepath.Join(logDir, "MasterLog"))
	dumpLog(t, filepath.Join(logDir, "StartLog"))
	t.Fatal("Go CCB log does not show any daemon registering")
}

func runCondor(t *testing.T, configFile string, timeout time.Duration, name string, args ...string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not found: %v", name, err)
	}
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// saveLogs copies the harness log directory to a stable location (outside the
// test's t.TempDir, which is deleted on exit) and prints the path so the daemon
// logs -- StartLog, CcbLog, MasterLog, ShadowLog -- can be inspected afterward.
func saveLogs(t *testing.T, logDir string) {
	dest, err := os.MkdirTemp("", "ccb-itest-logs-")
	if err != nil {
		t.Logf("could not preserve logs: %v", err)
		return
	}
	if out, err := exec.Command("cp", "-a", logDir+"/.", dest).CombinedOutput(); err != nil {
		t.Logf("could not copy logs to %s: %v\n%s", dest, err, out)
		return
	}
	t.Logf("preserved HTCondor logs at: %s", dest)
}

func dumpLog(t *testing.T, path string) {
	t.Helper()
	if data, err := os.ReadFile(path); err == nil {
		t.Logf("=== %s ===\n%s", filepath.Base(path), data)
	} else {
		t.Logf("(could not read %s: %v)", path, err)
	}
}

// TestGoCCBSharedPortUnderCondorMaster runs the Go CCB as a DaemonCore daemon
// behind condor_master's shared port, with FS the only authentication method,
// and sends it DC_RECONFIG with condor_reconfig through the shared port. An
// HTCondor 25.14+ FS client binds the authentication to the shared-port id it
// dialed (?sock=), so the command being decided at all proves the broker
// accepts that binding. It is first refused, as ALLOW_ADMINISTRATOR_CCB
// excludes the caller; after the configuration admits the caller and the pool
// is reconfigured (condor_master signals the broker), it runs -- the policy
// reloaded without a restart.
//
// condor_ping -table ALL against the broker reports each level's decision
// under that policy, and each level negotiated under its own SEC_<level>_*:
// READ unauthenticated, DAEMON and the ADVERTISE_* levels (which fall back to
// SEC_DAEMON_*) encrypted.
func TestGoCCBSharedPortUnderCondorMaster(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_reconfig", "condor_ping"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	ccbBin := filepath.Join(tmp, "golang-ccb")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", ccbBin, "./cmd/golang-ccb")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building golang-ccb: %v\n%s", err, out)
	}

	extra := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, CCB
DC_DAEMON_LIST = + CCB
ENABLE_CCB_SERVER = False
CCB = %s
CCB_LOG = $(LOG)/CcbLog
CCB_DEBUG = D_FULLDEBUG D_SECURITY
# cedar implements only AES-GCM; the master's family session must use it.
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
ALLOW_ADMINISTRATOR_CCB = nobody@nowhere.invalid
# Distinct per-level policies for condor_ping to report.
SEC_READ_AUTHENTICATION = NEVER
SEC_DAEMON_ENCRYPTION = REQUIRED
SEC_CLIENT_AUTHENTICATION = OPTIONAL
SEC_CLIENT_ENCRYPTION = OPTIONAL
`, ccbBin)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	configFile := h.GetConfigFile()
	logDir := h.GetLogDir()
	ccbLog := filepath.Join(logDir, "CcbLog")
	defer saveLogs(t, logDir)

	addr := "<" + waitForCCBContact(t, ccbLog) + ">"
	if !strings.Contains(addr, "sock=") {
		t.Fatalf("Go CCB contact %s is not a shared-port address", addr)
	}

	reconfigCCB := func() (string, error) {
		cmd := exec.Command("condor_reconfig", "-addr", addr)
		cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := reconfigCCB(); err == nil {
		dumpLog(t, ccbLog)
		t.Fatalf("condor_reconfig of the Go CCB ran under ALLOW_ADMINISTRATOR_CCB = nobody, want refused:\n%s", out)
	}
	if data, _ := os.ReadFile(ccbLog); !strings.Contains(string(data), "PERMISSION DENIED") {
		dumpLog(t, ccbLog)
		t.Fatal("the Go CCB did not log the refused DC_RECONFIG as PERMISSION DENIED")
	}

	table := pingTable(t, configFile, addr)
	for _, lvl := range []string{"ALLOW", "READ", "WRITE", "NEGOTIATOR", "DAEMON", "ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER"} {
		if got := table[lvl].decision; got != "ALLOW" {
			t.Errorf("condor_ping %s: decision %q, want ALLOW (table %v)", lvl, got, table)
		}
	}
	// ADMINISTRATOR_CCB admits nobody; OWNER is checked at ADMINISTRATOR; no
	// ALLOW_CONFIG is set.
	for _, lvl := range []string{"ADMINISTRATOR", "OWNER", "CONFIG"} {
		if got := table[lvl].decision; got != "FAIL" {
			t.Errorf("condor_ping %s: decision %q, want FAIL (table %v)", lvl, got, table)
		}
	}
	if got := table["READ"].auth; got != "none" {
		t.Errorf("condor_ping READ authenticated with %q, want none (SEC_READ_AUTHENTICATION = NEVER)", got)
	}
	for _, lvl := range []string{"DAEMON", "ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER"} {
		if got := table[lvl].encryption; got == "none" || got == "" {
			t.Errorf("condor_ping %s: encryption %q, want encrypted (SEC_DAEMON_ENCRYPTION = REQUIRED)", lvl, got)
		}
	}
	// A refused level is the broker's answer, not a command it lacks; a
	// permitted one reports the broker's own version.
	verbose := pingOut(t, configFile, "-addr", addr, "-verbose", "ADMINISTRATOR", "CONFIG", "READ")
	if strings.Count(verbose, `"DENIED"`) != 2 || strings.Contains(verbose, "CMD_NOT_FOUND") {
		t.Errorf("condor_ping ADMINISTRATOR and CONFIG were not both refused as DENIED:\n%s", verbose)
	}
	if !strings.Contains(verbose, "BuildID: golang-ccb") {
		t.Errorf("condor_ping READ did not report the Go CCB's version:\n%s", verbose)
	}

	// Admit the caller, and reconfigure the pool: condor_master signals the
	// broker, which rebuilds its policy.
	f, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\nALLOW_ADMINISTRATOR_CCB = *\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	runCondor(t, configFile, 30*time.Second, "condor_reconfig")

	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := reconfigCCB()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			dumpLog(t, ccbLog)
			t.Fatalf("condor_reconfig of the Go CCB still refused after the pool reconfig admitted the caller: %v\n%s", err, out)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if data, _ := os.ReadFile(ccbLog); !strings.Contains(string(data), "DC_RECONFIG received") {
		dumpLog(t, ccbLog)
		t.Fatal("the Go CCB did not log running DC_RECONFIG")
	}
	if got := pingTable(t, configFile, addr)["ADMINISTRATOR"].decision; got != "ALLOW" {
		t.Errorf("condor_ping ADMINISTRATOR after admitting the caller: decision %q, want ALLOW", got)
	}
}

// pingRow is one level's row of condor_ping -table.
type pingRow struct {
	auth, encryption, decision string
}

// pingTable runs condor_ping -table ALL against addr and returns its rows by
// level.
func pingTable(t *testing.T, configFile, addr string) map[string]pingRow {
	t.Helper()
	out := pingOut(t, configFile, "-addr", addr, "-table", "ALL")
	rows := map[string]pingRow{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] == "Instruction" {
			continue
		}
		rows[f[0]] = pingRow{auth: f[1], encryption: f[2], decision: f[4]}
	}
	if len(rows) == 0 {
		t.Fatalf("condor_ping printed no table:\n%s", out)
	}
	return rows
}

// pingOut runs condor_ping with args and returns its output. condor_ping exits
// non-zero when any level fails, so its exit status is not checked.
func pingOut(t *testing.T, configFile string, args ...string) string {
	t.Helper()
	cmd := exec.Command("condor_ping", args...)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// waitForCCBContact waits for the Go CCB to log the shared-port address it
// advertises and returns it (host:port?sock=...).
func waitForCCBContact(t *testing.T, ccbLog string) string {
	t.Helper()
	re := regexp.MustCompile(`advertising shared-port CCB contact.*address=([^ ]+)`)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(ccbLog); err == nil {
			if m := re.FindSubmatch(data); m != nil {
				return strings.Trim(string(m[1]), `"<>`)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	dumpLog(t, ccbLog)
	t.Fatal("Go CCB did not log a shared-port contact")
	return ""
}
