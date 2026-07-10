package ccbserver_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestGoCCBUnderCondorMaster runs the Go CCB as the pool's CCB daemon under a
// real condor_master, with the collector's built-in CCB disabled, a
// non-trivial security policy (authentication REQUIRED via FS + IDTOKENS;
// encryption/integrity optional, since the CCB path is plaintext and the real
// peers secure themselves end to end), and a CCB-routed execute node. It then submits a real job and
// waits for it to complete: the submit side is public but the startd is only
// reachable through the Go CCB, so the shadow->startd connection is brokered by
// the Go CCB. Job completion proves the Go CCB serves C++ daemons seamlessly.
func TestGoCCBUnderCondorMaster(t *testing.T) {
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
SEC_DEFAULT_INTEGRITY = REQUIRED
SEC_DEFAULT_ENCRYPTION = OPTIONAL
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
`, collectorPort, ccbBin, ccbAddr, ccbAddr, ccbAddr, passwordDir, filepath.Join(passwordDir, "POOL"))

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
