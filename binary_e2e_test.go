package ccbserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// launchCCBBinary starts one golang-ccb process with the given extra config and
// waits until it accepts connections. Returns its "127.0.0.1:port" address. The
// process runs with SEC_* OPTIONAL + ALLOW_* = * so an unauthenticated test
// client is accepted (the CCB path is plaintext by design).
func launchCCBBinary(t *testing.T, bin, extraConfig string) string {
	t.Helper()
	dir := t.TempDir()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfgPath := filepath.Join(dir, "condor_config")
	cfg := fmt.Sprintf(`LOG = %s
LOCK = %s
RUN = %s
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_ENCRYPTION = OPTIONAL
SEC_DEFAULT_INTEGRITY = OPTIONAL
ALLOW_DAEMON = *
ALLOW_READ = *
CCB_OUTBOUND_PROXY = true
%s
`, dir, dir, dir, extraConfig)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "-listen", addr, "-public", addr)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+cfgPath)
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("starting golang-ccb: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			if b, err := os.ReadFile(filepath.Join(dir, "CcbLog")); err == nil {
				t.Logf("CcbLog(%s):\n%s", addr, b)
			}
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("golang-ccb at %s did not start listening in time", addr)
	return ""
}

// launchBinaryChain launches n golang-ccb processes: an exit CCB that dials
// targetIP directly, then n-1 inside CCBs each pointing at the previous as its
// next hop. Returns the entry (innermost) broker address.
func launchBinaryChain(t *testing.T, bin string, n int, targetIP string) string {
	t.Helper()
	entry := launchCCBBinary(t, bin, "CCB_OUTBOUND_TARGET_ALLOWLIST = "+targetIP+"/32")
	for i := 1; i < n; i++ {
		entry = launchCCBBinary(t, bin, "CCB_OUTBOUND_NEXT_HOP = "+entry)
	}
	return entry
}

// TestBinaryTunnelChain is the process-level end-to-end test: it compiles the
// golang-ccb binary and relays bulk data across chains of 1, 2, and 3 launched
// CCB processes -- exercising the daemon's config wiring (CCB_OUTBOUND_PROXY /
// _NEXT_HOP / _TARGET_ALLOWLIST) and its client-security building, which the
// in-process library tests do not cover.
func TestBinaryTunnelChain(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level CCB chain test skipped under -short")
	}
	bin := buildCCBBinary(t)
	targetIP := nonLoopbackIPv4(t)

	for _, n := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("%dCCB", n), func(t *testing.T) {
			size := int64(8 << 20)
			tgtAddr, stopTgt := startBulkTarget(t, targetIP, size)
			defer stopTgt()

			entry := launchBinaryChain(t, bin, n, targetIP)

			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			conn, err := ccb.OutboundConnect(ctx, entry, "<"+tgtAddr+">", ccb.OutboundOptions{
				Security: plaintextSec(),
				Name:     "bin-bw",
				Timeout:  30 * time.Second,
			})
			if err != nil {
				t.Fatalf("OutboundConnect through %d launched CCB(s): %v", n, err)
			}
			defer func() { _ = conn.Close() }()

			start := time.Now()
			if err := blast(conn, size); err != nil {
				t.Fatalf("bulk relay through %d launched CCB(s): %v", n, err)
			}
			t.Logf("%d launched-CCB chain: %d MiB each way in %v", n, size>>20, time.Since(start).Round(time.Millisecond))
		})
	}
}

// buildCCBBinary compiles the golang-ccb command into a temporary directory.
func buildCCBBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "golang-ccb")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "./cmd/golang-ccb").CombinedOutput(); err != nil {
		t.Fatalf("building golang-ccb: %v\n%s", err, out)
	}
	return bin
}

// encryptedPolicy requires encryption and integrity of every session, as
// `use security:recommended` does.
const encryptedPolicy = `SEC_DEFAULT_ENCRYPTION = REQUIRED
SEC_DEFAULT_INTEGRITY = REQUIRED
`

// encryptedSec is a client policy requiring an encrypted (AES-GCM, so also
// integrity-protected) session, without authenticating.
func encryptedSec() *security.SecurityConfig {
	s := plaintextSec()
	s.CryptoMethods = []security.CryptoMethod{security.CryptoAES}
	s.Encryption = security.SecurityRequired
	s.Integrity = security.SecurityRequired
	return s
}

// TestBinaryTunnelsEncrypted runs launched brokers under a policy requiring
// encryption, so every broker session -- a requester's, a registrant's, and an
// inside CCB's own sessions with its next hop -- is encrypted, while the
// relayed bytes are spliced raw: an outbound 2-CCB chain relays bulk data, and
// a client reaches an EP behind a 2-CCB inbound tunnel by its nested contact.
func TestBinaryTunnelsEncrypted(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level CCB test skipped under -short")
	}
	bin := buildCCBBinary(t)

	t.Run("outbound", func(t *testing.T) {
		targetIP := nonLoopbackIPv4(t)
		size := int64(1 << 20)
		tgtAddr, stopTgt := startBulkTarget(t, targetIP, size)
		defer stopTgt()
		exit := launchCCBBinary(t, bin, encryptedPolicy+"CCB_OUTBOUND_TARGET_ALLOWLIST = "+targetIP+"/32")
		entry := launchCCBBinary(t, bin, encryptedPolicy+"CCB_OUTBOUND_NEXT_HOP = "+exit)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, err := ccb.OutboundConnect(ctx, entry, "<"+tgtAddr+">", ccb.OutboundOptions{
			Security: encryptedSec(),
			Name:     "bin-encrypted",
			Timeout:  15 * time.Second,
		})
		if err != nil {
			t.Fatalf("OutboundConnect through 2 encrypted CCBs: %v", err)
		}
		defer func() { _ = conn.Close() }()
		if err := blast(conn, size); err != nil {
			t.Fatalf("bulk relay through 2 encrypted CCBs: %v", err)
		}
	})

	t.Run("inbound", func(t *testing.T) {
		outside := launchCCBBinary(t, bin, encryptedPolicy)
		readyFile := filepath.Join(t.TempDir(), "ccb_tunnel_ready")
		inside := launchCCBBinary(t, bin, encryptedPolicy+"CCB_OUTBOUND_NEXT_HOP = "+outside+"\nCCB_TUNNEL_READY_FILE = "+readyFile)
		deadline := time.Now().Add(10 * time.Second)
		for {
			if data, err := os.ReadFile(readyFile); err == nil && strings.TrimSpace(string(data)) != "" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("inside CCB never registered with the outside CCB")
			}
			time.Sleep(50 * time.Millisecond)
		}

		served := make(chan struct{}, 1)
		ep := cedarserver.New(plaintextSec())
		ep.Handle(commands.DC_NOP, func(_ context.Context, _ *cedarserver.Conn) error {
			select {
			case served <- struct{}{}:
			default:
			}
			return nil
		})
		lis := ccb.NewListener(ccb.ListenerConfig{
			BrokerAddr:        inside,
			Security:          encryptedSec(),
			Name:              "encrypted-ep",
			HeartbeatInterval: 30 * time.Second,
			Handler:           func(conn net.Conn, _ ccb.InboundMeta) { _ = ep.ServeConn(context.Background(), conn) },
		})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		go func() { _ = lis.Run(ctx) }()
		var contact string
		for contact == "" {
			if ctx.Err() != nil {
				t.Fatal("EP did not register with the inside CCB")
			}
			contact = lis.Contact()
			time.Sleep(10 * time.Millisecond)
		}
		if strings.Count(contact, "#") < 2 {
			t.Fatalf("EP contact %q is not nested", contact)
		}

		conn, err := ccb.Dial(ctx, contactsFor(t, contact), ccb.DialOptions{
			Security:   encryptedSec(),
			TargetDesc: "encrypted-ep",
			Timeout:    15 * time.Second,
		})
		if err != nil {
			t.Fatalf("Dial nested contact %q through encrypted CCBs: %v", contact, err)
		}
		defer func() { _ = conn.Close() }()
		if err := endToEndDCNop(ctx, conn, contact); err != nil {
			t.Fatalf("end-to-end DC_NOP through the encrypted tunnel: %v", err)
		}
		select {
		case <-served:
		case <-ctx.Done():
			t.Fatal("EP DC_NOP did not dispatch through the encrypted tunnel")
		}
	})
}
