package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"

	ccbserver "github.com/bbockelm/golang-ccb"
)

// These tests serve the broker the way run does -- newBroker under
// serveBroker -- and reach it as a chosen identity: a session pre-shared with
// the broker and attributed to that identity there, as condor_master's family
// session is.

type testBroker struct {
	t         *testing.T
	addr      string
	cfgFile   string
	cache     *security.SessionCache
	reconfigs atomic.Int32
}

// startTestBroker serves a broker under the ALLOW_/DENY_ knobs, from a
// configuration file reloaded on reconfig.
func startTestBroker(t *testing.T, knobs map[string]string) *testBroker {
	t.Helper()
	b := &testBroker{
		t:       t,
		cfgFile: filepath.Join(t.TempDir(), "condor_config"),
		cache:   security.NewSessionCache(),
	}
	b.writeConfig(knobs)
	t.Setenv("CONDOR_CONFIG", b.cfgFile)
	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "CCB"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatal(err)
	}
	d, err := daemon.New(daemon.Options{Subsys: "CCB", Config: cfg, Logger: log, ShutdownGrace: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b.addr = ln.Addr().String()
	srv, az, err := newBroker(d, ccbserver.Config{
		PublicAddress: b.addr,
		Security: &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{security.AuthFS},
			Authentication: security.SecurityOptional,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityOptional,
			Integrity:      security.SecurityOptional,
			SessionCache:   b.cache,
		},
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Runs after the policy reload newBroker registered.
	d.OnReconfig(func(*config.Config) { b.reconfigs.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = serveBroker(ctx, d, srv, az, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return b
}

func (b *testBroker) writeConfig(knobs map[string]string) {
	b.t.Helper()
	var sb strings.Builder
	sb.WriteString("LOCAL_CONFIG_FILE =\nLOCAL_CONFIG_DIR =\n")
	for k, v := range knobs {
		fmt.Fprintf(&sb, "%s = %s\n", k, v)
	}
	if err := os.WriteFile(b.cfgFile, []byte(sb.String()), 0o600); err != nil {
		b.t.Fatal(err)
	}
}

// as returns a client security config that resumes a session the broker
// attributes to identity.
func (b *testBroker) as(identity string) *security.SecurityConfig {
	b.t.Helper()
	minted, err := security.MintClaimSession(b.cache, security.MintClaimOptions{
		Sinful:  "<127.0.0.1:1>",
		PeerFQU: identity,
	})
	if err != nil {
		b.t.Fatal(err)
	}
	cc := security.NewSessionCache()
	sid, err := security.ImportClaimSession(cc, minted.ClaimID(), security.ClaimSessionOptions{PeerFQU: "ccb@pool"})
	if err != nil {
		b.t.Fatal(err)
	}
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionID:      sid,
		SessionCache:   cc,
	}
}

// reconfig sends DC_RECONFIG as sec's identity and reports whether the
// broker reconfigured.
func (b *testBroker) reconfig(sec *security.SecurityConfig) bool {
	b.t.Helper()
	before := b.reconfigs.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs := *sec
	cs.Command = commands.DC_RECONFIG
	if cl, err := client.ConnectAndAuthenticate(ctx, b.addr, &cs); err == nil {
		if message.NewMessageForStream(cl.GetStream()).FinishMessage(ctx) == nil {
			// DC_RECONFIG has no reply; the broker closes the connection once
			// it has run.
			_, _ = message.NewMessageFromStream(cl.GetStream()).GetInt(ctx)
		}
		_ = cl.Close()
	}
	return b.reconfigs.Load() > before
}

// request sends a CCB_REQUEST as sec's identity and reports whether the broker
// ran it: an authorized request for an unknown target is answered with a
// failure result, a refused one is not answered.
func (b *testBroker) request(sec *security.SecurityConfig) bool {
	b.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs := *sec
	cs.Command = ccb.CommandRequest
	cl, err := client.ConnectAndAuthenticate(ctx, b.addr, &cs)
	if err != nil {
		return false
	}
	defer func() { _ = cl.Close() }()
	if err := ccb.WriteControlAd(ctx, cl.GetStream(), ccb.NewAd(map[string]any{
		ccb.AttrCCBID:     "999",
		ccb.AttrClaimID:   "connect-id",
		ccb.AttrMyAddress: "<127.0.0.1:1>",
	})); err != nil {
		return false
	}
	reply, err := ccb.ReadControlAd(ctx, cl.GetStream())
	if err != nil {
		return false
	}
	return strings.Contains(ccb.AdString(reply, ccb.AttrErrorString), "no target registered")
}

// TestFamilyReconfigsUnderRestrictiveAdmin: condor_master's family session
// reconfigures the broker although ALLOW_ADMINISTRATOR names only admin@pool
// and DENY_ADMINISTRATOR names every condor identity; another condor identity
// is refused.
func TestFamilyReconfigsUnderRestrictiveAdmin(t *testing.T) {
	b := startTestBroker(t, map[string]string{
		"ALLOW_ADMINISTRATOR": "admin@pool",
		"DENY_ADMINISTRATOR":  "condor@*",
	})
	if !b.reconfig(b.as(authz.FamilyFQU)) {
		t.Fatal("DC_RECONFIG as condor@family refused")
	}
	if b.reconfig(b.as("condor@pool")) {
		t.Fatal("DC_RECONFIG as condor@pool ran, want refused")
	}
	if !b.reconfig(b.as("admin@pool")) {
		t.Fatal("DC_RECONFIG as admin@pool refused")
	}
}

// TestPolicyReloadWithoutRestart: a reconfig rebuilds the broker's policy from
// the changed configuration file, so the next CCB command is decided by it.
func TestPolicyReloadWithoutRestart(t *testing.T) {
	b := startTestBroker(t, map[string]string{"ALLOW_READ": "alice@pool"})
	if b.request(b.as("bob@pool")) {
		t.Fatal("CCB_REQUEST as bob@pool ran before reconfig, want refused")
	}
	if !b.request(b.as("alice@pool")) {
		t.Fatal("CCB_REQUEST as alice@pool refused before reconfig")
	}

	b.writeConfig(map[string]string{"ALLOW_READ_CCB": "bob@pool"})
	if !b.reconfig(b.as(authz.FamilyFQU)) {
		t.Fatal("DC_RECONFIG as condor@family refused")
	}
	if !b.request(b.as("bob@pool")) {
		t.Fatal("CCB_REQUEST as bob@pool refused after reconfig added him")
	}
	if b.request(b.as("alice@pool")) {
		t.Fatal("CCB_REQUEST as alice@pool ran after reconfig dropped her, want refused")
	}
}
