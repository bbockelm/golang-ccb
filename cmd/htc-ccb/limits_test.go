package main

import (
	"path/filepath"
	"testing"

	"github.com/htcondor/cedar/security"
	"github.com/htcondor/golang-htcondor/config"
	"github.com/htcondor/golang-htcondor/logging"

	ccbserver "github.com/bbockelm/golang-ccb"
)

// TestBrokerLimitsDerivesSpliceCap: with CCB_LIMIT_MAX_SPLICES_TOTAL unset the
// broker-wide relay cap comes from the descriptor limit; set, even to 0, it
// is what the administrator said.
func TestBrokerLimitsDerivesSpliceCap(t *testing.T) {
	n := descriptorLimit()
	if n == 0 {
		t.Skip("no finite descriptor limit on this platform")
	}
	cfg := config.NewEmpty()
	l, err := brokerLimits(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := int(n / spliceDescriptorShare); l.Total.MaxSplices != want {
		t.Errorf("derived MaxSplices = %d, want %d", l.Total.MaxSplices, want)
	}
	cfg.Set("CCB_LIMIT_MAX_SPLICES_TOTAL", "0")
	if l, err = brokerLimits(cfg); err != nil || l.Total.MaxSplices != 0 {
		t.Errorf("explicit 0 gave %d, %v; want unlimited", l.Total.MaxSplices, err)
	}
}

// TestReloadLimitsKeepsPolicyOnError: a reconfig whose limits do not parse
// leaves the policy in force alone.
func TestReloadLimitsKeepsPolicyOnError(t *testing.T) {
	log, err := logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ccbserver.New(ccbserver.Config{
		PublicAddress: "127.0.0.1:1",
		Security:      plaintextTestSec(),
		Limits:        ccbserver.Limits{Default: ccbserver.ClassLimits{MaxPending: 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bad := config.NewEmpty()
	bad.Set("CCB_LIMIT_REQUEST_RATE", "fast")
	reloadLimits(log, srv, bad)
	if got := srv.Limits().Default.MaxPending; got != 3 {
		t.Errorf("after a bad reconfig MaxPending = %d, want the previous 3", got)
	}
	good := config.NewEmpty()
	good.Set("CCB_LIMIT_MAX_PENDING", "9")
	reloadLimits(log, srv, good)
	if got := srv.Limits().Default.MaxPending; got != 9 {
		t.Errorf("after a good reconfig MaxPending = %d, want 9", got)
	}
}

func plaintextTestSec() *security.SecurityConfig {
	return &security.SecurityConfig{
		Authentication: security.SecurityNever,
		Encryption:     security.SecurityNever,
		Integrity:      security.SecurityNever,
	}
}
