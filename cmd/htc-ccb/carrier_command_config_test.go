package main

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCarrierCommandSettingsFromConfig(t *testing.T) {
	cfg := proxyConfig(t, strings.Join([]string{
		"CCB_CARRIER_LISTEN = tcp://127.0.0.1:9700",
		"CCB_CARRIER_COMMAND_DIR = /var/lib/condor",
		"CCB_CARRIER_COMMAND_GRACE = 7",
		"CCB_CARRIER_RETRY_INITIAL = 3",
		"CCB_CARRIER_RETRY_MAX = 300",
	}, "\n"))

	cc, err := buildCarrierSettings(cfg, nil, "", nil, nil)
	if err != nil {
		t.Fatalf("buildCarrierSettings: %v", err)
	}
	if cc.listen != "tcp://127.0.0.1:9700" {
		t.Errorf("listen = %q", cc.listen)
	}
	if cc.commandDir != "/var/lib/condor" {
		t.Errorf("commandDir = %q", cc.commandDir)
	}
	if cc.commandGrace != 7*time.Second {
		t.Errorf("commandGrace = %s, want 7s", cc.commandGrace)
	}
	if cc.retryInitial != 3*time.Second || cc.retryMax != 300*time.Second {
		t.Errorf("retry = %s/%s, want 3s/300s", cc.retryInitial, cc.retryMax)
	}
}

// Unset means "use the default", and so does a value that makes no sense. A
// typo in a seconds knob must not quietly become an aggressive value -- a
// CCB_CARRIER_RETRY_MAX of "60s" (with the unit) parses as no number at all,
// and reading it as 0 seconds would spawn an ssh per failure with no pause.
func TestCarrierSecondsKnobsFallBackToTheDefault(t *testing.T) {
	cfg := proxyConfig(t, strings.Join([]string{
		"CCB_CARRIER_COMMAND_GRACE = 60s",
		"CCB_CARRIER_RETRY_INITIAL = -5",
		"CCB_CARRIER_RETRY_MAX =",
	}, "\n"))
	for _, key := range []string{"CCB_CARRIER_COMMAND_GRACE", "CCB_CARRIER_RETRY_INITIAL", "CCB_CARRIER_RETRY_MAX"} {
		if got := configSeconds(cfg, key); got != 0 {
			t.Errorf("configSeconds(%s) = %s, want 0 (meaning: use the default)", key, got)
		}
	}
	if got := configSeconds(cfg, "CCB_CARRIER_NOT_SET_AT_ALL"); got != 0 {
		t.Errorf("configSeconds of an unset knob = %s, want 0", got)
	}
}

// The child inherits the broker's environment -- that is how ssh finds HOME,
// SSH_AUTH_SOCK and KRB5CCNAME -- and the knob adds to it rather than replacing
// it. A nil result means "inherit", which is not the same as an empty slice.
func TestCarrierCommandEnv(t *testing.T) {
	t.Setenv("CCB_TEST_INHERITED", "yes")

	if got := carrierCommandEnv(proxyConfig(t, "")); got != nil {
		t.Errorf("unset knob gave %v, want nil (inherit the broker's environment)", got)
	}

	got := carrierCommandEnv(proxyConfig(t, "CCB_CARRIER_COMMAND_ENV = HOME=/var/lib/condor SSH_AUTH_SOCK=/run/agent"))
	if !slices.Contains(got, "HOME=/var/lib/condor") || !slices.Contains(got, "SSH_AUTH_SOCK=/run/agent") {
		t.Errorf("configured entries missing from %v", got)
	}
	if !slices.Contains(got, "CCB_TEST_INHERITED=yes") {
		t.Error("the broker's own environment was dropped rather than added to")
	}
	// An override must come after the inherited copy, since exec takes the last.
	home := -1
	for i, e := range got {
		if strings.HasPrefix(e, "HOME=") {
			home = i
		}
	}
	if home == -1 || got[home] != "HOME=/var/lib/condor" {
		t.Errorf("the configured HOME does not win; last HOME entry is %q", got[home])
	}
	if len(got) <= len(os.Environ()) {
		t.Error("the configured entries were not added to the inherited environment")
	}
}
