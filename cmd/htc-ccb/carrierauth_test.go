package main

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	ccbserver "github.com/bbockelm/golang-ccb"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// buildSettings resolves carrier settings from config text, as run does.
func buildSettings(t *testing.T, text string, nextHop string, up *ccbserver.UpstreamConfig) (carrierSettings, error) {
	t.Helper()
	cfg := testConfig(t, text)
	return buildCarrierSettings(cfg, &security.SecurityConfig{}, nextHop, up, quietLogger())
}

// TestCarrierAuthDefaultsToToken pins backward compatibility: an existing
// configuration that says nothing about CCB_CARRIER_AUTH keeps requiring a
// bearer token on both sides.
func TestCarrierAuthDefaultsToToken(t *testing.T) {
	cc, err := buildSettings(t, `
CCB_CARRIER_LISTEN = ws://127.0.0.1:18080/ccb/tunnel
`, "ws://outside:443/ccb/tunnel", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cc.unauthenticated {
		t.Fatal("CCB_CARRIER_AUTH defaulted to none; existing deployments would stop presenting a token")
	}
	if cc.verify == nil {
		t.Fatal("no token verifier was built for a ws:// listener by default")
	}
	if cc.tokenSource == nil && cc.token == "" {
		t.Fatal("no client credential was arranged by default")
	}
}

// TestCarrierAuthNoneDropsCredentials: with the knob set, no verifier is built
// and no token is discovered -- so nothing reaches a proxy, and a node without
// a token can still dial.
func TestCarrierAuthNoneDropsCredentials(t *testing.T) {
	cc, err := buildSettings(t, `
CCB_CARRIER_AUTH = none
CCB_CARRIER_LISTEN = ws://127.0.0.1:18080/ccb/tunnel
CCB_CARRIER_TOKEN = a-token-that-must-not-be-sent
`, "ws://outside:443/ccb/tunnel", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cc.unauthenticated {
		t.Fatal("CCB_CARRIER_AUTH = none was not honored")
	}
	if cc.verify != nil {
		t.Fatal("a token verifier was built although the carrier is unauthenticated")
	}
	if cc.token != "" || cc.tokenSource != nil {
		t.Fatalf("a client credential survived CCB_CARRIER_AUTH = none (token=%q source=%v)", cc.token, cc.tokenSource != nil)
	}
	if cc.sciTokens != nil {
		t.Fatal("SciToken map machinery was wired for an unauthenticated carrier")
	}
}

// TestCarrierAuthRejectsUnknownValue: a typo must stop the daemon rather than
// silently picking a mode the operator did not ask for.
func TestCarrierAuthRejectsUnknownValue(t *testing.T) {
	_, err := buildSettings(t, `
CCB_CARRIER_AUTH = optional
CCB_CARRIER_LISTEN = ws://127.0.0.1:18080/ccb/tunnel
`, "", nil)
	if err == nil {
		t.Fatal("an unrecognized CCB_CARRIER_AUTH was accepted")
	}
	if !strings.Contains(err.Error(), "CCB_CARRIER_AUTH") {
		t.Fatalf("error does not name the knob: %v", err)
	}
}

// TestCarrierAuthCaseAndSpace: HTCondor configs are written by hand.
func TestCarrierAuthCaseAndSpace(t *testing.T) {
	for _, v := range []string{"none", "None", "NONE", "  none  "} {
		cc, err := buildSettings(t, "CCB_CARRIER_AUTH = "+v+"\nCCB_CARRIER_LISTEN = ws://127.0.0.1:18080/ccb/tunnel\n", "", nil)
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if !cc.unauthenticated {
			t.Fatalf("%q was not read as none", v)
		}
	}
}

// TestCarrierLimitsFromConfig: the DoS knobs reach the settings, and absent
// ones leave the defaults in place for the transport to resolve.
func TestCarrierLimitsFromConfig(t *testing.T) {
	cc, err := buildSettings(t, `
CCB_CARRIER_LISTEN = ws://127.0.0.1:18080/ccb/tunnel
CCB_CARRIER_MAX_SESSIONS = 32
CCB_CARRIER_MAX_PER_SOURCE = 4
CCB_CARRIER_PIPE_PROBATION = 15
`, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cc.maxSessions != 32 || cc.maxPerSource != 4 {
		t.Fatalf("limits = %d/%d, want 32/4", cc.maxSessions, cc.maxPerSource)
	}
	if cc.probation != 15*time.Second {
		t.Fatalf("probation = %v, want 15s", cc.probation)
	}

	bare, err := buildSettings(t, "CCB_CARRIER_LISTEN = ws://127.0.0.1:18080/ccb/tunnel\n", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if bare.maxSessions != 0 || bare.maxPerSource != 0 || bare.probation != 0 || bare.probationOff {
		t.Fatalf("unset limits should stay zero so the transport defaults apply, got %d/%d/%v off=%v",
			bare.maxSessions, bare.maxPerSource, bare.probation, bare.probationOff)
	}
}

// TestCarrierProbationZeroMeansOff: an explicit 0 must disable probation, not
// silently fall back to the default -- otherwise an operator who turned it off
// would still have pipes dropped.
func TestCarrierProbationZeroMeansOff(t *testing.T) {
	cc, err := buildSettings(t, `
CCB_CARRIER_LISTEN = ws://127.0.0.1:18080/ccb/tunnel
CCB_CARRIER_PIPE_PROBATION = 0
`, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cc.probationOff {
		t.Fatal("CCB_CARRIER_PIPE_PROBATION = 0 did not disable probation")
	}
	if cc.probation != 0 {
		t.Fatalf("probation = %v, want 0 when disabled", cc.probation)
	}
}
