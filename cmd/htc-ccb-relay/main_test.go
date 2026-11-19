package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// A relay that quietly ignored configuration it cannot carry out would be the
// worst of both worlds: the administrator sees no error, and goes looking for
// sessions that were never persisted or a carrier that was never accepted --
// from the far side of an ssh session, where there is nothing to look at.
func TestItRefusesConfigurationItCannotHonour(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantsInError string
	}{
		{
			name:         "a session cache it does not keep",
			body:         "CCB_SESSION_CACHE_FILE = /var/lib/condor/sessions.db\n",
			wantsInError: "CCB_SESSION_CACHE_FILE",
		},
		{
			name:         "a carrier of its own",
			body:         "CCB_CARRIER_LISTEN = wss://0.0.0.0:443/ccb/tunnel\n",
			wantsInError: "CCB_CARRIER_LISTEN",
		},
		{
			name:         "a next hop that is not the pipe",
			body:         "CCB_OUTBOUND_NEXT_HOP = wss://ccb.example.org/ccb/tunnel\n",
			wantsInError: "CCB_OUTBOUND_NEXT_HOP",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseUnsupported(testConfig(t, tc.body))
			if err == nil {
				t.Fatal("accepted configuration this binary cannot carry out")
			}
			if !strings.Contains(err.Error(), tc.wantsInError) {
				t.Errorf("the error does not name the knob that caused it: %v", err)
			}
			// Every one of these works in htc-ccb, so the error has to say so
			// -- otherwise it reads as "not supported" rather than "stage the
			// other binary".
			if !strings.Contains(err.Error(), "htc-ccb") {
				t.Errorf("the error does not point at the binary that can do it: %v", err)
			}
		})
	}
}

// stdio: is what this binary's carrier always is, so saying so explicitly must
// not be an error -- an administrator copying a working inside-broker config
// would otherwise be refused for agreeing with us.
func TestItAcceptsTheConfigurationItDoesHonour(t *testing.T) {
	for _, body := range []string{
		"",
		"CCB_OUTBOUND_NEXT_HOP = stdio:\n",
		"CCB_OUTBOUND_NEXT_HOP = stdio\n",
		"CCB_OUTBOUND_PROXY = TRUE\nCCB_LISTEN = 127.0.0.1:9700\n",
		"CCB_SESSION_CACHE_FILE =\n", // set but empty is not set
	} {
		if err := refuseUnsupported(testConfig(t, body)); err != nil {
			t.Errorf("refused configuration it can honour (%q): %v", body, err)
		}
	}
}

func TestConfigBoolReadsHTCondorSpellings(t *testing.T) {
	cfg := testConfig(t, "A = TRUE\nB = false\nC = 1\nD = No\nE = rubbish\n")
	for _, tc := range []struct {
		key  string
		def  bool
		want bool
	}{
		{"A", false, true},
		{"B", true, false},
		{"C", false, true},
		{"D", true, false},
		{"E", true, true}, // unparsable falls back to the default
		{"E", false, false},
		{"MISSING", true, true},
		{"MISSING", false, false},
	} {
		if got := configBool(cfg, tc.key, tc.def); got != tc.want {
			t.Errorf("configBool(%q, def=%v) = %v, want %v", tc.key, tc.def, got, tc.want)
		}
	}
}

func testConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONDOR_CONFIG", path)
	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "CCB"})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
