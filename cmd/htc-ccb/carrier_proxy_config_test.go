package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// The site's environment and the pool's configuration can disagree about how to
// reach the carrier, and an administrator's answer lives in the configuration
// file -- a daemon started by condor_master may not even inherit the site's
// HTTPS_PROXY. These pin the precedence: CCB_CARRIER_PROXY wins, including when
// it says to use no proxy at all.

// proxyConfig builds a config from knobs written to a temporary condor_config.
func proxyConfig(t *testing.T, knobs string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "condor_config")
	body := "LOG = " + dir + "\nLOCK = " + dir + "\nRUN = " + dir + "\n" + knobs + "\n"
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

// resolve runs the built proxy function the way a carrier dial would.
func resolve(t *testing.T, fn func(*http.Request) (*url.URL, error), endpoint string) *url.URL {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fn(&http.Request{URL: u, Header: http.Header{}})
	if err != nil {
		t.Fatalf("resolving proxy for %s: %v", endpoint, err)
	}
	return got
}

const proxyEndpoint = "https://ccb.offsite.test/ccb/tunnel"

func TestCarrierProxyConfigBeatsEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://site-squid.example:3128")
	t.Setenv("NO_PROXY", "")
	cfg := proxyConfig(t, "CCB_CARRIER_PROXY = http://pool-squid.example:8080")

	fn, source, err := buildCarrierProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := resolve(t, fn, proxyEndpoint)
	if got == nil || got.Host != "pool-squid.example:8080" {
		t.Fatalf("proxy = %v, want the configured pool-squid.example:8080 to beat HTTPS_PROXY", got)
	}
	if !strings.Contains(source, "CCB_CARRIER_PROXY") {
		t.Errorf("source %q does not name the configuration knob", source)
	}
}

// "none" is the knob an administrator needs when the site exports an HTTPS_PROXY
// that must not be used for the carrier -- without it, the only way to get a
// direct dial would be to change the daemon's environment.
func TestCarrierProxyNoneBeatsEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://site-squid.example:3128")
	t.Setenv("NO_PROXY", "")
	cfg := proxyConfig(t, "CCB_CARRIER_PROXY = none")

	fn, source, err := buildCarrierProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolve(t, fn, proxyEndpoint); got != nil {
		t.Fatalf("proxy = %v, want a direct dial", got)
	}
	if !strings.Contains(source, "none") {
		t.Errorf("source %q does not record that a direct dial was configured", source)
	}
}

// With nothing configured the site environment is still honoured, so an existing
// deployment keeps working -- and the source says so, since an operator reading
// the log cannot otherwise tell a configured proxy from a leaked one.
func TestCarrierProxyFallsBackToEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://site-squid.example:3128")
	t.Setenv("NO_PROXY", "")
	cfg := proxyConfig(t, "")

	fn, source, err := buildCarrierProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := resolve(t, fn, proxyEndpoint)
	if got == nil || got.Host != "site-squid.example:3128" {
		t.Fatalf("proxy = %v, want HTTPS_PROXY when nothing is configured", got)
	}
	if !strings.Contains(source, "environment") {
		t.Errorf("source %q does not say the setting came from the environment", source)
	}
}

// The environment is re-read per dial. net/http's ProxyFromEnvironment resolves
// once per process and caches forever, which would pin whatever the environment
// happened to be the first time anything asked.
func TestCarrierProxyEnvironmentIsNotCached(t *testing.T) {
	t.Setenv("NO_PROXY", "")
	t.Setenv("HTTPS_PROXY", "http://first.example:3128")
	cfg := proxyConfig(t, "")
	fn, _, err := buildCarrierProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolve(t, fn, proxyEndpoint); got == nil || got.Host != "first.example:3128" {
		t.Fatalf("proxy = %v, want first.example:3128", got)
	}

	t.Setenv("HTTPS_PROXY", "http://second.example:3128")
	if got := resolve(t, fn, proxyEndpoint); got == nil || got.Host != "second.example:3128" {
		t.Fatalf("proxy = %v after the environment changed, want second.example:3128", got)
	}
}

func TestCarrierProxyCredentialFile(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "proxy.cred")
	if err := os.WriteFile(credPath, []byte("pilot:s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := proxyConfig(t, "CCB_CARRIER_PROXY = http://squid.example:3128\n"+
		"CCB_CARRIER_PROXY_CREDENTIAL_FILE = "+credPath)

	fn, source, err := buildCarrierProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := resolve(t, fn, proxyEndpoint)
	if got == nil || got.User == nil {
		t.Fatalf("proxy = %v, want credentials attached", got)
	}
	pass, _ := got.User.Password()
	if got.User.Username() != "pilot" || pass != "s3cret" {
		t.Errorf("credentials = %q:%q, want pilot:s3cret", got.User.Username(), pass)
	}
	if !strings.Contains(source, "CREDENTIAL_FILE") {
		t.Errorf("source %q does not record the credential file", source)
	}

	// Re-read per dial, so rotating the file takes effect without a restart.
	if err := os.WriteFile(credPath, []byte("pilot:rotated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got = resolve(t, fn, proxyEndpoint)
	pass, _ = got.User.Password()
	if pass != "rotated" {
		t.Errorf("password = %q after rotation, want rotated", pass)
	}
}

func TestCarrierProxyCredentialFileMustNotBeWorldReadable(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "proxy.cred")
	if err := os.WriteFile(credPath, []byte("pilot:s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := proxyConfig(t, "CCB_CARRIER_PROXY = http://squid.example:3128\n"+
		"CCB_CARRIER_PROXY_CREDENTIAL_FILE = "+credPath)

	if _, _, err := buildCarrierProxy(cfg); err == nil {
		t.Fatal("a world-readable credential file was accepted")
	} else if !strings.Contains(err.Error(), "world-readable") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

func TestCarrierProxyRejectsBadURL(t *testing.T) {
	cfg := proxyConfig(t, "CCB_CARRIER_PROXY = ://nonsense")
	if _, _, err := buildCarrierProxy(cfg); err == nil {
		t.Fatal("a malformed CCB_CARRIER_PROXY was accepted")
	}
}

// A bare host:port is the shorthand an administrator is most likely to write.
func TestCarrierProxyAcceptsBareHostPort(t *testing.T) {
	cfg := proxyConfig(t, "CCB_CARRIER_PROXY = squid.example:3128")
	fn, _, err := buildCarrierProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := resolve(t, fn, proxyEndpoint)
	if got == nil || got.Host != "squid.example:3128" || got.Scheme != "http" {
		t.Fatalf("proxy = %v, want http://squid.example:3128", got)
	}
}
