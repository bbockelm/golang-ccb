package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/golang-jwt/jwt/v5"
)

func testConfig(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// selfSignedSciToken is a current SciToken from issuer, signed by a key no
// issuer publishes.
func selfSignedSciToken(t *testing.T, issuer string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer, "sub": "alice", "scope": "condor:/DAEMON",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestCarrierRefusesSciTokensWithoutMapFile: a ws:// carrier listener with no
// CERTIFICATE_MAPFILE accepts no SciToken, and contacts no issuer.
func TestCarrierRefusesSciTokensWithoutMapFile(t *testing.T) {
	// Count connections, not requests: the daemon does not trust the test
	// certificate, so a fetch would fail in the TLS handshake.
	var hits atomic.Int32
	issuer := httptest.NewUnstartedServer(http.NotFoundHandler())
	issuer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			hits.Add(1)
		}
	}
	issuer.StartTLS()
	defer issuer.Close()

	cfg := testConfig(t, "CCB_CARRIER_LISTEN = ws://127.0.0.1:0/ccb/tunnel\n")
	cc, err := buildCarrierSettings(cfg, &security.SecurityConfig{}, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cc.verify == nil {
		t.Fatal("no carrier token verifier")
	}
	if id, err := cc.verify(context.Background(), selfSignedSciToken(t, issuer.URL)); err == nil {
		t.Fatalf("SciToken accepted as %q with no map file", id)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("issuer received %d connections", n)
	}
}

// TestApplySciTokensConfig checks the knobs are read as HTCondor reads them:
// CERTIFICATE_MAPFILE principals are regular expressions unless
// CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS is true, SCITOKENS_SERVER_AUDIENCE is
// a list, and foreign token issuers default to HTCondor's.
func TestApplySciTokensConfig(t *testing.T) {
	mapPath := filepath.Join(t.TempDir(), "mapfile")
	if err := os.WriteFile(mapPath, []byte(
		"SCITOKENS ^https://issuer\\.example,(.*)$ \\1\n"+
			"SCITOKENS https://lit.example,bob literal-bob\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("defaults", func(t *testing.T) {
		sec := &security.SecurityConfig{}
		m := applySciTokensConfig(testConfig(t, "CERTIFICATE_MAPFILE = "+mapPath+"\n"), sec, nil)
		if m == nil || sec.SciTokensMapper == nil {
			t.Fatal("no SciTokens mapper")
		}
		if user, ok := sec.SciTokensMapper("https://issuer.example,alice"); !ok || user != "alice" {
			t.Errorf("regex line mapped to %q, %v; want alice", user, ok)
		}
		if user, ok := sec.SciTokensMapper("https://lit.example,bob"); !ok || user != "literal-bob" {
			t.Errorf("line mapped to %q, %v; want literal-bob", user, ok)
		}
		if _, ok := sec.SciTokensMapper("https://evil.example,alice"); ok {
			t.Error("unmapped issuer mapped")
		}
		if len(sec.SciTokensServerAudience) != 0 {
			t.Errorf("audience = %q, want none", sec.SciTokensServerAudience)
		}
		if want := []string{defaultForeignTokenIssuers}; !slices.Equal(sec.SciTokensForeignTokenIssuers, want) {
			t.Errorf("foreign issuers = %q, want %q", sec.SciTokensForeignTokenIssuers, want)
		}
	})

	t.Run("hash keys", func(t *testing.T) {
		sec := &security.SecurityConfig{}
		applySciTokensConfig(testConfig(t, "CERTIFICATE_MAPFILE = "+mapPath+"\n"+
			"CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true\n"), sec, nil)
		// The unslashed regex line is now a literal and matches nothing.
		if user, ok := sec.SciTokensMapper("https://issuer.example,alice"); ok {
			t.Errorf("literal-mode line mapped to %q", user)
		}
		if user, ok := sec.SciTokensMapper("https://lit.example,bob"); !ok || user != "literal-bob" {
			t.Errorf("literal line mapped to %q, %v; want literal-bob", user, ok)
		}
	})

	t.Run("audience and foreign issuers", func(t *testing.T) {
		sec := &security.SecurityConfig{}
		applySciTokensConfig(testConfig(t, "CERTIFICATE_MAPFILE = "+mapPath+"\n"+
			"SCITOKENS_SERVER_AUDIENCE = https://a.example, https://b.example\n"+
			"SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES = false\n"), sec, nil)
		if want := []string{"https://a.example", "https://b.example"}; !slices.Equal(sec.SciTokensServerAudience, want) {
			t.Errorf("audience = %q, want %q", sec.SciTokensServerAudience, want)
		}
		if sec.SciTokensForeignTokenIssuers != nil {
			t.Errorf("foreign issuers = %q with foreign tokens disallowed", sec.SciTokensForeignTokenIssuers)
		}
	})

	t.Run("no map file", func(t *testing.T) {
		sec := &security.SecurityConfig{}
		applySciTokensConfig(testConfig(t, ""), sec, nil)
		if user, ok := sec.SciTokensMapper("https://issuer.example,alice"); ok {
			t.Errorf("mapped to %q with no map file", user)
		}
	})

	t.Run("unreadable map file", func(t *testing.T) {
		sec := &security.SecurityConfig{}
		applySciTokensConfig(testConfig(t, "CERTIFICATE_MAPFILE = "+mapPath+".missing\n"), sec, nil)
		if user, ok := sec.SciTokensMapper("https://issuer.example,alice"); ok {
			t.Errorf("mapped to %q with an unreadable map file", user)
		}
	})
}
