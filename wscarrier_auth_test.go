package ccbserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/mapfile"
	"github.com/golang-jwt/jwt/v5"
)

// TestBearerTokenVerifierAcceptsIDToken proves the CCB WebSocket-carrier verifier
// accepts a genuine HTCondor IDTOKEN via the cedar VerifyIDToken path, and
// rejects one signed by a different pool key.
func TestBearerTokenVerifierAcceptsIDToken(t *testing.T) {
	dir := t.TempDir()
	tok, err := security.GenerateTestJWT(dir, "pool", "startd@site.example", "site.example", time.Hour, []string{"DAEMON"})
	if err != nil {
		t.Fatalf("GenerateTestJWT: %v", err)
	}

	verify := BearerTokenVerifier(&security.SecurityConfig{TokenSigningKeyDir: dir})
	id, err := verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify IDTOKEN: %v", err)
	}
	if id != "startd@site.example" {
		t.Fatalf("identity = %q, want startd@site.example", id)
	}

	// A verifier keyed on a different signing directory must reject it.
	otherDir := t.TempDir()
	if _, err := security.GenerateTestJWT(otherDir, "pool", "x@y", "y", time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := BearerTokenVerifier(&security.SecurityConfig{TokenSigningKeyDir: otherDir})(context.Background(), tok); err == nil {
		t.Fatal("expected rejection under a different signing key")
	}
}

// sciIssuer is an https SciToken issuer serving OIDC metadata and a JWKS with
// one RSA key. hits counts every request it receives.
type sciIssuer struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	hits atomic.Int32
}

func newSciIssuer(t *testing.T, tlsServer bool) *sciIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	si := &sciIssuer{key: key}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		si.hits.Add(1)
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": si.srv.URL, "jwks_uri": si.srv.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	})
	if tlsServer {
		si.srv = httptest.NewTLSServer(h)
	} else {
		si.srv = httptest.NewServer(h)
	}
	t.Cleanup(si.srv.Close)
	return si
}

func (si *sciIssuer) url() string { return si.srv.URL }

// claims returns current SciTokens 1.0 claims for subject "alice".
func (si *sciIssuer) claims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":   si.url(),
		"sub":   "alice",
		"scope": "condor:/DAEMON",
		"iat":   now.Add(-time.Minute).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
}

func (si *sciIssuer) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(si.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// sciSec returns a SecurityConfig whose SCITOKENS map file is mapLines, read
// with every principal a regular expression (HTCondor's default for
// CERTIFICATE_MAPFILE), trusting si's test certificate.
func sciSec(t *testing.T, si *sciIssuer, mapLines string) *security.SecurityConfig {
	t.Helper()
	mf, err := mapfile.Options{RegexKeys: true}.Parse(strings.NewReader(mapLines), "mapfile")
	if err != nil {
		t.Fatal(err)
	}
	return &security.SecurityConfig{
		UIDDomain:           "pool.example",
		SciTokensMapper:     func(name string) (string, bool) { return mf.Map("SCITOKENS", name) },
		SciTokensHTTPClient: si.srv.Client(),
	}
}

// mapLine maps si's issuer and subject alice to user.
func mapLine(si *sciIssuer, user string) string {
	return "SCITOKENS ^" + regexp.QuoteMeta(si.url()+",alice") + "$ " + user + "\n"
}

// TestSciTokenVerifierRefusesSelfIssuedToken is a token an attacker mints and
// serves the key for: from a plain-http issuer, or from an https issuer no
// SCITOKENS line maps. Neither is accepted, and neither issuer is contacted.
func TestSciTokenVerifierRefusesSelfIssuedToken(t *testing.T) {
	t.Run("http issuer", func(t *testing.T) {
		si := newSciIssuer(t, false)
		// Even a map line naming the issuer does not admit http.
		verify := BearerTokenVerifier(sciSec(t, si, mapLine(si, "alice")))
		if id, err := verify(context.Background(), si.sign(t, si.claims())); err == nil {
			t.Fatalf("http-issuer SciToken accepted as %q", id)
		}
		if n := si.hits.Load(); n != 0 {
			t.Errorf("http issuer received %d requests", n)
		}
	})
	t.Run("unmapped issuer", func(t *testing.T) {
		si := newSciIssuer(t, true)
		verify := BearerTokenVerifier(sciSec(t, si, "SCITOKENS ^https://issuer\\.example,.*$ someone\n"))
		if id, err := verify(context.Background(), si.sign(t, si.claims())); err == nil {
			t.Fatalf("unmapped SciToken accepted as %q", id)
		}
		if n := si.hits.Load(); n != 0 {
			t.Errorf("unmapped issuer received %d requests", n)
		}
	})
}

// TestSciTokenVerifierRefusesWithoutMapFile: with no SCITOKENS mapping
// configured, as with no map file in HTCondor, no SciToken is accepted.
func TestSciTokenVerifierRefusesWithoutMapFile(t *testing.T) {
	si := newSciIssuer(t, true)
	sec := &security.SecurityConfig{SciTokensHTTPClient: si.srv.Client()}
	for name, verify := range map[string]func(context.Context, string) (string, error){
		"SciTokenVerifier":         SciTokenVerifier(sec),
		"BearerTokenVerifier":      BearerTokenVerifier(sec),
		"SciTokenVerifier(nil)":    SciTokenVerifier(nil),
		"BearerTokenVerifier(nil)": BearerTokenVerifier(nil),
	} {
		if id, err := verify(context.Background(), si.sign(t, si.claims())); err == nil {
			t.Errorf("%s accepted a SciToken as %q with no mapping", name, id)
		}
	}
	if n := si.hits.Load(); n != 0 {
		t.Errorf("issuer received %d requests", n)
	}
}

func TestSciTokenVerifierRefusesExpired(t *testing.T) {
	si := newSciIssuer(t, true)
	c := si.claims()
	c["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	c["nbf"] = time.Now().Add(-2 * time.Hour).Unix()
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	verify := BearerTokenVerifier(sciSec(t, si, mapLine(si, "alice")))
	if id, err := verify(context.Background(), si.sign(t, c)); err == nil {
		t.Fatalf("expired SciToken accepted as %q", id)
	}
}

func TestSciTokenVerifierRefusesWrongAudience(t *testing.T) {
	si := newSciIssuer(t, true)
	sec := sciSec(t, si, mapLine(si, "alice"))
	sec.SciTokensServerAudience = []string{"https://ccb.pool.example"}
	verify := BearerTokenVerifier(sec)

	c := si.claims()
	c["aud"] = "https://other.example"
	if id, err := verify(context.Background(), si.sign(t, c)); err == nil {
		t.Fatalf("wrong-audience SciToken accepted as %q", id)
	}
	// The configured audience is accepted, so the refusal above is the audience.
	c["aud"] = "https://ccb.pool.example"
	if _, err := verify(context.Background(), si.sign(t, c)); err != nil {
		t.Fatalf("right-audience SciToken refused: %v", err)
	}
}

// TestSciTokenVerifierAcceptsMappedToken: a current token from a mapped https
// issuer is accepted as the mapped user, with the UID domain appended when the
// map line names none.
func TestSciTokenVerifierAcceptsMappedToken(t *testing.T) {
	for _, tc := range []struct{ user, want string }{
		{"ccbuser", "ccbuser@pool.example"},
		{"inside@Site.Example", "inside@site.example"},
	} {
		si := newSciIssuer(t, true)
		verify := BearerTokenVerifier(sciSec(t, si, mapLine(si, tc.user)))
		id, err := verify(context.Background(), si.sign(t, si.claims()))
		if err != nil {
			t.Fatalf("mapped SciToken refused: %v", err)
		}
		if id != tc.want {
			t.Errorf("identity = %q, want %q", id, tc.want)
		}
		if si.hits.Load() == 0 {
			t.Error("the issuer's keys were never fetched")
		}
	}
}
