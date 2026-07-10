package ccbserver

import (
	"context"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
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
