package ccbserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbockelm/cedar/security"
)

// This file provides optional HTCondor-flavoured token glue for the WebSocket
// carrier (Config.CarrierTokenSource / Config.CarrierTokenVerify). A daemon may
// assign these directly or supply its own. The transport (transport/wscarrier)
// stays credential-agnostic; the pool-specific policy lives here.

// DiscoverBearerToken finds a bearer token to present when dialing a WebSocket
// carrier, preferring a SciToken from the standard WLCG Bearer Token Discovery
// locations, then an HTCondor IDTOKEN from the token directory. Suitable as a
// Config.CarrierTokenSource. ctx is accepted for interface uniformity.
func DiscoverBearerToken(ctx context.Context) (string, error) {
	// WLCG Bearer Token Discovery order.
	if t := strings.TrimSpace(os.Getenv("BEARER_TOKEN")); t != "" {
		return t, nil
	}
	if f := os.Getenv("BEARER_TOKEN_FILE"); f != "" {
		if t, err := readFirstToken(f); err == nil {
			return t, nil
		}
	}
	uid := os.Getuid()
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		if t, err := readFirstToken(filepath.Join(xdg, fmt.Sprintf("bt_u%d", uid))); err == nil {
			return t, nil
		}
	}
	if t, err := readFirstToken(fmt.Sprintf("/tmp/bt_u%d", uid)); err == nil {
		return t, nil
	}
	// HTCondor IDTOKEN: first token in the token directory.
	if t, err := discoverIDToken(); err == nil {
		return t, nil
	}
	return "", fmt.Errorf("ccbserver: no bearer token found (set BEARER_TOKEN/BEARER_TOKEN_FILE, or place an IDTOKEN in the token directory)")
}

// discoverIDToken returns the first token from HTCondor's token directory
// (SEC_TOKEN_DIRECTORY, else ~/.condor/tokens.d, else /etc/condor/tokens.d).
func discoverIDToken() (string, error) {
	var dirs []string
	if d := os.Getenv("SEC_TOKEN_DIRECTORY"); d != "" {
		dirs = append(dirs, d)
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".condor", "tokens.d"))
	}
	dirs = append(dirs, "/etc/condor/tokens.d")
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if t, err := readFirstToken(filepath.Join(d, e.Name())); err == nil && t != "" {
				return t, nil
			}
		}
	}
	return "", fmt.Errorf("ccbserver: no IDTOKEN found in the token directory")
}

// readFirstToken reads the first non-empty line of a token file (HTCondor token
// files may hold several, one per line).
func readFirstToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t, nil
		}
	}
	return "", fmt.Errorf("ccbserver: token file %s is empty", path)
}

// SciTokenVerifier is a Config.CarrierTokenVerify that accepts a SciToken/WLCG
// JWT, verifying it against its issuer's JWKS (cedar security.VerifySciToken),
// and returns "<issuer>/<subject>" as the identity. It rejects non-SciToken
// bearer tokens (an HTCondor IDTOKEN needs the pool-signing-key HMAC path, which
// the daemon should wire separately -- see the note below).
func SciTokenVerifier(ctx context.Context, token string) (string, error) {
	if !security.IsSciToken(token) {
		return "", fmt.Errorf("ccbserver: bearer token is not a SciToken (IDTOKEN verification not wired)")
	}
	claims, err := security.VerifySciToken(token)
	if err != nil {
		return "", fmt.Errorf("ccbserver: SciToken verification failed: %w", err)
	}
	return claims.Issuer + "/" + claims.Subject, nil
}
