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

// SciTokenVerifier returns a Config.CarrierTokenVerify that accepts a
// SciToken/WLCG JWT the way an HTCondor server accepts SCITOKENS
// authentication (condor_auth_ssl.cpp): the token's "issuer,subject" must be
// mapped by sec.SciTokensMapper (the SCITOKENS lines of CERTIFICATE_MAPFILE),
// its audience must satisfy sec.SciTokensServerAudience
// (SCITOKENS_SERVER_AUDIENCE), and it must be current and signed by a key its
// https issuer publishes. The mapping is consulted before anything is fetched,
// so an issuer no map line names is never contacted. The identity is the
// mapped user, with sec's UID domain appended when it has no '@'
// (SecurityConfig.CanonicalUser), as HTCondor names a SCITOKENS peer.
//
// With a nil sec or a nil sec.SciTokensMapper every SciToken is refused, as
// HTCondor refuses them with no map file. It rejects non-SciToken bearer
// tokens; use BearerTokenVerifier to also accept HTCondor IDTOKENs.
func SciTokenVerifier(sec *security.SecurityConfig) func(ctx context.Context, token string) (string, error) {
	return func(ctx context.Context, token string) (string, error) {
		if !security.IsSciToken(token) {
			return "", fmt.Errorf("ccbserver: bearer token is not a SciToken")
		}
		if sec == nil || sec.SciTokensMapper == nil {
			return "", fmt.Errorf("ccbserver: no SCITOKENS mapping is configured, so no SciToken is accepted")
		}
		var user string
		_, err := security.VerifySciToken(ctx, token, security.SciTokenVerifyOptions{
			Accept: func(issuer, subject string) bool {
				mapped, ok := sec.SciTokensMapper(issuer + "," + subject)
				if !ok || mapped == "" {
					return false
				}
				user = mapped
				return true
			},
			Audiences:           sec.SciTokensServerAudience,
			ForeignTokenIssuers: sec.SciTokensForeignTokenIssuers,
			HTTPClient:          sec.SciTokensHTTPClient,
		})
		if err != nil {
			return "", fmt.Errorf("ccbserver: SciToken verification failed: %w", err)
		}
		return sec.CanonicalUser(user), nil
	}
}

// IDTokenVerifier returns a Config.CarrierTokenVerify that accepts an HTCondor
// IDTOKEN, verifying its HKDF+HMAC signature against the pool/named signing key
// located from sec (cedar security.VerifyIDToken). The identity is the token
// subject. sec must carry the signing-key location (TokenPoolSigningKeyFile /
// TokenSigningKeyDir); a server's Config.Security is the natural choice.
func IDTokenVerifier(sec *security.SecurityConfig) func(ctx context.Context, token string) (string, error) {
	return func(_ context.Context, token string) (string, error) {
		claims, err := security.VerifyIDToken(token, sec)
		if err != nil {
			return "", err
		}
		return claims.Subject, nil
	}
}

// BearerTokenVerifier returns a Config.CarrierTokenVerify that accepts EITHER an
// HTCondor IDTOKEN (HKDF+HMAC against the pool signing key in sec) or a SciToken
// (see SciTokenVerifier: mapped by sec.SciTokensMapper, refused when it is nil),
// dispatching on the token's header. This is the general choice for a pool that
// admits both credential types.
func BearerTokenVerifier(sec *security.SecurityConfig) func(ctx context.Context, token string) (string, error) {
	idVerify := IDTokenVerifier(sec)
	sciVerify := SciTokenVerifier(sec)
	return func(ctx context.Context, token string) (string, error) {
		if security.IsSciToken(token) {
			return sciVerify(ctx, token)
		}
		return idVerify(ctx, token)
	}
}
