package main

import (
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/mapfile"
)

// defaultForeignTokenIssuers is SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS's default
// in HTCondor's param_info.in.
const defaultForeignTokenIssuers = "https://aai-dev.egi.eu/auth/realms/egi"

// sciTokenMap holds the SCITOKENS lines of CERTIFICATE_MAPFILE, reloaded on
// reconfig. A nil map (no map file, or one that failed to load) maps nothing.
type sciTokenMap struct {
	mf  atomic.Pointer[mapfile.MapFile]
	log *slog.Logger
}

// mapper is a security.SecurityConfig.SciTokensMapper over the current map.
func (m *sciTokenMap) mapper(authName string) (string, bool) {
	return m.mf.Load().Map("SCITOKENS", authName)
}

// load reads CERTIFICATE_MAPFILE as HTCondor does: every principal is a regular
// expression unless CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS is true (default
// false), and a bad line is logged and skipped. A file that cannot be read
// leaves no map, so every SciToken is refused, as HTCondor refuses them when
// its map file fails to load.
func (m *sciTokenMap) load(cfg *config.Config) {
	path, _ := cfg.Get("CERTIFICATE_MAPFILE")
	path = strings.TrimSpace(path)
	if path == "" {
		m.mf.Store(nil)
		return
	}
	mf, err := mapfile.Options{
		RegexKeys: !configBool(cfg, "CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS", false),
		Logger:    m.log,
	}.Load(path)
	if err != nil {
		m.log.Warn("cannot load CERTIFICATE_MAPFILE; refusing every SciToken", "file", path, "error", err)
		m.mf.Store(nil)
		return
	}
	m.mf.Store(mf)
}

// applySciTokensConfig sets sec's SciToken acceptance from the HTCondor
// configuration, as condor_auth_ssl.cpp and condor_scitokens.cpp read it:
// the SCITOKENS lines of CERTIFICATE_MAPFILE map "issuer,subject" to a user
// (no map file, or no matching line, refuses the token),
// SCITOKENS_SERVER_AUDIENCE restricts "aud", and
// SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES / SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS
// name the issuers whose non-SciTokens JWTs are accepted. It returns the map
// so the caller can reload it on reconfig, or nil when sec already carries a
// mapper. This belongs in golang-htcondor's security config builder and can
// move there.
func applySciTokensConfig(cfg *config.Config, sec *security.SecurityConfig, log *slog.Logger) *sciTokenMap {
	if sec.SciTokensMapper != nil {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	m := &sciTokenMap{log: log}
	m.load(cfg)
	sec.SciTokensMapper = m.mapper

	if v, ok := cfg.Get("SCITOKENS_SERVER_AUDIENCE"); ok {
		sec.SciTokensServerAudience = tokenList(v)
	}
	sec.SciTokensForeignTokenIssuers = nil
	if configBool(cfg, "SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES", true) {
		v, ok := cfg.Get("SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS")
		if !ok {
			v = defaultForeignTokenIssuers
		}
		sec.SciTokensForeignTokenIssuers = tokenList(v)
	}
	return m
}

// tokenList splits a list as HTCondor's StringTokenIterator does, on commas
// and white space.
func tokenList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}
