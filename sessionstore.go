package ccbserver

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/gob"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SessionRecord is the persistable form of a CEDAR session: everything needed to
// restore a resumable server-side session after a restart. The KeyData is the
// symmetric session key and is only ever written encrypted under the DEK.
type SessionRecord struct {
	ID          string
	Addr        string
	KeyData     []byte
	KeyProtocol string
	PolicyText  string // serialized ClassAd
	Expiration  time.Time
	LeaseSecs   int64
	Tag         string
	PeerVersion string
}

// SessionStore persists CEDAR session records encrypted at rest.
type SessionStore interface {
	Load(ctx context.Context) ([]SessionRecord, error)
	Save(ctx context.Context, recs []SessionRecord) error
	Close() error
}

// sqliteSessionStore persists session records in SQLite, encrypted with a DEK
// that is itself wrapped by each available HTCondor signing key (see
// crypto_envelope.go). The session table holds only ciphertext; the master_key
// table holds the wrapped DEK, one row per signing key.
type sqliteSessionStore struct {
	db  *sql.DB
	log *slog.Logger

	mu  sync.Mutex
	env *envelope
}

// OpenSessionStore opens (creating if needed) the encrypted session database at
// path. keys are the available signing keys used to wrap/unwrap the DEK; at
// least one is required (the cache cannot be encrypted without a key). On an
// existing database whose DEK cannot be recovered from any available key, the
// store re-initializes with a fresh DEK and discards the unreadable sessions
// (clients re-authenticate) rather than failing to start.
func OpenSessionStore(path string, keys []SigningKey, log *slog.Logger) (SessionStore, error) {
	if log == nil {
		log = slog.Default()
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("ccb: session cache persistence requires at least one signing key (SEC_PASSWORD_DIRECTORY)")
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening session db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS master_key (
			key_id  TEXT PRIMARY KEY,
			salt    BLOB NOT NULL,
			nonce   BLOB NOT NULL,
			wrapped BLOB NOT NULL
		);
		CREATE TABLE IF NOT EXISTS session (
			id         TEXT PRIMARY KEY,
			expiration INTEGER NOT NULL,
			nonce      BLOB NOT NULL,
			ciphertext BLOB NOT NULL
		);`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating session tables: %w", err)
	}

	s := &sqliteSessionStore{db: db, log: log}
	if err := s.initEnvelope(keys); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// initEnvelope recovers or creates the DEK and ensures every available signing
// key has a wrapping row (supporting rotation).
func (s *sqliteSessionStore) initEnvelope(keys []SigningKey) error {
	ctx := context.Background()
	rows, err := s.loadMasterKeyRows(ctx)
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		// Fresh database: mint a DEK and wrap it for all keys.
		env, err := newEnvelope()
		if err != nil {
			return err
		}
		s.env = env
		return s.wrapForKeys(ctx, keys, existingKeyIDs(rows))
	}

	env, err := openEnvelope(rows, keys)
	if err != nil {
		// None of the available keys can decrypt the existing DEK. Re-initialize
		// rather than fail: discard the unreadable cache so the broker still
		// starts (clients re-authenticate).
		s.log.Warn("ccb session cache: no available signing key can decrypt the stored DEK; re-initializing (cached sessions discarded)")
		if _, err := s.db.ExecContext(ctx, `DELETE FROM session`); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM master_key`); err != nil {
			return err
		}
		fresh, err := newEnvelope()
		if err != nil {
			return err
		}
		s.env = fresh
		return s.wrapForKeys(ctx, keys, nil)
	}

	s.env = env
	// Rotation: ensure any newly-available key also wraps the DEK.
	return s.wrapForKeys(ctx, keys, existingKeyIDs(rows))
}

// wrapForKeys writes a master_key row for every key not already present in have.
func (s *sqliteSessionStore) wrapForKeys(ctx context.Context, keys []SigningKey, have map[string]bool) error {
	for _, k := range keys {
		if have[k.ID] {
			continue
		}
		row, err := s.env.wrapFor(k)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR REPLACE INTO master_key (key_id, salt, nonce, wrapped) VALUES (?, ?, ?, ?)`,
			row.KeyID, row.Salt, row.Nonce, row.Wrapped); err != nil {
			return fmt.Errorf("writing master key row: %w", err)
		}
	}
	return nil
}

func (s *sqliteSessionStore) loadMasterKeyRows(ctx context.Context) ([]masterKeyRow, error) {
	rs, err := s.db.QueryContext(ctx, `SELECT key_id, salt, nonce, wrapped FROM master_key`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []masterKeyRow
	for rs.Next() {
		var r masterKeyRow
		if err := rs.Scan(&r.KeyID, &r.Salt, &r.Nonce, &r.Wrapped); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

func existingKeyIDs(rows []masterKeyRow) map[string]bool {
	m := make(map[string]bool, len(rows))
	for _, r := range rows {
		m[r.KeyID] = true
	}
	return m
}

// Load returns all non-expired session records, decrypting each with the DEK.
func (s *sqliteSessionStore) Load(ctx context.Context) ([]SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := s.db.QueryContext(ctx, `SELECT id, expiration, nonce, ciphertext FROM session`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()

	now := time.Now()
	var out []SessionRecord
	for rs.Next() {
		var id string
		var exp int64
		var nonce, ct []byte
		if err := rs.Scan(&id, &exp, &nonce, &ct); err != nil {
			return nil, err
		}
		if exp != 0 && now.After(time.Unix(exp, 0)) {
			continue // do not restore expired sessions
		}
		plain, err := s.env.open(nonce, ct)
		if err != nil {
			s.log.Warn("ccb session cache: failed to decrypt a session record; skipping", "id", id)
			continue
		}
		var rec SessionRecord
		if err := gob.NewDecoder(bytes.NewReader(plain)).Decode(&rec); err != nil {
			s.log.Warn("ccb session cache: failed to decode a session record; skipping", "id", id, "error", err)
			continue
		}
		out = append(out, rec)
	}
	return out, rs.Err()
}

// Save replaces the persisted session set with recs, encrypting each under the
// DEK. The replacement is atomic (a single transaction).
func (s *sqliteSessionStore) Save(ctx context.Context, recs []SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM session`); err != nil {
		return err
	}
	for _, rec := range recs {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(rec); err != nil {
			return fmt.Errorf("encoding session %s: %w", rec.ID, err)
		}
		nonce, ct, err := s.env.seal(buf.Bytes())
		if err != nil {
			return fmt.Errorf("encrypting session %s: %w", rec.ID, err)
		}
		var exp int64
		if !rec.Expiration.IsZero() {
			exp = rec.Expiration.Unix()
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO session (id, expiration, nonce, ciphertext) VALUES (?, ?, ?, ?)`,
			rec.ID, exp, nonce, ct); err != nil {
			return fmt.Errorf("writing session %s: %w", rec.ID, err)
		}
	}
	return tx.Commit()
}

func (s *sqliteSessionStore) Close() error {
	return s.db.Close()
}
