package ccbserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// sqliteStore is a ReconnectStore backed by a table in a SQLite database, with a
// single writer goroutine. Put/Delete enqueue operations that are coalesced per
// CCBID and committed in one transaction at most once per flush interval, so a
// burst of registrations costs one fsync per window rather than one per
// connection.
//
// Each record's secret fields are encrypted at rest with the caller-supplied
// seal/unseal (the session cache's data-encryption key), so the shared database
// file leaks no reconnect cookies without a signing key. The database is owned
// by the session cache; this store shares its handle and never closes it.
type sqliteStore struct {
	db     *sql.DB
	log    *slog.Logger
	flush  time.Duration
	seal   func([]byte) ([]byte, error)
	unseal func([]byte) ([]byte, error)

	ops  chan storeOp
	done chan struct{}
	wg   sync.WaitGroup
}

type storeOp struct {
	del bool
	rec ReconnectRecord
}

// sealedReconnect is the plaintext payload sealed into a reconnect row's blob.
// ccbid and updated_at remain plaintext columns so the writer can key and sweep
// rows without decrypting; only the secret fields are encrypted.
type sealedReconnect struct {
	Cookie string `json:"c"`
	PeerIP string `json:"p"`
	Name   string `json:"n"`
}

// OpenSharedReconnectStore returns a ReconnectStore that persists reconnect
// records in db -- typically the session cache's shared SQLite handle -- with
// each record's secret fields encrypted via seal/unseal (the session cache's
// DEK). It creates its table if needed. The store does NOT own db and never
// closes it; the session cache owns the database lifecycle. flush is the maximum
// delay before a queued write is committed (0 selects a 50ms default).
func OpenSharedReconnectStore(db *sql.DB, seal, unseal func([]byte) ([]byte, error), flush time.Duration, log *slog.Logger) (ReconnectStore, error) {
	if db == nil {
		return nil, fmt.Errorf("reconnect store: nil database")
	}
	if seal == nil || unseal == nil {
		return nil, fmt.Errorf("reconnect store: seal/unseal are required for encrypted persistence")
	}
	if log == nil {
		log = slog.Default()
	}
	if flush <= 0 {
		flush = 50 * time.Millisecond
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS reconnect (
		ccbid      INTEGER PRIMARY KEY,
		sealed     BLOB NOT NULL,
		updated_at INTEGER NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("creating reconnect table: %w", err)
	}

	s := &sqliteStore{
		db:     db,
		log:    log,
		flush:  flush,
		seal:   seal,
		unseal: unseal,
		ops:    make(chan storeOp, 1024),
		done:   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

func (s *sqliteStore) Load(ctx context.Context) ([]ReconnectRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ccbid, sealed, updated_at FROM reconnect`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReconnectRecord
	for rows.Next() {
		var r ReconnectRecord
		var sealed []byte
		var ts int64
		if err := rows.Scan(&r.CCBID, &sealed, &ts); err != nil {
			return nil, err
		}
		plain, err := s.unseal(sealed)
		if err != nil {
			// A record we cannot decrypt (e.g. after a key loss) is useless;
			// drop it and let the target re-register rather than failing to load.
			s.log.Warn("ccb reconnect store: dropping undecryptable record", "ccbid", r.CCBID, "error", err)
			continue
		}
		var p sealedReconnect
		if err := json.Unmarshal(plain, &p); err != nil {
			s.log.Warn("ccb reconnect store: dropping malformed record", "ccbid", r.CCBID, "error", err)
			continue
		}
		r.Cookie, r.PeerIP, r.Name = p.Cookie, p.PeerIP, p.Name
		r.UpdatedAt = time.Unix(ts, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqliteStore) Put(rec ReconnectRecord) {
	s.enqueue(storeOp{rec: rec})
}

func (s *sqliteStore) Delete(ccbid uint64) {
	s.enqueue(storeOp{del: true, rec: ReconnectRecord{CCBID: ccbid}})
}

func (s *sqliteStore) enqueue(op storeOp) {
	select {
	case s.ops <- op:
	case <-s.done:
	}
}

// Close stops the writer, flushing any pending operations. It does not close the
// shared database (the session cache owns it).
func (s *sqliteStore) Close() error {
	close(s.done)
	s.wg.Wait()
	return nil
}

// writer is the single goroutine that owns all writes. It coalesces operations
// per CCBID and commits the accumulated batch once per flush tick.
func (s *sqliteStore) writer() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flush)
	defer ticker.Stop()

	batch := map[uint64]storeOp{}
	for {
		select {
		case op := <-s.ops:
			batch[op.rec.CCBID] = op // last write per ccbid wins
		case <-ticker.C:
			s.commit(batch)
			batch = map[uint64]storeOp{}
		case <-s.done:
			// Drain anything still queued, then do a final commit.
			for {
				select {
				case op := <-s.ops:
					batch[op.rec.CCBID] = op
					continue
				default:
				}
				break
			}
			s.commit(batch)
			return
		}
	}
}

func (s *sqliteStore) commit(batch map[uint64]storeOp) {
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.log.Warn("ccb reconnect store: begin tx failed", "error", err)
		return
	}
	for _, op := range batch {
		if op.del {
			_, err = tx.ExecContext(ctx, `DELETE FROM reconnect WHERE ccbid = ?`, op.rec.CCBID)
		} else {
			var payload []byte
			payload, err = json.Marshal(sealedReconnect{
				Cookie: op.rec.Cookie,
				PeerIP: op.rec.PeerIP,
				Name:   op.rec.Name,
			})
			if err == nil {
				var sealed []byte
				if sealed, err = s.seal(payload); err == nil {
					_, err = tx.ExecContext(ctx,
						`INSERT INTO reconnect (ccbid, sealed, updated_at)
						 VALUES (?, ?, ?)
						 ON CONFLICT(ccbid) DO UPDATE SET
						   sealed=excluded.sealed, updated_at=excluded.updated_at`,
						op.rec.CCBID, sealed, op.rec.UpdatedAt.Unix())
				}
			}
		}
		if err != nil {
			s.log.Warn("ccb reconnect store: write failed, rolling back batch", "error", err)
			_ = tx.Rollback()
			return
		}
	}
	if err := tx.Commit(); err != nil {
		s.log.Warn("ccb reconnect store: commit failed", "error", err)
	}
}
