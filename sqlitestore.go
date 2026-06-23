package ccbserver

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// sqliteStore is a ReconnectStore backed by SQLite with a single writer
// goroutine. Put/Delete enqueue operations that are coalesced per CCBID and
// committed in one transaction at most once per flush interval, so a burst of
// registrations costs one fsync per window rather than one per connection.
type sqliteStore struct {
	db    *sql.DB
	log   *slog.Logger
	flush time.Duration

	ops  chan storeOp
	done chan struct{}
	wg   sync.WaitGroup
}

type storeOp struct {
	del bool
	rec ReconnectRecord
}

// OpenSQLiteReconnectStore opens (creating if needed) a SQLite-backed
// ReconnectStore at path, with the given flush interval (0 selects the 50ms
// default). It is the public entry point for wiring persistence into a Server's
// Config.ReconnectStore.
func OpenSQLiteReconnectStore(path string, flush time.Duration, log *slog.Logger) (ReconnectStore, error) {
	return openSQLiteStore(path, flush, log)
}

// openSQLiteStore opens (creating if needed) the reconnect database at path and
// starts its writer goroutine. flush is the maximum delay before a queued write
// is committed (e.g. 50ms). The database uses WAL with synchronous=NORMAL so
// commits are durable across process crashes without an fsync per transaction.
func openSQLiteStore(path string, flush time.Duration, log *slog.Logger) (*sqliteStore, error) {
	if log == nil {
		log = slog.Default()
	}
	if flush <= 0 {
		flush = 50 * time.Millisecond
	}
	// busy_timeout guards against transient locks; WAL + NORMAL trade an fsync
	// per commit for a single fsync at checkpoint while remaining crash-safe.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening reconnect db: %w", err)
	}
	// A single underlying connection keeps us a true single writer and avoids
	// WAL writer contention.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS reconnect (
		ccbid      INTEGER PRIMARY KEY,
		cookie     TEXT NOT NULL,
		peer_ip    TEXT NOT NULL,
		name       TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating reconnect table: %w", err)
	}

	s := &sqliteStore{
		db:    db,
		log:   log,
		flush: flush,
		ops:   make(chan storeOp, 1024),
		done:  make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

func (s *sqliteStore) Load(ctx context.Context) ([]ReconnectRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ccbid, cookie, peer_ip, name, updated_at FROM reconnect`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReconnectRecord
	for rows.Next() {
		var r ReconnectRecord
		var ts int64
		if err := rows.Scan(&r.CCBID, &r.Cookie, &r.PeerIP, &r.Name, &ts); err != nil {
			return nil, err
		}
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

// Close stops the writer, flushing any pending operations, and closes the db.
func (s *sqliteStore) Close() error {
	close(s.done)
	s.wg.Wait()
	return s.db.Close()
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
			_, err = tx.ExecContext(ctx,
				`INSERT INTO reconnect (ccbid, cookie, peer_ip, name, updated_at)
				 VALUES (?, ?, ?, ?, ?)
				 ON CONFLICT(ccbid) DO UPDATE SET
				   cookie=excluded.cookie, peer_ip=excluded.peer_ip,
				   name=excluded.name, updated_at=excluded.updated_at`,
				op.rec.CCBID, op.rec.Cookie, op.rec.PeerIP, op.rec.Name, op.rec.UpdatedAt.Unix())
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
