package ccbserver

import (
	"context"
	"time"
)

// ReconnectRecord is the persistent state that lets a registered target reclaim
// its CCBID (and therefore its advertised sinful) after the target's connection
// drops or the broker restarts. It mirrors the (peer-ip, ccbid, cookie) triple
// the C++ CCB stores in its CCB_RECONNECT_FILE, plus the target name for
// diagnostics and an update timestamp for sweeping stale records.
type ReconnectRecord struct {
	CCBID     uint64
	Cookie    string
	PeerIP    string
	Name      string
	UpdatedAt time.Time
}

// ReconnectStore persists reconnect records. Put and Delete are asynchronous and
// best-effort: implementations are expected to batch them and flush
// periodically (so registrations do not pay an fsync each). Load is synchronous
// and used once at startup; Close flushes and releases resources.
//
// A nil store disables persistence (reconnect still works within a single
// process lifetime via the in-memory table).
type ReconnectStore interface {
	Load(ctx context.Context) ([]ReconnectRecord, error)
	Put(rec ReconnectRecord)
	Delete(ccbid uint64)
	Close() error
}

// memoryStore is a synchronous in-memory ReconnectStore, used in tests and as a
// reference implementation. It is safe for the server's single-writer use.
type memoryStore struct {
	recs map[uint64]ReconnectRecord
}

func newMemoryStore() *memoryStore {
	return &memoryStore{recs: map[uint64]ReconnectRecord{}}
}

func (m *memoryStore) Load(context.Context) ([]ReconnectRecord, error) {
	out := make([]ReconnectRecord, 0, len(m.recs))
	for _, r := range m.recs {
		out = append(out, r)
	}
	return out, nil
}

func (m *memoryStore) Put(rec ReconnectRecord) { m.recs[rec.CCBID] = rec }
func (m *memoryStore) Delete(ccbid uint64)     { delete(m.recs, ccbid) }
func (m *memoryStore) Close() error            { return nil }
