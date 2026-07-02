package ccbserver

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	htsqlite "github.com/bbockelm/golang-htcondor/sessioncache/sqlite"
)

// openSharedTestStore opens an encrypted session-cache database at path and
// returns a reconnect store sharing that database (mirroring how main.go wires
// the two together), plus the SharedStore so the caller can close the database.
func openSharedTestStore(t *testing.T, path string, flush time.Duration) (ReconnectStore, htsqlite.SharedStore) {
	t.Helper()
	keys := []htsqlite.SigningKey{{ID: "POOL", Material: bytes.Repeat([]byte{0x5a}, 32)}}
	ss, err := htsqlite.Open(path, keys, nil)
	if err != nil {
		t.Fatalf("open session store: %v", err)
	}
	shared, ok := ss.(htsqlite.SharedStore)
	if !ok {
		_ = ss.Close()
		t.Fatal("session store does not implement SharedStore")
	}
	rc, err := OpenSharedReconnectStore(shared.SharedDB(), shared.Seal, shared.Unseal, flush, nil)
	if err != nil {
		_ = ss.Close()
		t.Fatalf("open reconnect store: %v", err)
	}
	return rc, shared
}

func TestSQLiteStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	st, shared := openSharedTestStore(t, path, 10*time.Millisecond)

	st.Put(ReconnectRecord{CCBID: 1, Cookie: "c1", PeerIP: "10.0.0.1", Name: "a", UpdatedAt: time.Unix(1000, 0)})
	st.Put(ReconnectRecord{CCBID: 2, Cookie: "c2", PeerIP: "10.0.0.2", Name: "b", UpdatedAt: time.Unix(2000, 0)})
	// Coalesce: a second write to ccbid 1 should win, producing one row.
	st.Put(ReconnectRecord{CCBID: 1, Cookie: "c1b", PeerIP: "10.0.0.9", Name: "a2", UpdatedAt: time.Unix(1500, 0)})

	recs := waitForRecords(t, st, 2)
	byID := map[uint64]ReconnectRecord{}
	for _, r := range recs {
		byID[r.CCBID] = r
	}
	if byID[1].Cookie != "c1b" || byID[1].PeerIP != "10.0.0.9" {
		t.Errorf("ccbid 1 not coalesced to last write: %+v", byID[1])
	}
	if byID[2].Cookie != "c2" {
		t.Errorf("ccbid 2 wrong: %+v", byID[2])
	}

	// Delete persists.
	st.Delete(2)
	recs = waitForRecords(t, st, 1)
	if recs[0].CCBID != 1 {
		t.Errorf("after delete, expected only ccbid 1, got %+v", recs)
	}

	// The reconnect cookie must not appear in plaintext in the shared file.
	if err := st.Close(); err != nil {
		t.Fatalf("close reconnect store: %v", err)
	}
	if raw, err := os.ReadFile(path); err != nil {
		t.Fatalf("read db file: %v", err)
	} else if bytes.Contains(raw, []byte("c1b")) {
		t.Error("reconnect cookie found in plaintext in the shared database file")
	}
	if err := shared.Close(); err != nil {
		t.Fatalf("close session store: %v", err)
	}

	// Reopen (simulated restart): a fresh session store + reconnect store on the
	// same file must decrypt the surviving record.
	st2, shared2 := openSharedTestStore(t, path, 10*time.Millisecond)
	defer shared2.Close()
	defer st2.Close()
	recs, err := st2.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].CCBID != 1 || recs[0].Cookie != "c1b" || recs[0].PeerIP != "10.0.0.9" {
		t.Errorf("reopened store has wrong contents: %+v", recs)
	}
}

func TestSQLiteStoreFlushesOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	// Long flush interval: only Close() should persist the pending write.
	st, shared := openSharedTestStore(t, path, time.Hour)
	st.Put(ReconnectRecord{CCBID: 7, Cookie: "k", PeerIP: "1.2.3.4", Name: "n", UpdatedAt: time.Unix(5, 0)})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := shared.Close(); err != nil {
		t.Fatal(err)
	}

	st2, shared2 := openSharedTestStore(t, path, time.Hour)
	defer shared2.Close()
	defer st2.Close()
	recs, _ := st2.Load(context.Background())
	if len(recs) != 1 || recs[0].CCBID != 7 {
		t.Errorf("Close did not flush pending write: %+v", recs)
	}
}

func TestLoadReconnectsSeedsNextID(t *testing.T) {
	store := newMemoryStore()
	store.Put(ReconnectRecord{CCBID: 5, Cookie: "a", PeerIP: "10.0.0.5", Name: "x", UpdatedAt: time.Now()})
	store.Put(ReconnectRecord{CCBID: 42, Cookie: "b", PeerIP: "10.0.0.42", Name: "y", UpdatedAt: time.Now()})

	s, err := New(Config{
		PublicAddress:  "127.0.0.1:9618",
		Security:       plaintextSec(),
		ReconnectStore: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.nextID != 142 { // max(42) + 100 guard
		t.Errorf("nextID = %d, want 142", s.nextID)
	}
	if len(s.reconnects) != 2 || s.reconnects[42] == nil {
		t.Errorf("reconnect table not seeded: %+v", s.reconnects)
	}
}

func TestSweepReconnects(t *testing.T) {
	store := newMemoryStore()
	s, err := New(Config{
		PublicAddress:  "127.0.0.1:9618",
		Security:       plaintextSec(),
		ReconnectStore: store,
		ReconnectTTL:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A stale, disconnected record (old timestamp, no live target) -> swept.
	s.reconnects[1] = &ReconnectRecord{CCBID: 1, Cookie: "old", UpdatedAt: time.Now().Add(-2 * time.Hour)}
	store.Put(*s.reconnects[1])
	// A disconnected but fresh record -> kept.
	s.reconnects[2] = &ReconnectRecord{CCBID: 2, Cookie: "fresh", UpdatedAt: time.Now()}
	// A stale record whose target is still live -> kept.
	s.reconnects[3] = &ReconnectRecord{CCBID: 3, Cookie: "live", UpdatedAt: time.Now().Add(-2 * time.Hour)}
	s.targets[3] = &target{id: 3}

	s.SweepReconnects()

	if _, ok := s.reconnects[1]; ok {
		t.Error("stale disconnected record should have been swept")
	}
	if _, ok := s.reconnects[2]; !ok {
		t.Error("fresh record should have been kept")
	}
	if _, ok := s.reconnects[3]; !ok {
		t.Error("live target's record should have been kept despite age")
	}
	if recs, _ := store.Load(context.Background()); len(recs) != 0 {
		t.Errorf("swept record should have been deleted from store, got %+v", recs)
	}
}

// waitForRecords polls the store until it holds want records or the deadline.
func waitForRecords(t *testing.T, st ReconnectStore, want int) []ReconnectRecord {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		recs, err := st.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) == want {
			return recs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("store did not reach %d records in time", want)
	return nil
}
