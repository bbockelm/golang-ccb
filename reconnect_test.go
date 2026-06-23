package ccbserver

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reconnect.db")
	st, err := openSQLiteStore(path, 10*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}

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

	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen and confirm durability of the surviving record.
	st2, err := openSQLiteStore(path, 10*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	recs, err = st2.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].CCBID != 1 || recs[0].Cookie != "c1b" {
		t.Errorf("reopened store has wrong contents: %+v", recs)
	}
}

func TestSQLiteStoreFlushesOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reconnect.db")
	// Long flush interval: only Close() should persist the pending write.
	st, err := openSQLiteStore(path, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Put(ReconnectRecord{CCBID: 7, Cookie: "k", PeerIP: "1.2.3.4", Name: "n", UpdatedAt: time.Unix(5, 0)})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := openSQLiteStore(path, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
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
