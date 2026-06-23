package ccbserver

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
)

func makeEntry(t *testing.T, id string) *security.SessionEntry {
	t.Helper()
	policy := classad.New()
	_ = policy.Set("User", "condor@pool.example")
	_ = policy.Set("Encryption", "AESGCM")
	ki := &security.KeyInfo{Data: []byte("session-key-" + id), Protocol: "AESGCM"}
	e := security.NewSessionEntry(id, "<10.0.0.1:9618>", ki, policy,
		time.Now().Add(time.Hour), 30*time.Minute, "")
	e.SetLastPeerVersion("$CondorVersion: 25.12.0$")
	return e
}

// TestSessionEntryConversionRoundTrip verifies a SessionEntry survives the
// entry->record->store->record->entry round trip with key and policy intact.
func TestSessionEntryConversionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	keys := []SigningKey{sk("POOL", 3)}

	store, err := OpenSessionStore(path, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	orig := makeEntry(t, "conv-1")
	if err := store.Save(context.Background(), []SessionRecord{entryToRecord(orig)}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	store2, err := OpenSessionStore(path, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	recs, err := store2.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	got, err := recordToEntry(recs[0])
	if err != nil {
		t.Fatalf("recordToEntry: %v", err)
	}
	if got.ID() != "conv-1" || got.Addr() != "<10.0.0.1:9618>" {
		t.Errorf("identity not restored: id=%q addr=%q", got.ID(), got.Addr())
	}
	if got.KeyInfo() == nil || string(got.KeyInfo().Data) != "session-key-conv-1" {
		t.Errorf("session key not restored: %+v", got.KeyInfo())
	}
	if got.LastPeerVersion() != "$CondorVersion: 25.12.0$" {
		t.Errorf("peer version not restored: %q", got.LastPeerVersion())
	}
	if u, ok := got.Policy().EvaluateAttrString("User"); !ok || u != "condor@pool.example" {
		t.Errorf("policy User not restored: %q (ok=%v)", u, ok)
	}
}

// TestSessionPersistenceRestoreSnapshot exercises snapshot() then restore()
// through the global cache: a session stored in the cache is snapshotted, the
// entry is removed, and restore() brings it back resumable.
func TestSessionPersistenceRestoreSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	keys := []SigningKey{sk("POOL", 5)}

	cache := security.GetSessionCache()
	id := "restore-snap-unique-1"
	cache.Store(makeEntry(t, id))

	store, err := OpenSessionStore(path, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := newSessionPersistence(store, nil, time.Minute)
	if err := p.snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.Close()

	// Simulate the entry being gone after a restart.
	cache.Invalidate(id)
	if _, ok := cache.LookupNonExpired(id); ok {
		t.Fatal("entry should be gone before restore")
	}

	store2, err := OpenSessionStore(path, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	p2 := newSessionPersistence(store2, nil, time.Minute)
	if err := p2.restore(context.Background()); err != nil {
		t.Fatal(err)
	}

	restored, ok := cache.LookupNonExpired(id)
	if !ok {
		t.Fatal("session was not restored into the cache")
	}
	if restored.KeyInfo() == nil || string(restored.KeyInfo().Data) != "session-key-"+id {
		t.Errorf("restored session key mismatch: %+v", restored.KeyInfo())
	}
}

// TestSessionPersistenceSkipsInherited verifies inherited sessions are not
// persisted (they are re-imported from the environment each boot).
func TestSessionPersistenceSkipsInherited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	keys := []SigningKey{sk("POOL", 7)}

	cache := security.GetSessionCache()
	inh := makeEntry(t, "inherited-unique-1")
	inh.SetInherited(true)
	cache.Store(inh)
	keep := makeEntry(t, "normal-unique-1")
	cache.Store(keep)

	store, err := OpenSessionStore(path, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p := newSessionPersistence(store, nil, time.Minute)
	if err := p.snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}

	recs, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.ID == "inherited-unique-1" {
			t.Error("inherited session must not be persisted")
		}
	}
}
