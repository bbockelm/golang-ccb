package ccbserver

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sk(id string, b byte) SigningKey {
	m := make([]byte, 24)
	for i := range m {
		m[i] = b + byte(i)
	}
	return SigningKey{ID: id, Material: m}
}

func sampleRecords() []SessionRecord {
	return []SessionRecord{
		{
			ID:          "sess-1",
			Addr:        "<10.0.0.1:9618>",
			KeyData:     []byte("super-secret-session-key"),
			KeyProtocol: "AESGCM",
			PolicyText:  "[ User = \"condor@pool\" ]",
			Expiration:  time.Now().Add(time.Hour).Truncate(time.Second),
			LeaseSecs:   1800,
			Tag:         "",
			PeerVersion: "$CondorVersion: 25.12.0$",
		},
		{
			ID:         "sess-2",
			Addr:       "<10.0.0.2:9618>",
			KeyData:    []byte("another-key"),
			Expiration: time.Now().Add(2 * time.Hour).Truncate(time.Second),
		},
	}
}

func TestSessionStoreRoundTripAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	keys := []SigningKey{sk("POOL", 1)}

	st, err := OpenSessionStore(path, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	recs := sampleRecords()
	if err := st.Save(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// "Restart": reopen with the same signing key.
	st2, err := OpenSessionStore(path, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	got, err := st2.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
	byID := map[string]SessionRecord{}
	for _, r := range got {
		byID[r.ID] = r
	}
	if !bytes.Equal(byID["sess-1"].KeyData, []byte("super-secret-session-key")) {
		t.Errorf("sess-1 key not restored: %q", byID["sess-1"].KeyData)
	}
	if byID["sess-1"].PolicyText != "[ User = \"condor@pool\" ]" {
		t.Errorf("sess-1 policy not restored: %q", byID["sess-1"].PolicyText)
	}
}

func TestSessionStoreEncryptedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	st, err := OpenSessionStore(path, []SigningKey{sk("POOL", 1)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("super-secret-session-key")
	if err := st.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// The raw database file must not contain the plaintext session key.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Error("plaintext session key found in database file; at-rest encryption failed")
	}
}

func TestSessionStoreRequiresKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	if _, err := OpenSessionStore(path, nil, nil); err == nil {
		t.Error("expected error when no signing keys are available")
	}
}

func TestSessionStoreKeyRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	k1 := sk("POOL", 1)
	k2 := sk("POOL2", 9)

	// Create with k1.
	st, err := OpenSessionStore(path, []SigningKey{k1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Reopen with BOTH keys -> the DEK gets re-wrapped for k2.
	st2, err := OpenSessionStore(path, []SigningKey{k1, k2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()

	// Now only k2 is available (k1 rotated away) -> still opens and loads.
	st3, err := OpenSessionStore(path, []SigningKey{k2}, nil)
	if err != nil {
		t.Fatalf("rotation: store should open with the new key alone: %v", err)
	}
	defer st3.Close()
	got, err := st3.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 records after rotation, got %d", len(got))
	}
}

func TestSessionStoreKeyLossReinitializes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	st, err := OpenSessionStore(path, []SigningKey{sk("POOL", 1)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Reopen with a totally different key: cannot decrypt -> re-init, empty cache.
	st2, err := OpenSessionStore(path, []SigningKey{sk("DIFFERENT", 200)}, nil)
	if err != nil {
		t.Fatalf("key loss should re-initialize, not error: %v", err)
	}
	defer st2.Close()
	got, err := st2.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty cache after key loss, got %d records", len(got))
	}
	// And the new DEK must be usable for fresh saves.
	if err := st2.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatalf("save after re-init failed: %v", err)
	}
}

func TestSessionStoreSkipsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	st, err := OpenSessionStore(path, []SigningKey{sk("POOL", 1)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	recs := []SessionRecord{
		{ID: "live", KeyData: []byte("k"), Expiration: time.Now().Add(time.Hour)},
		{ID: "dead", KeyData: []byte("k"), Expiration: time.Now().Add(-time.Hour)},
	}
	if err := st.Save(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "live" {
		t.Errorf("expected only the live session, got %+v", got)
	}
}
