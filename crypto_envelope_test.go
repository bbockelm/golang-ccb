package ccbserver

import (
	"bytes"
	"errors"
	"testing"
)

func key(id string, b byte) SigningKey {
	mat := make([]byte, 24)
	for i := range mat {
		mat[i] = b + byte(i)
	}
	return SigningKey{ID: id, Material: mat}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	env, err := newEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	pool := key("POOL", 1)
	row, err := env.wrapFor(pool)
	if err != nil {
		t.Fatal(err)
	}

	// Recover the DEK from the wrapped row using the same signing key.
	env2, err := openEnvelope([]masterKeyRow{row}, []SigningKey{pool})
	if err != nil {
		t.Fatalf("openEnvelope: %v", err)
	}

	// A payload sealed by env must open under the recovered envelope.
	nonce, ct, err := env.seal([]byte("session-key-material"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := env2.open(nonce, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != "session-key-material" {
		t.Errorf("round-trip mismatch: %q", got)
	}
}

func TestEnvelopeMultipleKeysAnyOneOpens(t *testing.T) {
	env, _ := newEnvelope()
	k1 := key("POOL", 1)
	k2 := key("other", 50)
	r1, _ := env.wrapFor(k1)
	r2, _ := env.wrapFor(k2)
	rows := []masterKeyRow{r1, r2}

	// Only the second key is currently available -> still opens.
	env2, err := openEnvelope(rows, []SigningKey{k2})
	if err != nil {
		t.Fatalf("should open with any one key: %v", err)
	}
	nonce, ct, _ := env.seal([]byte("x"))
	if _, err := env2.open(nonce, ct); err != nil {
		t.Fatalf("recovered DEK should decrypt: %v", err)
	}
}

func TestEnvelopeNoMatchingKey(t *testing.T) {
	env, _ := newEnvelope()
	row, _ := env.wrapFor(key("POOL", 1))

	// A different key id -> not found.
	if _, err := openEnvelope([]masterKeyRow{row}, []SigningKey{key("rotated", 9)}); !errors.Is(err, errNoKey) {
		t.Errorf("expected errNoKey for non-matching id, got %v", err)
	}
	// Right id, wrong material -> GCM open fails -> not found.
	wrong := SigningKey{ID: "POOL", Material: bytes.Repeat([]byte{0xff}, 24)}
	if _, err := openEnvelope([]masterKeyRow{row}, []SigningKey{wrong}); !errors.Is(err, errNoKey) {
		t.Errorf("expected errNoKey for wrong material, got %v", err)
	}
}

func TestEnvelopeTamperDetection(t *testing.T) {
	env, _ := newEnvelope()
	nonce, ct, _ := env.seal([]byte("authenticated"))
	ct[0] ^= 0x80 // flip a ciphertext bit
	if _, err := env.open(nonce, ct); err == nil {
		t.Error("GCM must reject tampered ciphertext")
	}
}

func TestEnvelopeRotationRewrap(t *testing.T) {
	// Simulate adding a new signing key: recover DEK with the old key, then wrap
	// it for a new key so future boots can use either.
	env, _ := newEnvelope()
	old := key("POOL", 1)
	oldRow, _ := env.wrapFor(old)

	recovered, err := openEnvelope([]masterKeyRow{oldRow}, []SigningKey{old})
	if err != nil {
		t.Fatal(err)
	}
	newKey := key("POOL2", 7)
	newRow, err := recovered.wrapFor(newKey)
	if err != nil {
		t.Fatal(err)
	}

	// With only the new key available, the DEK still opens.
	env3, err := openEnvelope([]masterKeyRow{oldRow, newRow}, []SigningKey{newKey})
	if err != nil {
		t.Fatalf("rotation: new key should open: %v", err)
	}
	if !bytes.Equal(env3.dek, env.dek) {
		t.Error("rewrapped DEK must equal the original DEK")
	}
}
