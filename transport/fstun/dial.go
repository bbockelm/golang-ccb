package fstun

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Dial establishes a byte pipe to the acceptor listening on cfg.Root, by creating
// a fresh <conn-id>/ subtree, writing a SYN into its send direction, and waiting
// for the acceptor's SYN. It is the initiator (inside CCB) side.
func Dial(ctx context.Context, cfg Config) (*Conn, error) {
	rc, params, err := cfg.resolve()
	if err != nil {
		return nil, err
	}
	connID, err := newConnID()
	if err != nil {
		return nil, err
	}
	c, err := handshake(ctx, rc, params, cfg.Root, connID, roleInitiator)
	if err != nil {
		// Never-established: the initiator owns cleanup so a failed dial leaks
		// neither its (hashed) work subtree nor its inbox marker.
		_ = os.RemoveAll(connPath(cfg.Root, connID))
		_ = os.Remove(inboxMarkerPath(cfg.Root, connID))
		return nil, err
	}
	return c, nil
}

// handshake creates the send direction, writes our SYN as frame 0, opens the recv
// direction, and waits for the peer's SYN. On success it starts a live Conn.
func handshake(ctx context.Context, rc resolvedConfig, params synParams, root, connID string, r role) (*Conn, error) {
	connDir := connPath(root, connID)
	sendDir := filepath.Join(connDir, r.sendDir())
	w, err := newSegWriter(sendDir, rc.segmentSize, rc.sync)
	if err != nil {
		return nil, fmt.Errorf("fstun: opening send dir: %w", err)
	}
	// Our SYN is frame 0 of the send direction, written before any DATA; force it
	// to the server so the peer can read it promptly even when Sync is off.
	syn := &frame{typ: frameSYN, seq: 0, dataOff: 0, payload: params.encode()}
	if err := w.append(syn, 0); err != nil {
		w.close()
		return nil, fmt.Errorf("fstun: writing SYN: %w", err)
	}
	w.syncNow()

	// The initiator announces itself AFTER its work subtree + SYN exist: it drops
	// a marker in the small inbox and rings the doorbell, so the acceptor learns
	// of the arrival by reading the inbox rather than listing the (hashed, large)
	// work tree. Best-effort: the acceptor's slow inbox scan is the backstop.
	if r == roleInitiator {
		if writeInboxMarker(root, connID) == nil {
			_ = ringDoorbell(root)
		}
	}

	sr := newSegReader(filepath.Join(connDir, r.recvDir()))
	peer, err := waitSYN(ctx, sr, rc)
	if err != nil {
		w.close()
		sr.close()
		return nil, err
	}
	if peer.version > protocolVersion {
		w.close()
		sr.close()
		return nil, fmt.Errorf("fstun: peer speaks protocol v%d, we speak v%d", peer.version, protocolVersion)
	}
	// sendSeq starts at 1 (SYN was frame 0). params are our own send-side choices.
	return newConn(rc, connDir, r, w, sr, 1, params), nil
}

// waitSYN reads the first frame of the recv direction, which must be a SYN,
// tolerating the file not existing yet and torn tails, until it appears or the
// handshake deadline / ctx fires.
func waitSYN(ctx context.Context, sr *segReader, rc resolvedConfig) (synParams, error) {
	deadline := time.Now().Add(rc.handshakeTimeout)
	poll := time.NewTimer(rc.pollInterval)
	defer poll.Stop()
	for {
		f, err := sr.next()
		switch {
		case err == nil:
			if f.typ != frameSYN {
				return synParams{}, fmt.Errorf("fstun: expected SYN, got %s", f.typ)
			}
			return decodeSynParams(f.payload)
		case errors.Is(err, errIncompleteFrame) || errors.Is(err, os.ErrNotExist):
			// keep waiting
		default:
			return synParams{}, fmt.Errorf("fstun: reading SYN: %w", err)
		}
		if time.Now().After(deadline) {
			return synParams{}, fmt.Errorf("fstun: timed out waiting for peer SYN after %s", rc.handshakeTimeout)
		}
		poll.Reset(rc.pollInterval)
		select {
		case <-poll.C:
		case <-ctx.Done():
			return synParams{}, ctx.Err()
		}
	}
}

func newConnID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
