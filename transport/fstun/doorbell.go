package fstun

import (
	"os"
	"path/filepath"
	"time"
)

// doorbellName is the single file at the root that initiators "ring" to announce
// a new subtree, so the acceptor can watch ONE file cheaply instead of listing
// the whole (NFS) directory on a tight loop. See docs/TRANSPORTS.md §4.1.1.
const doorbellName = ".doorbell"

// ringDoorbell announces a newly-created connection subtree to the acceptor.
//
// It bumps the root doorbell's mtime with a single os.Chtimes -- an atomic
// SETATTR RPC. We deliberately do NOT append: O_APPEND on NFS is TOCTOU (the
// client reads the size, then writes at that offset), so concurrent initiators
// sharing the root clobber each other's bytes and size is not reliably monotonic.
// A SETATTR has no such race and does not grow the file. The mtime is only a
// *hint* to scan sooner; correctness comes from the authoritative readdir and the
// slow-scan backstop, so coarse mtime granularity (which can merge closely-spaced
// rings) and clock skew (the acceptor compares to the last value it saw, not its
// own clock) are both tolerable.
//
// It then fsyncs the root directory so the just-created subtree's directory entry
// is pushed to the server rather than lingering in the local write-back cache.
func ringDoorbell(root string) error {
	db := filepath.Join(root, doorbellName)
	// First arrival creates the file; subsequent rings just re-stamp its mtime.
	if f, err := os.OpenFile(db, os.O_CREATE, 0o600); err == nil {
		_ = f.Close()
	} else {
		return err
	}
	now := time.Now()
	if err := os.Chtimes(db, now, now); err != nil {
		return err
	}
	if d, err := os.Open(root); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// doorbellState is the acceptor's last-observed doorbell mtime; a change means "a
// client may have arrived, do a scan". mtime (not size) is the signal because the
// ring is a SETATTR, not an append (see ringDoorbell).
type doorbellState struct {
	mtimeNanos int64
	seen       bool
}

// changed stats the doorbell and reports whether its mtime moved since the last
// look (also true the first time it appears). Any delta counts -- including a
// backward jump from a peer's slow clock. A missing doorbell is not a change.
func (s *doorbellState) changed(root string) bool {
	fi, err := os.Stat(filepath.Join(root, doorbellName))
	if err != nil {
		return false
	}
	m := fi.ModTime().UnixNano()
	if !s.seen || m != s.mtimeNanos {
		s.mtimeNanos, s.seen = m, true
		return true
	}
	return false
}
