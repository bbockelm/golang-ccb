package fstun

import (
	"os"
	"path/filepath"
)

const (
	// inboxDirName is the small directory of arrival markers under the root. An
	// initiator drops <root>/inbox/<connID>; the acceptor reads this (small)
	// directory to learn of new tunnels instead of listing the whole work tree,
	// and removes each marker once it has engaged the tunnel.
	inboxDirName = "inbox"

	// hashPrefixLen fans the work tree out by the first hashPrefixLen hex chars of
	// the (random hex) conn-id: <root>/<ab>/<cdef...>/. With a 2-char prefix that
	// is up to 256 fan-out directories, so no single directory accumulates all
	// tunnels -- important on filesystems that degrade with huge entry counts.
	// The acceptor never lists the work tree except at startup, so the fan-out is
	// purely to bound per-directory size.
	hashPrefixLen = 2
)

// connPath is the hashed work-subtree path for a conn-id.
func connPath(root, id string) string {
	if len(id) <= hashPrefixLen {
		return filepath.Join(root, id)
	}
	return filepath.Join(root, id[:hashPrefixLen], id[hashPrefixLen:])
}

// inboxMarkerPath is the arrival-marker path for a conn-id.
func inboxMarkerPath(root, id string) string {
	return filepath.Join(root, inboxDirName, id)
}

// writeInboxMarker drops an empty marker named after the conn-id in the inbox and
// fsyncs the inbox directory so the entry is pushed to the server. The marker
// carries no content -- its name is the conn-id, and its presence means "a new
// tunnel may exist at connPath(root, id)".
func writeInboxMarker(root, id string) error {
	inbox := filepath.Join(root, inboxDirName)
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(inboxMarkerPath(root, id), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_ = f.Close()
	if d, err := os.Open(inbox); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
