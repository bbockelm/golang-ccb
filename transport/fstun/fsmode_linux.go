//go:build linux

package fstun

import (
	"os"
	"path/filepath"
	"syscall"
)

// networkFSMagic holds statfs f_type values for filesystems that do NOT provide
// coherent cross-host visibility through the page cache, so fstun must fsync
// writes and revalidate reads close-to-open. Local filesystems (ext4, xfs, btrfs,
// tmpfs, apfs, ...) are absent, so detectNetworkFS returns false for them and the
// carrier skips the fsync/reopen overhead.
var networkFSMagic = map[uint32]bool{
	0x6969:     true, // NFS_SUPER_MAGIC
	0xFF534D42: true, // CIFS_MAGIC_NUMBER
	0xFE534D42: true, // SMB2_MAGIC_NUMBER
	0x0BD00BD0: true, // LUSTRE_SUPER_MAGIC
	0x00C36400: true, // CEPH_SUPER_MAGIC
	0x01161970: true, // GFS2_MAGIC
	0x7461636F: true, // OCFS2_SUPER_MAGIC
	0x47504653: true, // GPFS ("GPFS")
	0x5346414F: true, // AFS_SUPER_MAGIC (OpenAFS)
	0x65735546: true, // FUSE_SUPER_MAGIC (sshfs et al. -- treat conservatively)
	0xFF534D41: true, // SMB_SUPER_MAGIC (smbfs)
}

// detectNetworkFS reports whether path lives on a network filesystem, by statfs
// on the nearest existing ancestor (path itself may not exist yet). Unknown or
// unstattable => false (assume local).
func detectNetworkFS(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(nearestExisting(path), &st); err != nil {
		return false
	}
	return networkFSMagic[uint32(st.Type)]
}

// nearestExisting walks up from path to the first component that exists, so
// statfs has something to stat before the root subtree is created.
func nearestExisting(path string) string {
	for {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			return path
		}
		path = parent
	}
}
