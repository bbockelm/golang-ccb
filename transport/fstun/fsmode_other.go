//go:build !linux

package fstun

// detectNetworkFS cannot portably identify a network filesystem off Linux, so it
// assumes local. Set Config.NetworkFS explicitly to force network-mode behaviour
// (fsync batching + close-to-open reads) on a non-Linux NFS mount.
func detectNetworkFS(path string) bool { return false }
