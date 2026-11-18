//go:build darwin

package cmdcarrier

import "golang.org/x/sys/unix"

// dup2 points newfd at the same file as oldfd.
func dup2(oldfd, newfd int) error { return unix.Dup2(oldfd, newfd) }
