//go:build linux

package cmdcarrier

import "golang.org/x/sys/unix"

// dup2 points newfd at the same file as oldfd. Linux on arm64 and riscv64 has
// no dup2 syscall at all, only dup3, so that is what is used everywhere here.
func dup2(oldfd, newfd int) error { return unix.Dup3(oldfd, newfd, 0) }
