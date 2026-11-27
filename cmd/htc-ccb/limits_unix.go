//go:build unix

package main

import "syscall"

// descriptorLimit returns the soft RLIMIT_NOFILE (which the Go runtime raises
// to the hard limit at startup), or 0 if it is unknown or effectively
// unlimited.
func descriptorLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	if rl.Cur == 0 || rl.Cur >= 1<<31 {
		return 0
	}
	return rl.Cur
}
