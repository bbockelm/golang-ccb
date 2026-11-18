//go:build linux || darwin

package cmdcarrier

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var stdioOnce sync.Once

// Stdio claims this process's own stdin and stdout as a carrier byte pipe. It is
// the far end of a cmd: carrier -- what `ssh host htc-ccb -carrier-stdio` runs --
// and what lets the broker at the far end of an SSH session join the pool
// without binding a port of its own.
//
// It does three things beyond wrapping the descriptors, each closing a way the
// carrier would otherwise be corrupted or unexplainable:
//
//   - The descriptors are duplicated and fd 1 is then pointed at fd 2. The pipe
//     carries a framed protocol, so one stray write to stdout -- a library's
//     fmt.Println, a panic trace, a debugging line -- would corrupt it in a way
//     that surfaces as an unintelligible yamux error. After this, a stray write
//     lands in the log where it belongs and the carrier is unaffected.
//   - fd 0 is pointed at /dev/null for the same reason in reverse: anything that
//     reads stdin expecting the terminal cannot steal carrier bytes.
//   - The duplicates are put in non-blocking mode when they are pipes or
//     sockets, which is what makes them pollable and so able to take deadlines.
//     A terminal is left alone: its flags are shared with whatever else has it
//     open, and the carrier does not need deadlines.
//
// It may be called once; a second call is a programming error, since the
// descriptors have already been moved.
func Stdio(log *slog.Logger) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	called := false
	stdioOnce.Do(func() {
		called = true
		conn, err = claimStdio(log)
	})
	if !called {
		return nil, fmt.Errorf("cmdcarrier: stdin and stdout have already been claimed as a carrier")
	}
	return conn, err
}

func claimStdio(log *slog.Logger) (net.Conn, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	rfd, err := unix.Dup(unix.Stdin)
	if err != nil {
		return nil, fmt.Errorf("cmdcarrier: duplicating stdin: %w", err)
	}
	unix.CloseOnExec(rfd)
	wfd, err := unix.Dup(unix.Stdout)
	if err != nil {
		_ = unix.Close(rfd)
		return nil, fmt.Errorf("cmdcarrier: duplicating stdout: %w", err)
	}
	unix.CloseOnExec(wfd)

	// Point stdout at stderr and stdin at /dev/null. Failing here is not fatal:
	// the carrier works, it is just no longer protected from a stray write, so
	// say so rather than refusing to start.
	if err := dup2(unix.Stderr, unix.Stdout); err != nil {
		log.Warn("could not redirect stdout away from the carrier pipe; a stray write to stdout will corrupt the tunnel", "error", err)
	}
	if devnull, err := unix.Open(os.DevNull, unix.O_RDWR, 0); err == nil {
		if err := dup2(devnull, unix.Stdin); err != nil {
			log.Warn("could not redirect stdin away from the carrier pipe", "error", err)
		}
		_ = unix.Close(devnull)
	} else {
		log.Warn("could not open "+os.DevNull+" to redirect stdin away from the carrier pipe", "error", err)
	}

	pollable := makePollable(rfd) && makePollable(wfd)
	log.Debug("carrier claimed stdin and stdout", "pollable", pollable)

	return &pipeConn{
		rf:   os.NewFile(uintptr(rfd), "carrier-stdin"),
		wf:   os.NewFile(uintptr(wfd), "carrier-stdout"),
		addr: pipeAddr{network: "stdio", label: "stdio"},
	}, nil
}

// makePollable puts a pipe or socket into non-blocking mode so os.NewFile
// registers it with the runtime poller and deadlines work. Anything else -- a
// terminal, a regular file -- is left as it is: O_NONBLOCK lives on the open
// file description, which a terminal shares with every other process that has
// it open, and the carrier does not need deadlines.
func makePollable(fd int) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFIFO, unix.S_IFSOCK:
		return unix.SetNonblock(fd, true) == nil
	default:
		return false
	}
}
