//go:build unix

package cmdcarrier

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func dialArgv(t *testing.T, argv ...string) *cmdConn {
	t.Helper()
	c, err := Dial(context.Background(), DialConfig{Argv: argv})
	if err != nil {
		t.Fatalf("Dial(%q): %v", argv, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	cc, ok := c.(*cmdConn)
	if !ok {
		t.Fatalf("Dial returned %T, want *cmdConn", c)
	}
	return cc
}

// cat echoes stdin to stdout, so the pipe is a loopback: bytes written to the
// child come back. That exercises both directions of the plumbing at once.
func TestDialCarriesBytesBothWays(t *testing.T) {
	c := dialArgv(t, "cat")
	payload := strings.Repeat("ccb carrier payload\n", 500)
	go func() {
		_, _ = io.WriteString(c, payload)
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != payload {
		t.Errorf("echoed payload differs from what was written")
	}
}

// os.Pipe descriptors are pollable, so the pipe honours deadlines even though
// nothing in the carrier stack requires it.
func TestDeadlinesWork(t *testing.T) {
	c := dialArgv(t, "cat")
	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after deadline = %v, want os.ErrDeadlineExceeded", err)
	}
}

// The failure that matters: the command starts fine and then dies. Without the
// exit status and the child's own stderr this reaches the operator as a bare
// EOF, which says nothing about an ssh that was refused.
func TestReadErrorNamesExitStatusAndStderr(t *testing.T) {
	c := dialArgv(t, "/bin/sh", "-c", "echo 'Permission denied (publickey).' >&2; exit 255")
	_, err := io.ReadAll(c)
	if err == nil {
		t.Fatal("reading from a pipe whose child died returned no error")
	}
	for _, want := range []string{"exit status 255", "Permission denied (publickey).", "carrier command"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if !errors.Is(err, io.EOF) {
		t.Errorf("annotating the error lost the underlying io.EOF: %v", err)
	}
}

func TestExitedAndStderrAreReadable(t *testing.T) {
	c := dialArgv(t, "/bin/sh", "-c", "echo first >&2; echo second >&2; exit 3")
	_, _ = io.ReadAll(c)
	exitErr, exited := c.Exited()
	if !exited {
		t.Fatal("child not reported as exited after its output ended")
	}
	if exitErr == nil || !strings.Contains(exitErr.Error(), "exit status 3") {
		t.Errorf("Exited() = %v, want exit status 3", exitErr)
	}
	if got := c.Stderr(); got != "first; second" {
		t.Errorf("Stderr() = %q, want %q", got, "first; second")
	}
}

// A clean exit is reported as such rather than as a failure, so an operator is
// not sent hunting for an error that does not exist.
func TestCleanExitIsNotReportedAsFailure(t *testing.T) {
	c := dialArgv(t, "true")
	_, err := io.ReadAll(c)
	if err == nil {
		t.Fatal("want an error explaining the carrier closed")
	}
	if !strings.Contains(err.Error(), "exited cleanly") {
		t.Errorf("error %q does not say the child exited cleanly", err)
	}
}

// Close must reap the child. A carrier that is re-established on every failure
// would otherwise leave an ssh process behind each time.
func TestCloseStopsTheChild(t *testing.T) {
	c := dialArgv(t, "sleep", "300")
	pid := c.proc.cmd.Process.Pid
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, exited := c.Exited(); !exited {
		t.Fatal("Close returned before the child was reaped")
	}
	// Signal 0 probes for the process without touching it. After Wait the pid
	// is released, so this must fail.
	if err := syscall.Kill(pid, 0); err == nil {
		t.Errorf("child pid %d still exists after Close", pid)
	}
}

// Our own Close is not a diagnosis, so it must not be dressed up as one.
func TestCloseDoesNotAnnotateItsOwnError(t *testing.T) {
	c := dialArgv(t, "cat")
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("read on a closed pipe returned no error")
	}
	if strings.Contains(err.Error(), "carrier command") {
		t.Errorf("error %q annotates a close we asked for", err)
	}
}

func TestDialRejectsBadProgram(t *testing.T) {
	for _, tc := range []struct{ name, prog, want string }{
		{"relative path", "./htc-ccb", "relative path"},
		{"not on PATH", "htc-ccb-does-not-exist", "not found on PATH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Dial(context.Background(), DialConfig{Argv: []string{tc.prog}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Dial(%q) = %v, want an error containing %q", tc.prog, err, tc.want)
			}
		})
	}
	if _, err := Dial(context.Background(), DialConfig{}); err == nil {
		t.Error("Dial with no command returned no error")
	}
}

// ctx bounds the start, not the pipe: a carrier is established once and then
// carries every logical connection, so a cancelled dial context must not take
// the carrier down with it.
func TestDialContextDoesNotOwnThePipe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c, err := Dial(ctx, DialConfig{Argv: []string{"cat"}})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	cancel()
	time.Sleep(50 * time.Millisecond)
	if _, err := io.WriteString(c, "still here\n"); err != nil {
		t.Fatalf("write after the dial context was cancelled: %v", err)
	}
	buf := make([]byte, len("still here\n"))
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read after the dial context was cancelled: %v", err)
	}
}
