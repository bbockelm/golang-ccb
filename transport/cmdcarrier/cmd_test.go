//go:build unix

package cmdcarrier

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
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

// The failure that matters: the command starts fine and then dies. The
// explanation -- the exit status and what ssh said -- must survive, but it
// cannot be smuggled out through the read error.
//
// io.Copy and io.ReadAll recognise the end of a stream by comparing against
// io.EOF rather than unwrapping it, so a wrapped EOF reads as a failure and a
// copy reports an error where the stream merely ended. The diagnosis goes
// through Diagnostics instead, which is what the staged carrier check reports.
func TestDeadChildEndsCleanlyAndExplainsItself(t *testing.T) {
	c := dialArgv(t, "/bin/sh", "-c", "echo 'Permission denied (publickey).' >&2; exit 255")

	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("reading to the end returned %v; a stream that ended must look ended", err)
	}

	d, ok := any(c).(Diagnostics)
	if !ok {
		t.Fatalf("pipe (%T) does not implement Diagnostics", c)
	}
	if got := d.Stderr(); !strings.Contains(got, "Permission denied (publickey).") {
		t.Errorf("Stderr() = %q; the diagnosis did not survive the clean EOF", got)
	}
	exitErr, exited := d.Exited()
	if !exited {
		t.Fatal("the child was not reported as exited; EOF arrived before its status was recorded")
	}
	if exitErr == nil || !strings.Contains(exitErr.Error(), "exit status 255") {
		t.Errorf("Exited() = %v, want exit status 255", exitErr)
	}
}

// The contract, stated plainly: a carrier whose child exited cleanly is
// indistinguishable from any other stream that ended.
func TestCleanEOFIsIoEOF(t *testing.T) {
	c := dialArgv(t, "true")
	n, err := io.Copy(io.Discard, c)
	if err != nil {
		t.Fatalf("io.Copy over a cleanly-closed carrier returned %v (after %d bytes); it must be a clean end", err, n)
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

// Once Exited reports the child gone, Stderr must hold everything the child
// wrote. This child leaves its whole stderr in the pipe buffer as it exits, so
// the reader is still working when Wait returns.
func TestStderrCompleteOnceExited(t *testing.T) {
	c := dialArgv(t, "/bin/sh", "-c", `s=$(i=0; while [ $i -lt 400 ]; do echo "line $i"; i=$((i+1)); done; echo last); printf '%s\n' "$s" >&2; exit 3`)
	_, _ = io.ReadAll(c)
	if _, exited := c.Exited(); !exited {
		t.Fatal("child not reported as exited after its output ended")
	}
	if got := c.Stderr(); !strings.HasSuffix(got, "; last") {
		t.Fatalf("Stderr() does not end with the child's last line: %q", got[max(0, len(got)-80):])
	}
}

// A grandchild that inherits stderr holds the pipe open after the child is gone.
// The exit is still reported, at most stderrDrainGrace late, with what the
// child said before leaving.
func TestExitReportedWhileGrandchildHoldsStderr(t *testing.T) {
	c := dialArgv(t, "/bin/sh", "-c", "echo bye >&2; sleep 30 </dev/null >/dev/null & exit 4")
	pgid := c.proc.cmd.Process.Pid
	t.Cleanup(func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })

	_, _ = io.ReadAll(c)
	deadline := time.Now().Add(exitReportGrace + stderrDrainGrace)
	exitErr, exited := c.Exited()
	for !exited && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		exitErr, exited = c.Exited()
	}
	if !exited {
		t.Fatal("exit never reported while a grandchild held stderr open")
	}
	if exitErr == nil || !strings.Contains(exitErr.Error(), "exit status 4") {
		t.Errorf("Exited() = %v, want exit status 4", exitErr)
	}
	if got := c.Stderr(); got != "bye" {
		t.Errorf("Stderr() = %q, want %q", got, "bye")
	}
	start := time.Now()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(start); d > stderrDrainGrace {
		t.Errorf("Close took %v for a child that had already exited", d)
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

// A genuine I/O error -- not an end of stream -- still carries both of its
// causes: the underlying error and the child's exit status. Writing to a child
// that has exited is EPIPE, which is a failure rather than a clean end.
func TestRealIOErrorUnwrapsToBothCauses(t *testing.T) {
	c := dialArgv(t, "/bin/sh", "-c", "echo nope >&2; exit 42")

	// Let the child exit and the pipe tear down.
	_, _ = io.ReadAll(c)

	var err error
	for i := 0; i < 100 && err == nil; i++ {
		_, err = c.Write([]byte("x"))
		time.Sleep(10 * time.Millisecond)
	}
	if err == nil {
		t.Skip("writing to the dead child never failed on this platform")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("a write failure was reported as an end of stream: %v", err)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("errors.As(err, *exec.ExitError) = false; the exit status is not reachable: %v", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("ExitCode() = %d, want 42", got)
	}
}
