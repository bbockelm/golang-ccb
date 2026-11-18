// Package sshcarrier carries a CCB tunnel over an SSH session this broker
// opens itself, rather than by running the system ssh (the cmd: carrier).
//
// Embedding the client buys three things the spawned ssh cannot give:
//
//   - the binary can be staged on the far host before it is run, so a cluster
//     needs nothing installed in advance;
//   - authentication that needs a human can be parked and completed later by an
//     administrator, instead of failing the dial; and
//   - startup is observable step by step, rather than inferred from an exit
//     status and whatever ssh chose to print.
//
// What it costs is everything ssh_config does for free -- ProxyJump,
// ControlMaster, Match blocks, certificates, GSSAPI. The cmd: carrier remains
// the right default for a site that just wants `ssh bastion`; this is for the
// cases that need the three things above.
package sshcarrier

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// sessionConn presents an SSH session's stdin and stdout as a carrier byte
// pipe.
//
// The half-close the relay needs falls out of the protocol: closing the
// session's stdin sends EOF on the channel while stdout stays open, which is
// precisely CloseWrite. (A yamux stream had to have this adapted onto it; here
// it is native.)
type sessionConn struct {
	r      io.Reader
	w      io.WriteCloser
	sess   *ssh.Session
	client *ssh.Client
	addr   sshAddr

	// annotate explains a genuine I/O error using what the remote said on
	// stderr and how the command exited.
	annotate func(error) error

	// settle waits, briefly, for the remote command's exit status and final
	// stderr to be recorded. It runs when the stream reaches EOF so that
	// Diagnostics is already answerable by the time the relay logs the close:
	// the alternative is an accessor that blocks, or a report that races the
	// thing it is reporting on.
	settle func()

	closeOnce sync.Once
	closeErr  error
	closed    atomicBool
}

func (c *sessionConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	return n, c.filter(err)
}

func (c *sessionConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	return n, c.filter(err)
}

// filter explains a genuine I/O error, and leaves io.EOF alone.
//
// Wrapping EOF would be a quiet disaster: io.Copy and io.ReadAll test for the
// end of a stream with `err == io.EOF`, not errors.Is, so a wrapped one is not
// recognised and every clean close becomes an error. The relay would then
// report a successful transfer as a failure. Why the far command ended is
// delivered through Diagnostics instead, which the relay's close-logging
// consults -- that is where an operator reads it anyway.
//
// (errors.Is rather than == only to keep the linter happy about wrapped
// errors; a reader that returned a wrapped EOF would already be broken for
// io.Copy, so the two tests cannot disagree on anything that works.)
func (c *sessionConn) filter(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		// The command has ended; wait for its status before handing EOF on, so
		// whoever reads Diagnostics next sees a settled answer.
		if c.settle != nil && !c.closed.get() {
			c.settle()
		}
		return err
	}
	if c.closed.get() || c.annotate == nil {
		return err
	}
	return c.annotate(err)
}

// CloseWrite ends this side's sending without disturbing what is still
// arriving. Closing the session's stdin is an EOF on the channel, not a
// teardown.
func (c *sessionConn) CloseWrite() error { return c.w.Close() }

func (c *sessionConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.set()
		errs := []error{c.w.Close(), c.sess.Close(), c.client.Close()}
		// A session that has already ended reports io.EOF from Close; that is
		// the ordinary path, not a failure worth returning.
		kept := errs[:0]
		for _, err := range errs {
			if err != nil && !errors.Is(err, io.EOF) {
				kept = append(kept, err)
			}
		}
		c.closeErr = errors.Join(kept...)
	})
	return c.closeErr
}

func (c *sessionConn) LocalAddr() net.Addr  { return c.addr }
func (c *sessionConn) RemoteAddr() net.Addr { return c.addr }

// SSH channels carry no deadline mechanism. Nothing in the carrier stack needs
// one -- yamux implements deadlines on its own streams and never sets one on
// the pipe beneath -- so this reports that rather than pretending.
func (c *sessionConn) SetDeadline(time.Time) error {
	return fmt.Errorf("sshcarrier: %w", os.ErrNoDeadline)
}
func (c *sessionConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *sessionConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

type sshAddr struct{ label string }

func (a sshAddr) Network() string { return "ssh" }
func (a sshAddr) String() string  { return a.label }

// atomicBool is a tiny mutex-guarded flag; the carrier sets it once on close.
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) set() { b.mu.Lock(); b.v = true; b.mu.Unlock() }
func (b *atomicBool) get() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}

var (
	_ net.Conn                        = (*sessionConn)(nil)
	_ interface{ CloseWrite() error } = (*sessionConn)(nil)
)

// tail retains the most recent stderr lines from the far command.
type tail struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newTail(max int) *tail { return &tail{max: max} }

func (t *tail) add(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, s)
	if len(t.lines) > t.max {
		t.lines = t.lines[len(t.lines)-t.max:]
	}
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.lines, "; ")
}

// newReader adapts a bare Read method to io.Reader.
func newReader(r interface{ Read([]byte) (int, error) }) io.Reader { return readerFunc(r.Read) }

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// errorsAs is errors.As, named locally so ssh.go does not import errors twice.
func errorsAs(err error, target any) bool { return errors.As(err, target) }
