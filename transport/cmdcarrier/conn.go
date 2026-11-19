package cmdcarrier

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// pipeConn is a carrier byte pipe whose two directions are separate file
// descriptors: rf carries bytes from the peer, wf carries bytes to it. It
// satisfies net.Conn, so transport/carrier's yamux layer runs over it exactly
// as it does over a TCP or WebSocket pipe. It is unexported so the package can
// change how a pipe is built without changing what callers hold (a net.Conn).
//
// Deadlines work when the descriptors are pollable, which os.Pipe guarantees for
// the pipes we create for a child process. Nothing in the carrier stack requires
// them -- yamux v0.1.2 implements deadlines on its own streams and never sets one
// on the underlying pipe -- so a descriptor that cannot take a deadline (an
// inherited stdin that could not be made non-blocking) still carries a working
// carrier; SetDeadline simply reports os.ErrNoDeadline.
type pipeConn struct {
	rf, wf *os.File
	addr   pipeAddr

	// onClose runs after both descriptors are closed -- reaping a child
	// process, restoring a descriptor. May be nil.
	onClose func() error
	// annotate turns a genuine I/O error into one naming the cause. May be nil.
	annotate func(error) error

	// settle waits, briefly, for the child's exit status and last stderr to be
	// recorded. It runs when the stream reaches EOF, so that whoever asks for
	// Diagnostics next gets a settled answer rather than racing the child.
	settle func()

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

type pipeAddr struct {
	network string
	label   string
}

func (a pipeAddr) Network() string { return a.network }
func (a pipeAddr) String() string  { return a.label }

func (c *pipeConn) Read(p []byte) (int, error) {
	n, err := c.rf.Read(p)
	return n, c.filter(err)
}

func (c *pipeConn) Write(p []byte) (int, error) {
	n, err := c.wf.Write(p)
	return n, c.filter(err)
}

// filter annotates a genuine I/O error with why the peer went away -- except
// when we are the ones who closed it, since a Close we asked for is not a
// diagnosis, and except for io.EOF.
//
// io.EOF must be passed through untouched. It is how a reader signals a normal
// end of stream, and io.Copy and io.ReadAll recognise it by comparing against
// io.EOF rather than unwrapping, so a wrapped one reads as a failure and the
// copy reports an error where the stream simply ended. Annotating it here made
// this type violate the net.Conn contract: harmless where the pipe only ever
// feeds yamux, and a trap for anything else that reads it.
//
// Why the child went away is still available, through Diagnostics -- which is
// what the staged carrier check reports and where an operator reads it.
func (c *pipeConn) filter(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		if c.settle != nil && !c.closed.Load() {
			c.settle()
		}
		return err
	}
	if c.closed.Load() || c.annotate == nil {
		return err
	}
	return c.annotate(err)
}

func (c *pipeConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		errs := []error{c.rf.Close(), c.wf.Close()}
		if c.onClose != nil {
			errs = append(errs, c.onClose())
		}
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

func (c *pipeConn) LocalAddr() net.Addr  { return c.addr }
func (c *pipeConn) RemoteAddr() net.Addr { return c.addr }

func (c *pipeConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *pipeConn) SetReadDeadline(t time.Time) error {
	if err := c.rf.SetReadDeadline(t); err != nil {
		return fmt.Errorf("%s read deadline: %w", c.addr.network, err)
	}
	return nil
}

func (c *pipeConn) SetWriteDeadline(t time.Time) error {
	if err := c.wf.SetWriteDeadline(t); err != nil {
		return fmt.Errorf("%s write deadline: %w", c.addr.network, err)
	}
	return nil
}
