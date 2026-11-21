// Package carrier layers yamux multiplexing over a single-pipe transport (fstun,
// or a future WebSocket carrier), turning "one byte pipe per inside CCB" into the
// many logical connections CCB tunneling needs: the persistent upstream
// registration plus one stream per proxied connection.
//
// The outside CCB uses MuxListener as an ordinary net.Listener (Accept yields
// yamux streams across all connected inside CCBs) and Serves its cedar command
// loop on it. The inside CCB holds one MuxDialer and calls Open per dialBroker;
// wire Open into cedar's ccb dialer hook.
package carrier

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// DefaultKeepalive is how often an idle carrier sends a yamux ping when no
// interval is configured. The ping is the only traffic a quiet carrier
// produces, so on this transport it is not a liveness feature -- it is what
// stops something on the path reclaiming the tunnel as idle.
//
// 20s rather than yamux's 30s default, for margin. squid itself is rarely the
// binding constraint (read_timeout defaults to 15 minutes and restarts on every
// read); what closes an idle tunnel is usually a NAT table or a load balancer in
// between, commonly at 60s. 20s leaves two pings inside a 60s window, so one
// delayed ping does not lose the tunnel, and the cost is a few bytes a minute.
//
// This does NOT make an aggressive 30s idle timeout safe: at 20s a single
// delayed ping already exhausts it. Size the interval at no more than a third
// of the shortest idle timeout on the path and set CCB_CARRIER_KEEPALIVE
// explicitly when something on it is tighter than about a minute.
const DefaultKeepalive = 20 * time.Second

// yamuxConfig returns a yamux config with logging silenced and the keepalive
// interval set. keepalive <= 0 uses DefaultKeepalive.
func yamuxConfig(keepalive time.Duration) *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	if keepalive <= 0 {
		keepalive = DefaultKeepalive
	}
	c.KeepAliveInterval = keepalive
	// yamux fails a write that cannot complete within ConnectionWriteTimeout,
	// and a keepalive ping is a write. A keepalive shorter than that timeout
	// would let a stalled link queue several pings before the first is declared
	// dead, so keep the timeout no longer than the interval.
	if c.ConnectionWriteTimeout > keepalive {
		c.ConnectionWriteTimeout = keepalive
	}
	return c
}

// DefaultFirstStreamTimeout bounds how long a newly accepted pipe may sit
// without opening a logical connection. A real inside broker registers the
// moment its pipe is up -- the pipe is established lazily, on the first dial --
// so this is invisible to legitimate traffic while bounding what an anonymous
// peer can park on the broker.
const DefaultFirstStreamTimeout = 60 * time.Second

// PipeHooks observe the lifetime of individual pipes behind a MuxListener.
// One pipe is one carrier: a consumer that must tell a target reached over pipe
// A from one reached over pipe B registers here and reads each stream's pipe id
// with PipeIDOf.
type PipeHooks struct {
	Open  func(pipeID uint64)
	Close func(pipeID uint64)
}

// pipeConn is a stream tagged with the pipe it arrived on.
//
// It must forward CloseWrite. A relay probes for that method, and an embedded
// net.Conn does not expose it, so a wrapper that forgets leaves every spliced
// bulk transfer looking truncated while control traffic still works -- see
// halfCloseStream.
type pipeConn struct {
	net.Conn
	pipeID uint64
}

func (c *pipeConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("carrier: %T cannot half-close", c.Conn)
}

// PipeIDOf reports the pipe a connection arrived on, for a connection that came
// from a MuxListener. Pipe ids are unique for the life of that listener.
func PipeIDOf(c net.Conn) (uint64, bool) {
	pc, ok := c.(*pipeConn)
	if !ok {
		return 0, false
	}
	return pc.pipeID, true
}

// MuxOption adjusts a MuxListener.
type MuxOption func(*MuxListener)

// WithPipeHooks reports each pipe as it opens and closes. A consumer that keys
// state on the carrier uses this for its lifetime; Close runs exactly once per
// pipe that Open ran for.
func WithPipeHooks(h PipeHooks) MuxOption {
	return func(l *MuxListener) { l.hooks = h }
}

// WithFirstStreamTimeout closes a pipe that opens no stream within d. Zero or
// negative disables the check; unset means DefaultFirstStreamTimeout.
func WithFirstStreamTimeout(d time.Duration) MuxOption {
	return func(l *MuxListener) { l.firstStream = d }
}

// MuxListener accepts pipes from an inner carrier listener, runs a yamux server
// over each, and presents every accepted stream (from any pipe) as a net.Conn.
// It implements net.Listener.
type MuxListener struct {
	inner       net.Listener
	streams     chan net.Conn
	ctx         context.Context
	cancel      context.CancelFunc
	firstStream time.Duration
	hooks       PipeHooks
	nextPipe    atomic.Uint64

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewMuxListener starts serving yamux sessions over inner. It takes ownership of
// inner and closes it on Close.
func NewMuxListener(inner net.Listener, opts ...MuxOption) *MuxListener {
	ctx, cancel := context.WithCancel(context.Background())
	l := &MuxListener{
		inner:       inner,
		streams:     make(chan net.Conn),
		ctx:         ctx,
		cancel:      cancel,
		firstStream: DefaultFirstStreamTimeout,
	}
	for _, o := range opts {
		o(l)
	}
	l.wg.Add(1)
	go l.acceptPipes()
	return l
}

func (l *MuxListener) acceptPipes() {
	defer l.wg.Done()
	for {
		pipe, err := l.inner.Accept()
		if err != nil {
			return // inner closed or fatal
		}
		sess, err := yamux.Server(pipe, yamuxConfig(0))
		if err != nil {
			_ = pipe.Close()
			continue
		}
		l.wg.Add(1)
		go l.acceptStreams(sess, l.nextPipe.Add(1))
	}
}

func (l *MuxListener) acceptStreams(sess *yamux.Session, pipeID uint64) {
	defer l.wg.Done()
	defer sess.Close()
	if l.hooks.Open != nil {
		l.hooks.Open(pipeID)
	}
	if l.hooks.Close != nil {
		defer l.hooks.Close(pipeID)
	}
	// Probation: a pipe that never opens a stream is dropped. Stopping the
	// timer on the first stream leaves an established carrier untouched.
	var probation *time.Timer
	if l.firstStream > 0 {
		probation = time.AfterFunc(l.firstStream, func() { _ = sess.Close() })
		defer probation.Stop()
	}
	for {
		raw, err := sess.AcceptStream()
		if err != nil {
			return // session died
		}
		st := net.Conn(&pipeConn{Conn: withHalfClose(raw), pipeID: pipeID})
		if probation != nil {
			probation.Stop()
			probation = nil
		}
		select {
		case l.streams <- st:
		case <-l.ctx.Done():
			_ = st.Close()
			return
		}
	}
}

// Accept returns the next yamux stream from any connected inside CCB.
func (l *MuxListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.streams:
		return c, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *MuxListener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		_ = l.inner.Close()
	})
	return nil
}

func (l *MuxListener) Addr() net.Addr { return l.inner.Addr() }

// MuxDialer holds one yamux client session over a single carrier pipe. Each Open
// yields a fresh logical connection (a yamux stream) to the outside CCB.
type MuxDialer struct {
	pipe net.Conn
	sess *yamux.Session
}

// NewMuxDialer wraps an already-established carrier pipe in a yamux client. It
// takes ownership of pipe and closes it on Close.
func NewMuxDialer(pipe net.Conn) (*MuxDialer, error) {
	return NewMuxDialerKeepalive(pipe, 0)
}

// NewMuxDialerKeepalive is NewMuxDialer with an explicit keepalive interval;
// 0 uses DefaultKeepalive.
func NewMuxDialerKeepalive(pipe net.Conn, keepalive time.Duration) (*MuxDialer, error) {
	sess, err := yamux.Client(pipe, yamuxConfig(keepalive))
	if err != nil {
		return nil, err
	}
	return &MuxDialer{pipe: pipe, sess: sess}, nil
}

// Open starts a new logical connection over the shared pipe. The ctx bounds only
// the stream-open handshake; the returned conn outlives it.
func (d *MuxDialer) Open(ctx context.Context) (net.Conn, error) {
	type res struct {
		st  net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		st, err := d.sess.OpenStream()
		if err != nil {
			ch <- res{nil, err}
			return
		}
		ch <- res{withHalfClose(st), nil}
	}()
	select {
	case r := <-ch:
		return r.st, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// NumStreams reports the number of currently-open logical connections.
func (d *MuxDialer) NumStreams() int { return d.sess.NumStreams() }

// Closed reports whether the underlying session has gone away.
func (d *MuxDialer) Closed() bool { return d.sess.IsClosed() }

func (d *MuxDialer) Close() error { return d.sess.Close() }

// halfCloseStream gives a yamux stream the CloseWrite a relay needs.
//
// yamux has no CloseWrite method, so a relay that probes for one finds nothing
// and cannot tell its peer that the sender has finished. The peer then waits
// for data that will never arrive, the relay's drain grace expires, and a
// transfer that had completed is torn down and looks truncated -- on a carrier,
// every time, which is why control traffic survives it and bulk transfers do
// not.
//
// yamux's Close IS a half-close on an established stream: it sends a FIN and
// prohibits further local writes while leaving reads working. Its own Read
// says so -- "LocalClose only prohibits further local writes. Handle reads
// normally." A stream whose peer has already closed goes fully closed instead,
// which is also right: there is nothing left to read.
type halfCloseStream struct{ *yamux.Stream }

// CloseWrite ends this side's sending without disturbing what is still
// arriving the other way.
//
// Close here is the embedded yamux stream's, not this type's -- halfCloseStream
// declares no Close of its own, so there is no recursion.
func (s halfCloseStream) CloseWrite() error { return s.Close() }

// withHalfClose adapts a yamux stream for use as a relay endpoint. It is
// applied wherever a stream leaves this package, so nothing downstream has to
// know that yamux spells half-close differently.
func withHalfClose(s *yamux.Stream) net.Conn { return halfCloseStream{Stream: s} }

// WithHalfClose gives a yamux stream the CloseWrite a relay needs. Anything
// that splices onto a yamux stream must use it -- see halfCloseStream for what
// goes wrong without it, which is silent truncation of bulk transfers only.
func WithHalfClose(s *yamux.Stream) net.Conn { return withHalfClose(s) }
