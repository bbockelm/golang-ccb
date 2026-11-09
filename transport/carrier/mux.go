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
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// DefaultKeepalive is how often an idle carrier sends a yamux ping when no
// interval is configured. It is yamux's own default, and it is chosen here for
// a different reason than liveness: the ping is the only traffic a quiet
// carrier produces, so it is also what stops a site proxy from reclaiming the
// tunnel as idle. It must therefore be comfortably shorter than the shortest
// idle timeout on the path.
const DefaultKeepalive = 30 * time.Second

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

// MuxOption adjusts a MuxListener.
type MuxOption func(*MuxListener)

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
		go l.acceptStreams(sess)
	}
}

func (l *MuxListener) acceptStreams(sess *yamux.Session) {
	defer l.wg.Done()
	defer sess.Close()
	// Probation: a pipe that never opens a stream is dropped. Stopping the
	// timer on the first stream leaves an established carrier untouched.
	var probation *time.Timer
	if l.firstStream > 0 {
		probation = time.AfterFunc(l.firstStream, func() { _ = sess.Close() })
		defer probation.Stop()
	}
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return // session died
		}
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
		ch <- res{st, err}
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
