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

	"github.com/hashicorp/yamux"
)

// yamuxConfig returns a yamux config with logging silenced. yamux keepalive is
// left on: it gives stream-layer liveness above the carrier's own heartbeat.
func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	return c
}

// MuxListener accepts pipes from an inner carrier listener, runs a yamux server
// over each, and presents every accepted stream (from any pipe) as a net.Conn.
// It implements net.Listener.
type MuxListener struct {
	inner   net.Listener
	streams chan net.Conn
	ctx     context.Context
	cancel  context.CancelFunc

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewMuxListener starts serving yamux sessions over inner. It takes ownership of
// inner and closes it on Close.
func NewMuxListener(inner net.Listener) *MuxListener {
	ctx, cancel := context.WithCancel(context.Background())
	l := &MuxListener{
		inner:   inner,
		streams: make(chan net.Conn),
		ctx:     ctx,
		cancel:  cancel,
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
		sess, err := yamux.Server(pipe, yamuxConfig())
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
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return // session died
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
	sess, err := yamux.Client(pipe, yamuxConfig())
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
