// Package splice implements the far end of a CCB carrier as a byte relay.
//
// A splice helper runs on a restricted host and does one thing: it accepts
// local TCP connections and copies each onto its own stream of the carrier.
// It terminates no protocol, parses no ClassAds, holds no credentials, and
// needs no HTCondor configuration. Every daemon that reaches it is running one
// end-to-end CEDAR session with the outside broker, which is where
// authentication and authorization happen.
//
// This is the alternative to running a second CCB broker on the far side. See
// golang-ccb docs/SPLICE_HELPER.md for the model, what it costs, and the
// experiments behind it. The outside broker recognises targets that registered
// over a carrier and gives them a contact that nests through the carrier's id,
// which is what puts an ordinary client on the streaming path.
package splice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/bbockelm/golang-ccb/transport/carrier"
)

// DefaultKeepalive matches the carrier's, so a helper and a broker agree about
// when a silent pipe is dead.
const DefaultKeepalive = 30 * time.Second

// Config is everything a helper needs, which is not much.
type Config struct {
	// Listen is the local address daemons reach this helper at. It is the
	// address they put in their CCB configuration, and the only one they ever
	// need: for an incoming reversal the first hop out is the broker they
	// registered through, so nothing else has to be announced or agreed.
	Listen string

	// Pipe is the carrier: one reliable, ordered, bidirectional byte stream to
	// the outside broker. For a staged helper it is stdin/stdout.
	Pipe net.Conn

	// Keepalive bounds how long a silent pipe may sit before it is declared
	// dead. Zero means DefaultKeepalive.
	Keepalive time.Duration

	Log *slog.Logger
}

// Helper is a running splice helper.
type Helper struct {
	cfg  Config
	log  *slog.Logger
	sess *yamux.Session
	ln   net.Listener
	wg   sync.WaitGroup

	// live are the local connections being relayed. Shutting down has to close
	// them: a relay sits in io.Copy on a local socket that nothing else will
	// ever close, so waiting for the copies to finish without closing them
	// first waits for the peers, not for us.
	mu        sync.Mutex
	live      map[net.Conn]struct{}
	closing   bool
	closeOnce sync.Once
}

// Start brings up the carrier session and the local listener. The caller runs
// Serve and closes with Close.
func Start(cfg Config) (*Helper, error) {
	if cfg.Pipe == nil {
		return nil, errors.New("splice: no carrier pipe")
	}
	if cfg.Listen == "" {
		return nil, errors.New("splice: no listen address")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	ka := cfg.Keepalive
	if ka <= 0 {
		ka = DefaultKeepalive
	}
	yc := yamux.DefaultConfig()
	yc.LogOutput = io.Discard
	yc.KeepAliveInterval = ka
	if yc.ConnectionWriteTimeout > ka {
		yc.ConnectionWriteTimeout = ka
	}
	sess, err := yamux.Client(cfg.Pipe, yc)
	if err != nil {
		return nil, fmt.Errorf("splice: yamux over the carrier: %w", err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("splice: listening on %s: %w", cfg.Listen, err)
	}
	log.Info("splice helper ready", "listen", ln.Addr().String())
	return &Helper{cfg: cfg, log: log, sess: sess, ln: ln, live: map[net.Conn]struct{}{}}, nil
}

// Addr is the address daemons reach this helper at.
func (h *Helper) Addr() net.Addr { return h.ln.Addr() }

// Serve accepts local connections until ctx is cancelled, the listener is
// closed, or the carrier dies. A dead carrier ends the helper rather than
// leaving a listener that accepts connections it cannot carry.
func (h *Helper) Serve(ctx context.Context) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-h.sess.CloseChan():
			h.log.Warn("carrier closed; shutting down")
		case <-done:
			return
		}
		_ = h.ln.Close()
	}()

	for {
		c, err := h.ln.Accept()
		if err != nil {
			// Do not wait for the relays here: they are unblocked by Close,
			// which owns the shutdown. Serve only stops accepting.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if h.sess.IsClosed() {
				return errors.New("splice: the carrier to the outside broker closed")
			}
			return err
		}
		if !h.track(c) {
			_ = c.Close()
			continue
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer h.untrack(c)
			h.relay(c)
		}()
	}
}

// track registers a live connection, refusing once shutdown has begun so a
// connection accepted in the race cannot outlive Close.
func (h *Helper) track(c net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing {
		return false
	}
	h.live[c] = struct{}{}
	return true
}

func (h *Helper) untrack(c net.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.live, c)
}

// relay copies one local connection onto its own carrier stream. Nothing here
// looks at the bytes: the two real peers run their own end-to-end CEDAR
// session through this, and the helper never holds their keys.
func (h *Helper) relay(local net.Conn) {
	defer func() { _ = local.Close() }()
	raw, err := h.sess.OpenStream()
	if err != nil {
		h.log.Warn("cannot open a carrier stream", "remote", local.RemoteAddr(), "error", err)
		return
	}
	// carrier.WithHalfClose, not the bare stream: yamux has no CloseWrite, and
	// a relay that cannot half-close truncates bulk transfers while control
	// traffic survives.
	remote := carrier.WithHalfClose(raw)
	defer func() { _ = remote.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, local)
		// Half-close so the far side sees EOF on a one-way finish rather than
		// waiting for the whole connection to drop.
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, remote)
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// Close stops accepting, tears down the carrier, and closes every connection
// still being relayed, then waits for the relays to finish. It is safe to call
// more than once.
func (h *Helper) Close() error {
	var err error
	h.closeOnce.Do(func() {
		err = h.ln.Close()
		if cerr := h.sess.Close(); err == nil {
			err = cerr
		}
		h.mu.Lock()
		h.closing = true
		live := make([]net.Conn, 0, len(h.live))
		for c := range h.live {
			live = append(live, c)
		}
		h.mu.Unlock()
		// Closing the session stops the carrier side of each relay, but the
		// local side is a socket whose peer may hold it open indefinitely.
		for _, c := range live {
			_ = c.Close()
		}
		h.wg.Wait()
	})
	return err
}
