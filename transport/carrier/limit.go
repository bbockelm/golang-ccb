package carrier

import (
	"log/slog"
	"net"
	"sync"
)

// DefaultMaxSessions caps concurrently-held carrier pipes on a listener that
// does not set its own. One pipe per inside broker, so this is a node count.
const DefaultMaxSessions = 1024

// LimitListener bounds how many pipes a carrier listener holds at once, and
// optionally how many come from one peer address.
//
// The accept path needs this wherever the carrier itself does not authenticate
// the peer -- a raw TCP carrier, a WebSocket carrier in CCB_CARRIER_AUTH = none
// mode -- because the identity check then happens one layer up, at the CEDAR
// handshake, and anything that never gets that far would otherwise be free to
// park pipes on the broker. MuxListener's first-stream probation covers the
// pipe that opens no stream; this covers their number.
type LimitListener struct {
	inner        net.Listener
	log          *slog.Logger
	maxSessions  int
	maxPerSource int

	mu        sync.Mutex
	sessions  int
	perSource map[string]int
}

// NewLimitListener wraps inner. maxSessions <= 0 uses DefaultMaxSessions;
// maxPerSource <= 0 disables the per-source cap, which is right wherever many
// nodes legitimately share one address (everything behind one NAT or proxy).
func NewLimitListener(inner net.Listener, log *slog.Logger, maxSessions, maxPerSource int) *LimitListener {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	return &LimitListener{
		inner:        inner,
		log:          log,
		maxSessions:  maxSessions,
		maxPerSource: maxPerSource,
		perSource:    make(map[string]int),
	}
}

func (l *LimitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		source := sourceKey(c.RemoteAddr())
		if l.admit(source) {
			return &limitedConn{Conn: c, release: func() { l.release(source) }}, nil
		}
		l.log.Warn("refusing carrier pipe: accept limit reached",
			"source", source, "max_sessions", l.maxSessions, "max_per_source", l.maxPerSource)
		_ = c.Close()
	}
}

func (l *LimitListener) admit(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sessions >= l.maxSessions {
		return false
	}
	if l.maxPerSource > 0 && l.perSource[source] >= l.maxPerSource {
		return false
	}
	l.sessions++
	l.perSource[source]++
	return true
}

func (l *LimitListener) release(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sessions--
	if n := l.perSource[source] - 1; n > 0 {
		l.perSource[source] = n
	} else {
		delete(l.perSource, source)
	}
}

// Sessions reports how many pipes are currently held, for tests and metrics.
func (l *LimitListener) Sessions() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessions
}

func (l *LimitListener) Close() error   { return l.inner.Close() }
func (l *LimitListener) Addr() net.Addr { return l.inner.Addr() }

// sourceKey is the peer's host without its port, so a node reconnecting from a
// fresh ephemeral port still counts against the same source.
func sourceKey(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

type limitedConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (c *limitedConn) Close() error {
	c.releaseOnce.Do(c.release)
	return c.Conn.Close()
}

var _ net.Listener = (*LimitListener)(nil)
