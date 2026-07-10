package fstun

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Listener is the acceptor (outside CCB) side: it owns cfg.Root and yields one
// Conn per initiator that creates a subtree beneath it. It implements
// net.Listener, so the cedar command server can Serve on it directly.
type Listener struct {
	cfg    Config
	rc     resolvedConfig
	params synParams
	root   string

	accepted chan acceptResult
	ctx      context.Context
	cancel   context.CancelFunc

	mu   sync.Mutex
	seen map[string]bool // conn-ids we have begun accepting

	closeOnce sync.Once
}

type acceptResult struct {
	c   net.Conn
	err error
}

// Listen creates cfg.Root (if needed) and begins watching it for initiators.
func Listen(cfg Config) (*Listener, error) {
	rc, params, err := cfg.resolve()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Root, 0o700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		cfg:      cfg,
		rc:       rc,
		params:   params,
		root:     cfg.Root,
		accepted: make(chan acceptResult),
		ctx:      ctx,
		cancel:   cancel,
		seen:     make(map[string]bool),
	}
	go l.watchLoop()
	return l, nil
}

// scanInterval is how often the acceptor rescans the root for new subtrees. The
// SYN handshake tolerates a late-arriving peer, so this need not be as tight as
// the data-path poll.
func (l *Listener) scanInterval() time.Duration {
	if d := l.rc.pollInterval; d > 100*time.Millisecond {
		return d
	}
	return 100 * time.Millisecond
}

func (l *Listener) watchLoop() {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-t.C:
			l.scan()
			t.Reset(l.scanInterval())
		}
	}
}

// scan starts accepting any subtree that has an initiator SYN segment and is not
// yet seen, and forgets subtrees that have gone away (so seen does not grow
// without bound over a long-lived acceptor).
func (l *Listener) scan() {
	entries, err := os.ReadDir(l.root)
	if err != nil {
		return
	}
	live := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		live[id] = struct{}{}
		// An initiator writes its SYN into c2s/000000.seg before we should engage.
		if _, err := os.Stat(filepath.Join(l.root, id, "c2s", segName(0))); err != nil {
			continue
		}
		l.mu.Lock()
		if l.seen[id] {
			l.mu.Unlock()
			continue
		}
		l.seen[id] = true
		l.mu.Unlock()
		go l.accept(filepath.Join(l.root, id))
	}
	l.mu.Lock()
	for id := range l.seen {
		if _, ok := live[id]; !ok {
			delete(l.seen, id)
		}
	}
	l.mu.Unlock()
}

func (l *Listener) accept(connDir string) {
	c, err := handshake(l.ctx, l.rc, l.params, connDir, roleAcceptor)
	if err != nil {
		// A single initiator that never completed the SYN handshake must not kill
		// the accept loop; drop it. (The initiator's Dial has failed too.) Forget
		// it so a later re-creation of the subtree can be retried.
		l.mu.Lock()
		delete(l.seen, filepath.Base(connDir))
		l.mu.Unlock()
		return
	}
	select {
	case l.accepted <- acceptResult{c: c}:
	case <-l.ctx.Done():
		_ = c.Close()
	}
}

// Accept returns the next established pipe. It blocks until one is ready.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case r := <-l.accepted:
		return r.c, r.err
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() { l.cancel() })
	return nil
}

func (l *Listener) Addr() net.Addr { return fstunAddr{dir: l.root} }
