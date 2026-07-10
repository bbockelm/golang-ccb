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

const (
	// slowScanInterval is the guaranteed full-readdir backstop. Listing an NFS
	// directory is expensive, so we do it rarely and rely on the doorbell for
	// prompt arrival detection.
	slowScanInterval = 30 * time.Second
	// doorbellRescans is how many follow-up scans a single ring triggers, to
	// paper over an acceptor readdir that is briefly stale (NFS dir cache) and
	// omits the just-created subtree.
	doorbellRescans = 3
)

// doorbellInterval is how often the acceptor stats the single doorbell file: a
// cheap one-file GETATTR (subject to the NFS attribute cache), not a directory
// listing. Responsiveness therefore depends on the mount's attribute-cache
// timeouts (actimeo); the slow scan is the hard guarantee regardless.
func (l *Listener) doorbellInterval() time.Duration {
	if d := l.rc.pollInterval; d > 0 {
		return d
	}
	return 25 * time.Millisecond
}

// watchLoop learns of new initiators by watching a single doorbell file
// aggressively (cheap) and does a full directory scan only on a doorbell change
// (plus a few follow-up rescans to tolerate a stale NFS listing) or on the slow
// backstop timer.
func (l *Listener) watchLoop() {
	var db doorbellState
	l.scan() // engage any subtrees already present (e.g. after a restart)
	db.changed(l.root)

	fast := time.NewTicker(l.doorbellInterval())
	slow := time.NewTicker(slowScanInterval)
	defer fast.Stop()
	defer slow.Stop()

	rescans := 0
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-slow.C:
			l.scan()
		case <-fast.C:
			if db.changed(l.root) {
				rescans = doorbellRescans
			}
			if rescans > 0 {
				l.scan()
				rescans--
			}
		}
	}
}

// scan engages any subtree that has an initiator SYN segment and is not yet
// seen. It deliberately does NOT prune seen from the listing: a stale NFS readdir
// could transiently omit a live subtree and cause a double-accept. seen is
// forgotten authoritatively by forget() when a subtree is reaped or its
// handshake fails.
func (l *Listener) scan() {
	entries, err := os.ReadDir(l.root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
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
}

func (l *Listener) accept(connDir string) {
	c, err := handshake(l.ctx, l.rc, l.params, connDir, roleAcceptor)
	if err != nil {
		// The initiator never completed the SYN handshake; it cleans up its own
		// subtree. Forget it so a later re-creation can be retried.
		l.forget(connDir)
		return
	}
	// The acceptor owns the root, so it reaps the subtree once the tunnel is
	// terminal (Close, peer ERROR, or idle/heartbeat timeout).
	go l.reapWhenDone(connDir, c)
	select {
	case l.accepted <- acceptResult{c: c}:
	case <-l.ctx.Done():
		_ = c.Close()
	}
}

// reapWhenDone removes a finished tunnel's subtree once the pipe is terminal. On
// listener shutdown it leaves the subtree in place (the tunnel may still be
// live); crash residue is a future age-sweep's job.
func (l *Listener) reapWhenDone(connDir string, c *Conn) {
	select {
	case <-c.Done():
	case <-l.ctx.Done():
		return
	}
	_ = os.RemoveAll(connDir)
	l.forget(connDir)
}

// forget drops a conn-id from the seen set so its subtree can be re-accepted if
// re-created.
func (l *Listener) forget(connDir string) {
	l.mu.Lock()
	delete(l.seen, filepath.Base(connDir))
	l.mu.Unlock()
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
