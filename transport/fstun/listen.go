package fstun

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
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
// aggressively (a cheap one-file stat) and reads only the small inbox on a
// change (plus a few follow-up scans to tolerate NFS surfacing the marker before
// the work subtree) or on the slow backstop. The (hashed, potentially large)
// work tree is listed only once, at startup.
func (l *Listener) watchLoop() {
	var db doorbellState
	l.startupScan()    // re-engage tunnels that predate this (re)start
	db.changed(l.root) // prime

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
			l.scanInbox() // cheap backstop; the inbox holds only un-engaged arrivals
		case <-fast.C:
			if db.changed(l.root) {
				rescans = doorbellRescans
			}
			if rescans > 0 {
				l.scanInbox()
				rescans--
			}
		}
	}
}

// scanInbox reads the small inbox of arrival markers and engages any new tunnel
// whose hashed work subtree is already visible, removing the marker once it does
// (the acceptor owns inbox cleanup). A marker whose work subtree is not yet
// visible -- NFS may surface the marker before the subtree -- is left for a later
// scan (the doorbell rescans and slow backstop retry it). It never prunes seen
// from a listing, so a transiently-stale view cannot cause a double-accept.
func (l *Listener) scanInbox() {
	inbox := filepath.Join(l.root, inboxDirName)
	entries, err := os.ReadDir(inbox)
	if err != nil {
		return // inbox not created yet
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		id := e.Name()
		l.mu.Lock()
		already := l.seen[id]
		l.mu.Unlock()
		if already {
			_ = os.Remove(filepath.Join(inbox, id)) // stale marker for a known tunnel
			continue
		}
		// Engage only once the initiator's SYN segment is visible.
		if _, err := os.Stat(filepath.Join(connPath(l.root, id), "c2s", segName(0))); err != nil {
			continue // work subtree not visible yet; retry on a later scan
		}
		l.mu.Lock()
		l.seen[id] = true
		l.mu.Unlock()
		_ = os.Remove(filepath.Join(inbox, id)) // picked up
		go l.accept(id)
	}
}

// startupScan walks the hashed work tree once to re-engage tunnels that were live
// before this acceptor (re)started -- the only time the work tree is listed.
func (l *Listener) startupScan() {
	fanouts, err := os.ReadDir(l.root)
	if err != nil {
		return
	}
	for _, fo := range fanouts {
		if !fo.IsDir() || fo.Name() == inboxDirName || strings.HasPrefix(fo.Name(), ".") {
			continue
		}
		rests, err := os.ReadDir(filepath.Join(l.root, fo.Name()))
		if err != nil {
			continue
		}
		for _, re := range rests {
			if !re.IsDir() {
				continue
			}
			id := fo.Name() + re.Name()
			if _, err := os.Stat(filepath.Join(connPath(l.root, id), "c2s", segName(0))); err != nil {
				continue
			}
			l.mu.Lock()
			if l.seen[id] {
				l.mu.Unlock()
				continue
			}
			l.seen[id] = true
			l.mu.Unlock()
			go l.accept(id)
		}
	}
}

func (l *Listener) accept(connID string) {
	c, err := handshake(l.ctx, l.rc, l.params, l.root, connID, roleAcceptor)
	if err != nil {
		// The initiator never completed the SYN handshake; it cleans up its own
		// subtree. Forget it so a later re-creation can be retried.
		l.forget(connID)
		return
	}
	// The acceptor owns the root, so it reaps the subtree once the tunnel is
	// terminal (Close, peer ERROR, or idle/heartbeat timeout).
	go l.reapWhenDone(connID, c)
	select {
	case l.accepted <- acceptResult{c: c}:
	case <-l.ctx.Done():
		_ = c.Close()
	}
}

// reapWhenDone removes a finished tunnel's subtree once the pipe is terminal. On
// listener shutdown it leaves the subtree in place (the tunnel may still be
// live); crash residue is the age-sweep's job.
func (l *Listener) reapWhenDone(connID string, c *Conn) {
	select {
	case <-c.Done():
	case <-l.ctx.Done():
		return
	}
	_ = os.RemoveAll(connPath(l.root, connID))
	_ = os.Remove(inboxMarkerPath(l.root, connID)) // in case a marker lingered
	l.forget(connID)
}

// forget drops a conn-id from the seen set so its subtree can be re-accepted if
// re-created.
func (l *Listener) forget(connID string) {
	l.mu.Lock()
	delete(l.seen, connID)
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
