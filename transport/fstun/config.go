package fstun

import (
	"fmt"
	"time"
)

// Config parameters an fstun endpoint. Only Root is required; the rest have
// sensible defaults (see docs/TRANSPORTS.md §4). Segment size, window, and max
// frame are each a *sender's* own choice for its own direction -- the reader is
// agnostic -- so the two endpoints need not agree on them; they are exchanged in
// the SYN for diagnostics and future use.
type Config struct {
	// Root is the shared directory. The acceptor owns it; each initiator creates
	// one <conn-id>/ subtree beneath it per pipe.
	Root string

	// SegmentSize is the byte size at which this side rolls to a new segment file
	// in its send direction (default 128 MiB).
	SegmentSize int64

	// Window is the max outstanding unacked DATA bytes before Write blocks
	// (backpressure); it bounds this side's on-disk backlog (default 8 MiB).
	Window int64

	// MaxFrame is the max DATA payload per frame (default 256 KiB, capped at 1 MiB).
	MaxFrame int

	// PollInterval is how often the reader re-checks for newly-visible bytes when
	// idle (default 25 ms). Correctness never depends on it (NFS has no reliable
	// change notification); it only trades latency for syscall load.
	PollInterval time.Duration

	// Heartbeat is how often to emit a HEARTBEAT (also carrying a catch-up ACK)
	// (default 5 s).
	Heartbeat time.Duration

	// IdleTimeout fails the pipe if no frame is observed from the peer within this
	// window (default 60 s). Must exceed the peer's Heartbeat.
	IdleTimeout time.Duration

	// HandshakeTimeout bounds waiting for the peer's SYN (default 30 s).
	HandshakeTimeout time.Duration

	// Sync fsyncs after each append. Safer across a crash, slower. Default off:
	// the reader already tolerates torn tails, and the FS is assumed to make
	// appends eventually visible.
	Sync bool

	// AgeSweepInterval is how often the acceptor sweeps the root for crash
	// residue -- orphaned inbox markers and stale work subtrees that normal GC
	// (engage + idle-reap, initiator cleanup) does not cover (default 10m).
	// Negative disables the sweep. This is the only routine operation that walks
	// the work tree, so it is deliberately infrequent.
	AgeSweepInterval time.Duration

	// AgeSweepThreshold is the minimum age (since last activity) before the sweep
	// reaps an un-engaged subtree or an un-picked-up marker (default 15m). Must
	// comfortably exceed the time a live tunnel can look idle to the sweep so an
	// in-flight or briefly-quiet tunnel is never reaped.
	AgeSweepThreshold time.Duration
}

// resolvedConfig is Config with defaults applied and split into the fields the
// runtime actually consults.
type resolvedConfig struct {
	pollInterval      time.Duration
	heartbeat         time.Duration
	idleTimeout       time.Duration
	handshakeTimeout  time.Duration
	segmentSize       int64
	sync              bool
	ageSweepInterval  time.Duration // <= 0 disables the sweep
	ageSweepThreshold time.Duration
}

func (cfg Config) resolve() (resolvedConfig, synParams, error) {
	if cfg.Root == "" {
		return resolvedConfig{}, synParams{}, fmt.Errorf("fstun: Config.Root is required")
	}
	def := func(d, dflt time.Duration) time.Duration {
		if d <= 0 {
			return dflt
		}
		return d
	}
	seg := cfg.SegmentSize
	if seg <= 0 {
		seg = 128 << 20
	}
	win := cfg.Window
	if win <= 0 {
		win = 8 << 20
	}
	mf := cfg.MaxFrame
	if mf <= 0 {
		mf = 256 << 10
	}
	if mf > maxPayload {
		mf = maxPayload
	}
	ageInt := cfg.AgeSweepInterval
	switch {
	case ageInt == 0:
		ageInt = 10 * time.Minute
	case ageInt < 0:
		ageInt = 0 // disabled
	}
	rc := resolvedConfig{
		pollInterval:      def(cfg.PollInterval, 25*time.Millisecond),
		heartbeat:         def(cfg.Heartbeat, 5*time.Second),
		idleTimeout:       def(cfg.IdleTimeout, 60*time.Second),
		handshakeTimeout:  def(cfg.HandshakeTimeout, 30*time.Second),
		segmentSize:       seg,
		sync:              cfg.Sync,
		ageSweepInterval:  ageInt,
		ageSweepThreshold: def(cfg.AgeSweepThreshold, 15*time.Minute),
	}
	params := synParams{
		version:     protocolVersion,
		segmentSize: uint64(seg),
		window:      uint64(win),
		maxFrame:    uint32(mf),
	}
	return rc, params, nil
}
