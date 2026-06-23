package ccbserver

import (
	"context"
	"log/slog"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
)

// sessionPersistence bridges the global CEDAR session cache and a SessionStore:
// it restores persisted sessions into the cache at startup and periodically
// snapshots the cache back to the store, so resumable sessions survive a broker
// restart. Inherited (family) and expired sessions are never persisted.
type sessionPersistence struct {
	store    SessionStore
	cache    *security.SessionCache
	log      *slog.Logger
	interval time.Duration
}

func newSessionPersistence(store SessionStore, log *slog.Logger, interval time.Duration) *sessionPersistence {
	if log == nil {
		log = slog.Default()
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &sessionPersistence{
		store:    store,
		cache:    security.GetSessionCache(),
		log:      log,
		interval: interval,
	}
}

// restore loads persisted sessions into the cache. Records that fail to convert
// are skipped (logged), so one bad record cannot block startup.
func (p *sessionPersistence) restore(ctx context.Context) error {
	recs, err := p.store.Load(ctx)
	if err != nil {
		return err
	}
	restored := 0
	for _, r := range recs {
		entry, err := recordToEntry(r)
		if err != nil {
			p.log.Warn("ccb session cache: skipping unrestorable record", "id", r.ID, "error", err)
			continue
		}
		p.cache.Store(entry)
		restored++
	}
	if restored > 0 {
		p.log.Info("ccb session cache restored", "count", restored)
	}
	return nil
}

// snapshot persists the current cache contents (minus inherited/expired).
func (p *sessionPersistence) snapshot(ctx context.Context) error {
	var recs []SessionRecord
	for _, e := range p.cache.Snapshot() {
		if e.IsInherited() || e.IsExpired() {
			continue
		}
		recs = append(recs, entryToRecord(e))
	}
	return p.store.Save(ctx, recs)
}

// run snapshots periodically until ctx is cancelled. It does not close the
// store; the final shutdown snapshot and Close are handled by the server (see
// Server.Serve / finalSnapshot) so they complete deterministically before exit.
func (p *sessionPersistence) run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.snapshot(ctx); err != nil {
				p.log.Warn("ccb session cache: snapshot failed", "error", err)
			}
		}
	}
}

// finalSnapshot takes a last, bounded snapshot during shutdown.
func (p *sessionPersistence) finalSnapshot() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.snapshot(ctx); err != nil {
		p.log.Warn("ccb session cache: final snapshot failed", "error", err)
	}
}

// entryToRecord converts a cache entry into its persistable form.
func entryToRecord(e *security.SessionEntry) SessionRecord {
	rec := SessionRecord{
		ID:          e.ID(),
		Addr:        e.Addr(),
		Expiration:  e.Expiration(),
		LeaseSecs:   int64(e.Lease().Seconds()),
		Tag:         e.Tag(),
		PeerVersion: e.LastPeerVersion(),
	}
	if ki := e.KeyInfo(); ki != nil {
		rec.KeyData = ki.Data
		rec.KeyProtocol = ki.Protocol
	}
	if pol := e.Policy(); pol != nil {
		rec.PolicyText = pol.String()
	}
	return rec
}

// recordToEntry reconstructs a cache entry from a persisted record.
func recordToEntry(r SessionRecord) (*security.SessionEntry, error) {
	var keyInfo *security.KeyInfo
	if len(r.KeyData) > 0 {
		keyInfo = &security.KeyInfo{Data: r.KeyData, Protocol: r.KeyProtocol}
	}
	var policy *classad.ClassAd
	if r.PolicyText != "" {
		pol, err := classad.Parse(r.PolicyText)
		if err != nil {
			return nil, err
		}
		policy = pol
	}
	entry := security.NewSessionEntry(
		r.ID, r.Addr, keyInfo, policy, r.Expiration,
		time.Duration(r.LeaseSecs)*time.Second, r.Tag,
	)
	if r.PeerVersion != "" {
		entry.SetLastPeerVersion(r.PeerVersion)
	}
	return entry, nil
}
