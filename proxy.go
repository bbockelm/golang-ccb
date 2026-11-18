package ccbserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbockelm/cedar/ccb"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
)

// proxySession coordinates a streaming (private<->private) connection. The
// requester's request handler and the target's reverse-connect handler each
// supply one end; the broker then splices them.
type proxySession struct {
	connectID     string
	requestID     string
	requesterConn net.Conn
	targetCh      chan net.Conn // target reverse-connect delivers its conn here
	done          chan struct{} // closed when the splice has finished
}

// routeContext carries the recursive inbound tunnel routing + audit for a proxy
// request (mirrors the C++ CCBServer::CCBRouteContext). route is the space-separated
// remaining downstream CCBIDs after this hop's target; when non-empty the target is
// itself a downstream CCB and is asked to recurse. originalRequester/priorHop are the
// audit trail. (Whether to answer the requester -- the C++ reply_to_requester flag --
// is encoded here by proxyRelay's replyStream: non-nil on the client-facing hop, nil
// on an intermediate relay hop.)
type routeContext struct {
	route             string
	originalRequester string
	priorHop          string
}

// handleProxyRequest services a client-facing streaming-mode CCB_REQUEST: register a
// rendezvous keyed by connectID, ask the target to reverse-connect to the broker
// itself (forwarding rc so it recurses when there are more hops), reply, and splice.
func (s *Server) handleProxyRequest(ctx context.Context, c *cedarserver.Conn, t *target, connectID, name string, rc routeContext) error {
	return s.proxyRelay(ctx, c.Stream.GetConnection(), c.Stream, t, connectID, name, rc)
}

// proxyRelay is the shared core: set up a rendezvous with t, forward the route/audit
// so t recurses when rc.route is non-empty, and splice the requester to t. When
// replyStream != nil (the client-facing hop) it answers the requester before
// splicing; when nil (an intermediate relay hop) it only splices, because the outer
// broker already answered the client.
func (s *Server) proxyRelay(ctx context.Context, requesterConn net.Conn, replyStream *stream.Stream, t *target, connectID, name string, rc routeContext) error {
	s.mu.Lock()
	s.nextReq++
	reqID := fmt.Sprintf("%d", s.nextReq)
	sess := &proxySession{
		connectID:     connectID,
		requestID:     reqID,
		requesterConn: requesterConn,
		targetCh:      make(chan net.Conn, 1),
		done:          make(chan struct{}),
	}
	if _, exists := s.proxies[connectID]; exists {
		s.mu.Unlock()
		return s.proxyFail(ctx, replyStream, requesterConn, "duplicate connect id")
	}
	s.proxies[connectID] = sess
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.proxies, connectID)
		s.mu.Unlock()
	}()

	// Ask the target to reverse-connect to the broker's rendezvous address.
	fwd := ccb.NewAd(map[string]any{
		ccb.AttrCommand:   ccb.CommandRequest,
		ccb.AttrMyAddress: s.proxyAddrSinful(),
		ccb.AttrClaimID:   connectID,
		ccb.AttrRequestID: reqID,
		ccb.AttrName:      name,
	})
	// Recursive inbound tunnel: when there are more hops beyond this target, tell it
	// the remaining route so it recurses; carry the audit trail so it can log who the
	// connection is really for.
	if rc.route != "" {
		_ = fwd.Set(ccb.AttrCCBRoute, rc.route)
	}
	if rc.originalRequester != "" {
		_ = fwd.Set(ccb.AttrCCBOriginalRequester, rc.originalRequester)
	}
	if rc.priorHop != "" {
		_ = fwd.Set(ccb.AttrCCBPriorHop, rc.priorHop)
	}
	if err := t.write(ctx, fwd); err != nil {
		return s.proxyFail(ctx, replyStream, requesterConn, "failed to forward proxy request to target")
	}
	s.log.Info("forwarded proxy request", "ccbid", t.id, "request", reqID, "route", rc.route)

	select {
	case targetConn := <-sess.targetCh:
		if replyStream != nil {
			// Tell the requester the connection will be proxied on this socket, then
			// replay a reverse-connect hello (its accept logic validates
			// cmd==CCB_REVERSE_CONNECT && ClaimId==connectID).
			if err := ccb.WriteControlAd(ctx, replyStream, ccb.NewAd(map[string]any{
				ccb.AttrResult:    true,
				ccb.AttrProxyMode: true,
			})); err != nil {
				targetConn.Close()
				close(sess.done)
				return err
			}
			if err := ccb.WriteReverseConnect(ctx, replyStream, connectID, reqID, s.proxyAddrSinful()); err != nil {
				targetConn.Close()
				close(sess.done)
				return err
			}
		}
		// Splice raw bytes until either side closes.
		s.log.Info("proxy splice established", "ccbid", t.id, "request", reqID)
		st := spliceConns(sess.requesterConn, targetConn)
		args := append([]any{"ccbid", t.id, "request", reqID}, st.LogArgs()...)
		if st.OK() {
			s.log.Info("proxy splice closed", args...)
		} else {
			s.log.Warn("proxy splice failed", args...)
		}
		close(sess.done)
		return cedarserver.KeepOpen()
	case <-time.After(s.cfg.RequestTimeout):
		return s.proxyFail(ctx, replyStream, requesterConn, "timed out waiting for target to reverse-connect for proxy")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// proxyFail reports failure to a client-facing requester (replyStream != nil), or,
// on an intermediate relay hop, just closes the raw upstream pipe -- the outer broker
// sees the close and fails the client.
func (s *Server) proxyFail(ctx context.Context, replyStream *stream.Stream, requesterConn net.Conn, msg string) error {
	if replyStream != nil {
		_ = ccb.WriteControlAd(ctx, replyStream, ccb.NewAd(map[string]any{
			ccb.AttrResult:      false,
			ccb.AttrErrorString: msg,
		}))
	} else if requesterConn != nil {
		_ = requesterConn.Close()
	}
	return fmt.Errorf("proxy request failed: %s", msg)
}

// startInboundRelay is the intermediate-CCB entry point (mirrors the C++
// CCBServer::StartInboundRelay): this broker was asked -- over its upstream
// registration, so implicitly trusted -- to relay a tunneled connection whose
// remaining route is meta.Route. `upstream` is our just-established reverse
// connection to the requesting (outer) broker; set up the next hop toward the route
// head and splice it to `upstream`, forwarding the rest of the route so deeper hops
// recurse. It never replies (the outer broker already answered the client).
func (s *Server) startInboundRelay(ctx context.Context, upstream net.Conn, meta ccb.InboundMeta) {
	head, tail := splitRoute(meta.Route)
	targetID, ok := parseTargetID(head)
	if head == "" || !ok {
		s.log.Warn("inbound relay: bad or empty route", "route", meta.Route)
		_ = upstream.Close()
		return
	}
	s.mu.Lock()
	t := s.targets[targetID]
	s.mu.Unlock()
	if t == nil {
		s.log.Warn("inbound relay: no registrant for next-hop ccbid; dropping",
			"ccbid", targetID, "orig", meta.OriginalRequester)
		_ = upstream.Close()
		return
	}
	connectID, err := ccb.GenerateConnectID()
	if err != nil {
		_ = upstream.Close()
		return
	}
	s.log.Info("relaying inbound tunnel", "next", targetID, "route", tail,
		"orig", meta.OriginalRequester, "prior", meta.PriorHop)
	rc := routeContext{
		route:             tail,                   // hops beyond this target
		originalRequester: meta.OriginalRequester, // propagate unchanged
		priorHop:          s.proxyAddrSinful(),    // we are now the prior hop
	}
	// nil replyStream: a relay hop only splices (the outer broker answered the client).
	_ = s.proxyRelay(ctx, upstream, nil, t, connectID, "inbound-relay", rc)
}

// splitRoute splits a whitespace-separated route "id0 id1 ... idN" into head (id0)
// and tail ("id1 ... idN").
func splitRoute(route string) (head, tail string) {
	fields := strings.Fields(route)
	if len(fields) == 0 {
		return "", ""
	}
	return fields[0], strings.Join(fields[1:], " ")
}

// handleReverseConnect handles a raw CCB_REVERSE_CONNECT arriving from a target
// in proxy mode: match it to a pending proxy session and hand off the conn.
func (s *Server) handleReverseConnect(ctx context.Context, c *cedarserver.Conn) error {
	ad, err := ccb.ReadReverseConnectAd(ctx, c.Message, c.Command)
	if err != nil {
		return fmt.Errorf("reverse-connect: %w", err)
	}
	connectID := ccb.AdString(ad, ccb.AttrClaimID)

	s.mu.Lock()
	sess := s.proxies[connectID]
	s.mu.Unlock()
	if sess == nil {
		return fmt.Errorf("reverse-connect: no pending proxy session for connect id")
	}

	// Hand the target conn to the waiting request handler and wait until the
	// splice finishes before returning (so the conn is not closed early).
	select {
	case sess.targetCh <- c.Stream.GetConnection():
	default:
		return fmt.Errorf("reverse-connect: proxy session already satisfied")
	}
	select {
	case <-sess.done:
	case <-ctx.Done():
	}
	return cedarserver.KeepOpen()
}

// spliceDrainGrace bounds how long the relay waits for the second direction
// once the first has ended. It exists so a peer that stops reading without ever
// closing cannot hold a relay goroutine and two sockets open forever; it is
// generous, because the only thing it should ever cut short is a peer that has
// already gone away.
const spliceDrainGrace = 30 * time.Second

// closeWriter is a connection that can end its sending side while still
// receiving. *net.TCPConn and *tls.Conn implement it; a yamux stream's Close is
// itself a half-close, and anything else falls back to the grace above.
type closeWriter interface{ CloseWrite() error }

// spliceConns copies bytes bidirectionally between two connections until both
// directions are finished, then closes both.
//
// The two directions end independently, and an EOF on one says only that that
// peer has finished *sending*. It says nothing about bytes already in flight the
// other way, so tearing the whole relay down at that point -- which this did,
// closing both connections from whichever direction finished first -- discards
// them, and the far peer sees a truncated stream rather than a clean end.
//
// Each direction now propagates a half-close instead and leaves the other to
// drain. Note that this is about delivering what was already written; a relay
// cannot invent bytes a peer never sent, so a peer that closes without replying
// still produces an EOF at the far end, correctly.
// spliceStats describes how a relay ended.
//
// Without it a relay that carried a megabyte and one torn down after four bytes
// produce the same single log line, which makes a transport failure
// unfalsifiable from the broker's side -- and the broker is the only component
// that can see both ends. The byte counts are the valuable part: they separate
// "the relay worked and the application gave up" from "the relay stopped
// mid-stream", which no amount of client-side logging can do.
type spliceStats struct {
	// ToRequester and ToTarget count bytes written to each side. On a
	// truncated relay the still-running direction reports what it had written
	// so far, which on a kernel fast path is 0 until the copy completes --
	// read them together with Truncated.
	ToRequester int64
	ToTarget    int64
	Duration    time.Duration

	// Err is the first copy error, nil on a clean close, and Side names the
	// direction it happened in.
	Err  error
	Side string

	// Truncated reports that the drain grace expired with a direction still
	// copying, so the relay closed on bytes it had not finished delivering.
	Truncated bool

	// NoHalfClose reports that a transport could not propagate a half-close,
	// so the peer on that side was never told the sender had finished and sat
	// waiting for more. yamux streams are the case in practice: they have
	// Close but no CloseWrite, so a relay over a carrier reaches the drain
	// grace rather than ending when the data does. Naming it here turns an
	// otherwise mysterious 30-second stall into a one-line diagnosis.
	NoHalfClose bool
}

// OK reports a relay that ended cleanly: both directions reached EOF and
// neither was cut short. A peer closing without replying is ordinary and still
// OK -- a relay cannot invent bytes nobody sent.
func (s spliceStats) OK() bool { return s.Err == nil && !s.Truncated }

// Reason names what ended the relay, for an operator reading one log line.
func (s spliceStats) Reason() string {
	switch {
	case s.Err != nil:
		return s.Side + ": " + s.Err.Error()
	case s.Truncated && s.NoHalfClose:
		return "drain grace expired with " + s.Side + " still copying; the transport cannot half-close, so the peer was never told the sender had finished"
	case s.Truncated:
		return "drain grace expired with " + s.Side + " still copying"
	default:
		return "eof"
	}
}

// LogArgs renders the stats as slog key/value pairs.
func (s spliceStats) LogArgs() []any {
	return []any{
		"bytes_to_target", s.ToTarget,
		"bytes_to_requester", s.ToRequester,
		"duration", s.Duration.Round(time.Millisecond),
		"reason", s.Reason(),
	}
}

// otherSide names the direction opposite side. The two directions of a relay
// are labelled by where their bytes are going.
func otherSide(side string) string {
	switch side {
	case sideToTarget:
		return sideToRequester
	case sideToRequester:
		return sideToTarget
	default:
		return "a direction"
	}
}

// The two directions of a relay, labelled by where their bytes go.
const (
	sideToRequester = "to requester"
	sideToTarget    = "to target"
)

// countingConn counts the bytes written to a connection.
//
// It implements io.ReaderFrom so io.Copy still reaches the underlying
// connection's own ReadFrom -- on Linux a TCP-to-TCP relay uses splice(2)
// there, and quietly dropping to a userspace copy would be a real cost in a
// daemon whose whole job is moving bytes. The trade is that the fast path
// reports its count only when the copy finishes, where the per-Write path
// updates as it goes. That falls the right way round: the fast path exists
// only for plain TCP, and the carrier transports that have no fast path are
// exactly the ones where an in-flight count is worth having.
type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func (c countingConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		c.n.Add(n)
		return n, err
	}
	// No fast path underneath. This MUST do the copy itself: io.Copy calls
	// ReadFrom and returns whatever it gets, with no fallback, so an error
	// here would silently relay nothing -- which is every carrier relay, since
	// a yamux stream has no ReadFrom.
	//
	// writeOnly hides this type's own ReadFrom from io.Copy's probe, so the
	// copy below goes through Write (which counts) instead of recursing.
	return io.Copy(writeOnly{Writer: c}, r)
}

// writeOnly exposes nothing but Write, so io.Copy cannot find a ReadFrom on it.
type writeOnly struct{ io.Writer }

// spliceConns copies bytes bidirectionally between two connections until both
// directions are finished, then closes both. c1 is the requester and c2 the
// target, which is how the returned stats are labelled.
//
// The two directions end independently, and an EOF on one says only that that
// peer has finished *sending*. It says nothing about bytes already in flight the
// other way, so tearing the whole relay down at that point -- which this did,
// closing both connections from whichever direction finished first -- discards
// them, and the far peer sees a truncated stream rather than a clean end.
//
// Each direction now propagates a half-close instead and leaves the other to
// drain. Note that this is about delivering what was already written; a relay
// cannot invent bytes a peer never sent, so a peer that closes without replying
// still produces an EOF at the far end, correctly.
func spliceConns(c1, c2 net.Conn) spliceStats {
	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	firstDone := make(chan struct{})
	var once sync.Once

	var toRequester, toTarget atomic.Int64
	var errMu sync.Mutex
	var firstErr error
	var firstSide string
	var noHalfClose bool
	var finishedFirst string

	pipe := func(dst, src net.Conn, n *atomic.Int64, side string) {
		defer wg.Done()
		_, err := io.Copy(countingConn{Conn: dst, n: n}, src)
		if err != nil {
			errMu.Lock()
			if firstErr == nil {
				firstErr, firstSide = err, side
			}
			errMu.Unlock()
		}
		// This direction is finished. Tell dst's peer, so it stops waiting for
		// more, without disturbing what is still arriving the other way.
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			errMu.Lock()
			noHalfClose = true
			errMu.Unlock()
		}
		once.Do(func() {
			errMu.Lock()
			finishedFirst = side
			errMu.Unlock()
			close(firstDone)
		})
	}
	go pipe(c1, c2, &toRequester, sideToRequester)
	go pipe(c2, c1, &toTarget, sideToTarget)

	both := make(chan struct{})
	go func() { wg.Wait(); close(both) }()

	<-firstDone
	truncated := false
	select {
	case <-both:
	case <-time.After(spliceDrainGrace):
		truncated = true
	}
	_ = c1.Close()
	_ = c2.Close()

	errMu.Lock()
	err, side, half, first := firstErr, firstSide, noHalfClose, finishedFirst
	errMu.Unlock()
	if truncated && side == "" {
		// Name the direction that did NOT finish: it is the one still holding
		// bytes, and the opposite of whichever finished first. "a direction"
		// would send an operator looking at both.
		side = otherSide(first)
	}
	return spliceStats{
		ToRequester: toRequester.Load(),
		ToTarget:    toTarget.Load(),
		Duration:    time.Since(start),
		Err:         err,
		Side:        side,
		Truncated:   truncated,
		NoHalfClose: half,
	}
}
