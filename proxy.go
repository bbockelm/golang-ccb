package ccbserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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
		spliceConns(sess.requesterConn, targetConn)
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
func spliceConns(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	firstDone := make(chan struct{})
	var once sync.Once

	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// This direction is finished. Tell dst's peer, so it stops waiting for
		// more, without disturbing what is still arriving the other way.
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		once.Do(func() { close(firstDone) })
	}
	go pipe(c1, c2)
	go pipe(c2, c1)

	both := make(chan struct{})
	go func() { wg.Wait(); close(both) }()

	<-firstDone
	select {
	case <-both:
	case <-time.After(spliceDrainGrace):
	}
	_ = c1.Close()
	_ = c2.Close()
}
