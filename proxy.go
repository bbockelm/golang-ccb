package ccbserver

import (
	"context"
	"fmt"
	"io"
	"net"
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
	connectID       string
	requestID       string
	requesterStream *stream.Stream
	requesterConn   net.Conn
	targetCh        chan net.Conn // target reverse-connect delivers its conn here
	done            chan struct{} // closed when the splice has finished
}

// handleProxyRequest services a streaming-mode CCB_REQUEST: register a
// rendezvous keyed by connectID, ask the target to reverse-connect to the
// broker itself, then splice the two sockets.
func (s *Server) handleProxyRequest(ctx context.Context, c *cedarserver.Conn, t *target, connectID, name string) error {
	s.mu.Lock()
	s.nextReq++
	reqID := fmt.Sprintf("%d", s.nextReq)
	sess := &proxySession{
		connectID:       connectID,
		requestID:       reqID,
		requesterStream: c.Stream,
		requesterConn:   c.Stream.GetConnection(),
		targetCh:        make(chan net.Conn, 1),
		done:            make(chan struct{}),
	}
	if _, exists := s.proxies[connectID]; exists {
		s.mu.Unlock()
		return s.replyFailure(ctx, c, "duplicate connect id")
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
	if err := t.write(ctx, fwd); err != nil {
		return s.replyFailure(ctx, c, "failed to forward proxy request to target")
	}
	s.log.Info("forwarded proxy request", "ccbid", t.id, "request", reqID)

	select {
	case targetConn := <-sess.targetCh:
		// Tell the requester the connection will be proxied on this socket.
		if err := s.replySuccess(ctx, c, true); err != nil {
			targetConn.Close()
			close(sess.done)
			return err
		}
		// Replay a reverse-connect hello to the requester so its accept logic
		// (which validates cmd==CCB_REVERSE_CONNECT && ClaimId==connectID)
		// is satisfied. The target's own hello was consumed by the broker.
		if err := ccb.WriteReverseConnect(ctx, c.Stream, connectID, reqID, s.proxyAddrSinful()); err != nil {
			targetConn.Close()
			close(sess.done)
			return err
		}
		// Splice raw bytes until either side closes.
		s.log.Info("proxy splice established", "ccbid", t.id, "request", reqID)
		spliceConns(sess.requesterConn, targetConn)
		close(sess.done)
		return cedarserver.KeepOpen()
	case <-time.After(s.cfg.RequestTimeout):
		return s.replyFailure(ctx, c, "timed out waiting for target to reverse-connect for proxy")
	case <-ctx.Done():
		return ctx.Err()
	}
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

// spliceConns copies bytes bidirectionally between two connections until either
// side closes, then closes both.
func spliceConns(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
		_ = src.Close()
	}
	go pipe(c1, c2)
	go pipe(c2, c1)
	wg.Wait()
}
