package ccbserver

import (
	"context"
	"fmt"
	"time"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/ccb"
	cedarserver "github.com/bbockelm/cedar/server"
)

// handleRequest handles CCB_REQUEST. It looks up the target, decides between
// standard (direct reverse connect) and streaming/proxy mode, forwards the
// request, and relays the result to the requester.
func (s *Server) handleRequest(ctx context.Context, c *cedarserver.Conn) error {
	s.log.Info("CCB_REQUEST received", "remote", c.RemoteAddr)
	ad, err := ccb.ReadControlAd(ctx, c.Stream)
	if err != nil {
		s.log.Warn("request: reading ad failed", "remote", c.RemoteAddr, "error", err)
		return fmt.Errorf("request: reading ad: %w", err)
	}

	if err := s.authorize(c, ccb.CommandRequest); err != nil {
		s.log.Warn("request denied", "remote", c.RemoteAddr, "error", err)
		return s.replyFailure(ctx, c, "authorization denied")
	}

	targetContact := ccb.AdString(ad, ccb.AttrCCBID)
	connectID := ccb.AdString(ad, ccb.AttrClaimID)
	returnAddr := ccb.AdString(ad, ccb.AttrMyAddress)
	name := ccb.AdString(ad, ccb.AttrName)
	streamingRequired, _ := ccb.AdBool(ad, ccb.AttrCCBStreamingRequired)

	if connectID == "" || returnAddr == "" {
		return s.replyFailure(ctx, c, "request missing ClaimId or MyAddress")
	}

	targetID, ok := parseTargetID(targetContact)
	if !ok {
		return s.replyFailure(ctx, c, fmt.Sprintf("bad target CCBID %q", targetContact))
	}
	s.mu.Lock()
	t := s.targets[targetID]
	s.mu.Unlock()
	if t == nil {
		return s.replyFailure(ctx, c, fmt.Sprintf("no target registered for ccbid %d", targetID))
	}

	// Decide mode: the requester is private (and needs proxying) if it asked
	// for streaming, or if the return address is itself CCB-routed.
	returnInfo, _ := addresses.ParseSinful(returnAddr)
	if streamingRequired || returnInfo.IsCCB() {
		return s.handleProxyRequest(ctx, c, t, connectID, name)
	}
	return s.handleStandardRequest(ctx, c, t, connectID, returnAddr, name)
}

// handleStandardRequest forwards a direct reverse-connect request to the target
// and relays the target's result to the requester.
func (s *Server) handleStandardRequest(ctx context.Context, c *cedarserver.Conn, t *target, connectID, returnAddr, name string) error {
	s.mu.Lock()
	s.nextReq++
	reqID := s.nextReq
	req := &request{id: reqID, connectID: connectID, replyCh: make(chan replyResult, 1)}
	s.requests[reqID] = req
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.requests, reqID)
		s.mu.Unlock()
	}()

	fwd := ccb.NewAd(map[string]any{
		ccb.AttrCommand:   ccb.CommandRequest,
		ccb.AttrMyAddress: returnAddr,
		ccb.AttrClaimID:   connectID,
		ccb.AttrRequestID: fmt.Sprintf("%d", reqID),
		ccb.AttrName:      name,
	})
	if err := t.write(ctx, fwd); err != nil {
		return s.replyFailure(ctx, c, "failed to forward request to target")
	}
	s.log.Info("forwarded standard request", "ccbid", t.id, "request", reqID, "return", returnAddr)

	select {
	case res := <-req.replyCh:
		if res.success {
			return s.replySuccess(ctx, c, false)
		}
		return s.replyFailure(ctx, c, res.errMsg)
	case <-time.After(s.cfg.RequestTimeout):
		return s.replyFailure(ctx, c, "timed out waiting for target to connect")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) replySuccess(ctx context.Context, c *cedarserver.Conn, proxyMode bool) error {
	fields := map[string]any{ccb.AttrResult: true}
	if proxyMode {
		fields[ccb.AttrProxyMode] = true
	}
	return ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(fields))
}

func (s *Server) replyFailure(ctx context.Context, c *cedarserver.Conn, msg string) error {
	_ = ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(map[string]any{
		ccb.AttrResult:      false,
		ccb.AttrErrorString: msg,
	}))
	return fmt.Errorf("request failed: %s", msg)
}
