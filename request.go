package ccbserver

import (
	"context"
	"fmt"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/ccb"
	cedarserver "github.com/htcondor/cedar/server"
)

// handleRequest handles CCB_REQUEST. It looks up the target, decides between
// standard (direct reverse connect) and streaming/proxy mode, forwards the
// request, and relays the result to the requester.
// requesterIdentity renders an audit string for the peer that opened this request:
// the identity it is authorized as (its full user@domain, or
// unauthenticated@unmapped) at its network address. Inner tunnel hops forward
// this unchanged so every broker can log who the connection is really for.
func requesterIdentity(c *cedarserver.Conn) string {
	return c.AuthorizationUser() + " at " + c.RemoteAddr
}

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
	if err := s.limits.take(ctx, kindRequest, s.maxWait(), s.limits.endpointOf(c.Stream.GetConnection())); err != nil {
		return s.replyFailure(ctx, c, err.Error())
	}

	targetContact := ccb.AdString(ad, ccb.AttrCCBID)
	connectID := ccb.AdString(ad, ccb.AttrClaimID)
	returnAddr := ccb.AdString(ad, ccb.AttrMyAddress)
	name := ccb.AdString(ad, ccb.AttrName)
	streamingRequired, _ := ccb.AdBool(ad, ccb.AttrCCBStreamingRequired)
	// Recursive inbound tunnel: a non-empty route names the downstream CCBIDs to
	// pop after this hop's target, meaning the target is itself a downstream CCB
	// that must recurse. Such a request is inherently proxied/streamed.
	route := ccb.AdString(ad, ccb.AttrCCBRoute)

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
		// The id may name a CARRIER rather than a target: a carrier-attached
		// target advertises "<public>#P#T", so the client sends ccbid=P with
		// the real target at the head of the route. Both ids are ours, so
		// there is no hop to forward -- collapse it here.
		if ct, rest, ok := s.resolveCarrierHop(targetID, route); ok {
			s.log.Info("collapsed carrier hop", "carrier", targetID, "ccbid", ct.id, "route", rest)
			t, route = ct, rest
		} else {
			return s.replyFailure(ctx, c, fmt.Sprintf("no target registered for ccbid %d", targetID))
		}
	}

	// Decide mode: the requester is private (and needs proxying) if it asked
	// for streaming, if the return address is itself CCB-routed, or if there is a
	// downstream route to follow (a tunnel).
	returnInfo, _ := addresses.ParseSinful(returnAddr)
	// A carrier-attached target can never serve a standard request: standard
	// mode tells it to connect to the REQUESTER, which is further away than the
	// broker it reached us through. Such a target is always proxied.
	if streamingRequired || returnInfo.IsCCB() || route != "" || t.carrierID != 0 {
		rc := routeContext{
			route: route,
			// This is the client-facing (entry) broker: stamp the audit trail from
			// the authenticated requester so inner hops can log who the connection is
			// really for. Inner relay hops propagate these unchanged.
			originalRequester: requesterIdentity(c),
			priorHop:          s.proxyAddrSinful(),
		}
		return s.handleProxyRequest(ctx, c, t, connectID, name, rc)
	}
	return s.handleStandardRequest(ctx, c, t, connectID, returnAddr, name)
}

// handleStandardRequest forwards a direct reverse-connect request to the target
// and relays the target's result to the requester.
func (s *Server) handleStandardRequest(ctx context.Context, c *cedarserver.Conn, t *target, connectID, returnAddr, name string) error {
	endTarget, err := s.beginTargetRequest(ctx, t)
	if err != nil {
		return s.replyFailure(ctx, c, err.Error())
	}
	defer endTarget()

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
