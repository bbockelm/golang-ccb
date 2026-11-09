package ccbserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"

	"github.com/bbockelm/golang-ccb/transport/wscarrier"
)

// StageFarBroker is the end-to-end stage layered on top of the transport probe:
// a CEDAR handshake to the broker at the far end of the carrier. The transport
// stages prove bytes can cross the site's network policy; this one proves the
// thing on the other side is the expected broker and that the two agree on
// credentials -- the second large class of deployment failure, and one no amount
// of WebSocket success says anything about.
const StageFarBroker wscarrier.Stage = "far-broker-cedar"

// CheckCarrier reports whether this (inside) CCB can reach its outside CCB,
// stage by stage, before any CCB machinery depends on it. It is cheap, read-only
// and safe to run at startup: it opens connections, completes a handshake, and
// closes them.
//
// The stages are ordered so the first failure names the problem: a node that
// cannot reach the proxy, a proxy that will not tunnel to this destination, an
// intercepted TLS session, a rejected token, and a far end that is not the
// broker we think it is all look identical from a bare "dial failed".
func (s *Server) CheckCarrier(ctx context.Context) wscarrier.ProbeResult {
	if s.carrier == nil {
		return wscarrier.ProbeResult{URL: "(none)", Route: "no carrier configured"}
	}
	var res wscarrier.ProbeResult
	if s.carrier.ref.scheme == "ws" {
		res = wscarrier.Probe(ctx, s.carrier.wsDialConfig())
		if !res.OK() {
			// A failed transport stage already names the cause; opening a logical
			// connection on top of it would only add a confusing second error.
			return res
		}
	} else {
		// Other carriers (the filesystem tunnel) have no network stages to walk;
		// the end-to-end check below still applies and is the useful part.
		res = wscarrier.ProbeResult{URL: s.carrier.describe(), Route: "not a WebSocket carrier"}
	}
	res.Append(s.checkFarBroker(ctx))
	return res
}

// checkFarBroker opens one logical connection over the carrier and runs a CEDAR
// security handshake against whatever answers.
func (s *Server) checkFarBroker(ctx context.Context) wscarrier.StageResult {
	st := wscarrier.StageResult{Stage: StageFarBroker}
	sec := s.carrierPeerSecurity()
	if sec == nil {
		st.Skipped = true
		st.Detail = "no client security is configured for the far broker"
		return st
	}

	start := time.Now()
	conn, err := s.carrier.dial(ctx, "")
	if err != nil {
		st.Elapsed = time.Since(start)
		st.Err = err
		st.Advice = "the carrier pipe is up but no logical connection could be multiplexed over it; the far end may not be serving a CCB on this carrier"
		return st
	}
	defer func() { _ = conn.Close() }()

	// DC_NOP: the far broker completes the handshake and then has no handler for
	// it, so the connection closes with nothing done. The handshake is the whole
	// point -- it is what proves identity and credentials line up.
	cfg := *sec
	cfg.Command = commands.DC_NOP
	stm := stream.NewStream(conn)
	stm.SetPeerAddr(s.carrier.describe())
	neg, err := security.NewAuthenticator(&cfg, stm).ClientHandshake(ctx)
	st.Elapsed = time.Since(start)

	var authz *security.AuthorizationError
	switch {
	case err == nil:
		st.Detail = describeNegotiation(neg)
	case errors.As(err, &authz) && (authz.ReturnCode == "CMD_NOT_FOUND" || errors.Is(err, security.ErrCommandNotFound)):
		// The handshake completed and the peer told us who it thinks we are --
		// everything this stage exists to check. It simply has no DC_NOP handler,
		// which a broker is not obliged to have. Treating this as a failure would
		// report a healthy tunnel as broken.
		st.Detail = describeIdentity(authz) + " (the peer has no DC_NOP handler, which is fine)"
	case errors.As(err, &authz):
		// Authenticated, then refused: a different half of the configuration
		// entirely, and saying "handshake failed" would send an operator to the
		// wrong one.
		st.Err = err
		st.Advice = "the far broker authenticated us and then refused the command; that is its ALLOW_*/DENY_* policy for the command's authorization level, not a credential problem"
	default:
		st.Err = err
		st.Advice = "the far end answered but the CEDAR handshake failed; check that both brokers share a pool signing key / trust domain and agree on SEC_* policy"
	}
	return st
}

// describeNegotiation summarizes who answered and how, for the report.
func describeNegotiation(neg *security.SecurityNegotiation) string {
	if neg == nil {
		return "handshake completed"
	}
	who := neg.User
	if who == "" {
		who = "an unauthenticated peer"
	}
	detail := fmt.Sprintf("handshake completed with %s", who)
	if neg.NegotiatedAuth != "" {
		detail += fmt.Sprintf(" (auth %s", neg.NegotiatedAuth)
		if neg.Encryption {
			detail += ", encrypted"
		}
		detail += ")"
	}
	return detail
}

// describeIdentity summarizes the identity the peer reported while refusing a
// command, which is the same information a successful handshake would have given.
func describeIdentity(authz *security.AuthorizationError) string {
	who := authz.User
	if who == "" {
		who = "an unauthenticated peer"
	}
	detail := fmt.Sprintf("handshake completed with %s", who)
	if authz.Method != "" {
		detail += fmt.Sprintf(" (auth %s", authz.Method)
		if authz.Encrypted {
			detail += ", encrypted"
		}
		detail += ")"
	}
	return detail
}

// carrierPeerSecurity is the client-side security policy this broker uses toward
// the far end of the carrier: the upstream registration's, else the outbound
// next hop's. Both name the same broker when a carrier is in play.
func (s *Server) carrierPeerSecurity() *security.SecurityConfig {
	if s.cfg.Upstream != nil && s.cfg.Upstream.Security != nil {
		return s.cfg.Upstream.Security
	}
	return s.cfg.OutboundNextHopSecurity
}

// HasCarrier reports whether this broker dials a carrier to reach its outside
// CCB, i.e. whether CheckCarrier has anything to check.
func (s *Server) HasCarrier() bool { return s.carrier != nil }
