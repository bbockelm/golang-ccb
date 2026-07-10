package ccbserver

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/bbockelm/cedar/ccb"
	cedarserver "github.com/bbockelm/cedar/server"
)

// handleGetTunnelAddress serves CCB_GET_TUNNEL_ADDRESS: a master (off-host CCB,
// Model 2) asks this inside CCB for its derived tunnel address (§4.5). Replies
// {Result:true, CCBAddress:<outside>#<inside_id>} once registered upstream, else
// {Result:false}. Authenticated at DAEMON.
func (s *Server) handleGetTunnelAddress(ctx context.Context, c *cedarserver.Conn) error {
	if err := s.authorize(c, ccb.CommandGetTunnelAddress); err != nil {
		s.log.Warn("get-tunnel-address denied", "remote", c.RemoteAddr, "error", err)
		_ = ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(map[string]any{
			ccb.AttrResult:      false,
			ccb.AttrErrorString: "authorization denied",
		}))
		return nil
	}
	// The request carries {Subsys} (debugging); read and ignore its contents.
	if _, err := ccb.ReadControlAd(ctx, c.Stream); err != nil {
		return err
	}
	tc := s.TunnelContact()
	if tc == "" {
		return ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(map[string]any{
			ccb.AttrResult:      false,
			ccb.AttrErrorString: "CCB has no tunnel address yet (not registered upstream)",
		}))
	}
	return ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(map[string]any{
		ccb.AttrResult:     true,
		ccb.AttrCCBAddress: tc,
	}))
}

// startUpstream registers this inside CCB with its upstream (outside) CCB and
// feeds the sockets that broker reverse-connects down into this server's own
// command loop -- so a client rendezvousing a local registrant through the
// upstream has its next-hop CCB_REQUEST processed here (recursive streaming
// proxy, §4.4). Once the registration yields a contact, it becomes this CCB's
// tunnel contact (the broker prefix for stamping local registrants).
func (s *Server) startUpstream(ctx context.Context) {
	up := s.cfg.Upstream
	// When the upstream link is a carrier (e.g. fs:<dir>), register and service
	// reverse-connects over the shared carrier pipe instead of TCP.
	var upDial ccb.BrokerDialer
	if s.carrier != nil && isCarrier(up.BrokerAddr) {
		upDial = s.carrier.dial
	}
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        up.BrokerAddr,
		Security:          up.Security,
		Name:              "ccb-inside " + s.cfg.PublicAddress,
		HeartbeatInterval: up.HeartbeatInterval,
		Dial:              upDial,
		Handler: func(conn net.Conn) {
			// A forwarded inbound rendezvous arrived: serve it as our own broker so
			// the next-hop CCB_REQUEST (for a local registrant) is dispatched here.
			_ = s.srv.ServeConn(ctx, conn)
		},
	})
	s.upstream = lis
	go func() { _ = lis.Run(ctx) }()
	go s.watchTunnelReady(ctx, lis)
}

// watchTunnelReady publishes the tunnel contact once the upstream registration
// assigns one, so contactString can stamp nested contacts and WaitTunnelReady
// unblocks.
func (s *Server) watchTunnelReady(ctx context.Context, lis *ccb.Listener) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if c := lis.Contact(); c != "" {
				cp := c
				s.tunnelContact.Store(&cp)
				s.writeReadyFile(c)
				s.tunnelReadyOnce.Do(func() { close(s.tunnelReady) })
				s.log.Info("inside CCB registered upstream", "tunnel_contact", c, "upstream", s.cfg.Upstream.BrokerAddr)
				return
			}
		}
	}
}

// writeReadyFile atomically writes the derived tunnel contact to the configured
// readiness file (Model 1 barrier), if any. Best-effort: a failure is logged, not
// fatal (the tunnel is up regardless; only the master's file-based wait is
// affected).
func (s *Server) writeReadyFile(contact string) {
	f := s.cfg.Upstream.ReadyFile
	if f == "" {
		return
	}
	tmp := f + ".tmp"
	if err := os.WriteFile(tmp, []byte(contact+"\n"), 0o644); err != nil {
		s.log.Warn("failed to write tunnel ready file", "file", f, "error", err)
		return
	}
	if err := os.Rename(tmp, f); err != nil {
		s.log.Warn("failed to install tunnel ready file", "file", f, "error", err)
		_ = os.Remove(tmp)
		return
	}
	s.log.Info("wrote tunnel ready file", "file", f, "tunnel_contact", contact)
}

// TunnelContact returns this inside CCB's own contact via its upstream
// ("<outside>#<id>"), or "" if not an inside CCB / not yet registered upstream.
func (s *Server) TunnelContact() string {
	if tc := s.tunnelContact.Load(); tc != nil {
		return *tc
	}
	return ""
}

// WaitTunnelReady blocks until this inside CCB has registered upstream (so its
// local registrants will receive nested contacts), or ctx is done. It returns
// immediately for a non-inside CCB. In production the master sequences startup on
// a readiness file; this is the in-process equivalent.
func (s *Server) WaitTunnelReady(ctx context.Context) error {
	if s.cfg.Upstream == nil {
		return nil
	}
	select {
	case <-s.tunnelReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
