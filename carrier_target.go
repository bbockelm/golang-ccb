package ccbserver

import (
	"context"
	"net"
	"strconv"
	"sync"
)

// A carrier-attached target is one that reached this broker through a splice
// helper: a byte relay on the far side of a carrier, which terminates nothing
// and registers nothing. See docs/SPLICE_HELPER.md.
//
// Such a target cannot be reached in standard mode -- it would be told to dial
// the requester, which is further away than the broker it already cannot reach
// -- so a client has to choose the streaming path before it sends its request.
// The client chooses that path from the SHAPE OF THE CONTACT: dialOne takes the
// recursive route when the contact's broker is itself CCB-routed. So the
// contact for a carrier-attached target nests one level, "<public>#P#T", where
// P names the carrier and T the target.
//
// Unlike a nested contact today, both ids belong to THIS broker. There is no
// peer broker behind P to forward to, so the hop is collapsed here instead:
// resolveCarrierHop turns a request for (P, route "T ...") into an ordinary
// single-hop proxy request for T. P exists only to make the contact nest, which
// is what tells the client to stream.

// carrierConn tags a connection with the carrier it arrived on.
type carrierConn struct {
	net.Conn
	carrierID uint64
}

// carrierListener tags every connection it accepts. One listener is one carrier
// -- in production the yamux listener over a single pipe.
type carrierListener struct {
	net.Listener
	carrierID uint64
}

func (l *carrierListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &carrierConn{Conn: c, carrierID: l.carrierID}, nil
}

// carrierOf reports the carrier a connection arrived on, if any.
func carrierOf(c net.Conn) (uint64, bool) {
	cc, ok := c.(*carrierConn)
	if !ok {
		return 0, false
	}
	return cc.carrierID, true
}

// carriers tracks the live carrier ids so a request naming one can be told
// apart from a request naming a target.
type carrierSet struct {
	mu  sync.Mutex
	ids map[uint64]struct{}
}

func (s *carrierSet) add(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ids == nil {
		s.ids = make(map[uint64]struct{})
	}
	s.ids[id] = struct{}{}
}

func (s *carrierSet) remove(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ids, id)
}

func (s *carrierSet) has(id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ids[id]
	return ok
}

// ServeCarrier serves CCB on a carrier's listener: every connection accepted
// from l belongs to one carrier, and targets registering over it advertise a
// contact that nests through this broker's id for that carrier.
//
// l is the far end of one pipe. In production that is the yamux listener over
// the carrier; the helper on the other side relays bytes and nothing else.
func (s *Server) ServeCarrier(ctx context.Context, l net.Listener) error {
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	s.mu.Unlock()
	s.carriers.add(id)
	defer s.carriers.remove(id)
	s.log.Info("carrier attached", "carrier", id, "listen", l.Addr().String())
	s.StartBackground(ctx)
	return s.srv.Serve(ctx, &carrierListener{Listener: l, carrierID: id})
}

// carrierContactString builds the nested contact for a target behind a carrier.
func (s *Server) carrierContactString(carrierID, id uint64) string {
	return s.contactString(carrierID) + "#" + strconv.FormatUint(id, 10)
}

// resolveCarrierHop collapses a request that names a carrier rather than a
// target. The route's head is the real target, which must be one registered
// over that same carrier -- otherwise a client could use any carrier id as a
// prefix to reach any target, which is the sort of thing that is only ever
// noticed later.
func (s *Server) resolveCarrierHop(carrierID uint64, route string) (*target, string, bool) {
	if !s.carriers.has(carrierID) {
		return nil, "", false
	}
	head, tail := splitRoute(route)
	id, ok := parseTargetID(head)
	if !ok {
		return nil, "", false
	}
	s.mu.Lock()
	t := s.targets[id]
	s.mu.Unlock()
	if t == nil || t.carrierID != carrierID {
		return nil, "", false
	}
	return t, tail, true
}
