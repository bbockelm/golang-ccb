package ccbserver

import (
	"net"
	"strconv"
	"sync"

	"github.com/bbockelm/golang-ccb/transport/carrier"
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

// carrierSet maps each live pipe to the CCBID this broker gave it. Carrier ids
// come from the same counter as target ids, because both appear as "#N" in a
// contact and must not collide.
type carrierSet struct {
	mu    sync.Mutex
	byID  map[uint64]struct{} // carrier ids currently live
	byPip map[uint64]uint64   // transport pipe id -> carrier id
}

func (s *carrierSet) open(pipeID, carrierID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = make(map[uint64]struct{})
		s.byPip = make(map[uint64]uint64)
	}
	s.byID[carrierID] = struct{}{}
	s.byPip[pipeID] = carrierID
}

func (s *carrierSet) closePipe(pipeID uint64) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byPip[pipeID]
	if !ok {
		return 0, false
	}
	delete(s.byPip, pipeID)
	delete(s.byID, id)
	return id, true
}

func (s *carrierSet) forPipe(pipeID uint64) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byPip[pipeID]
	return id, ok
}

func (s *carrierSet) has(id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.byID[id]
	return ok
}

// CarrierHooks returns the pipe hooks to give carrier.NewMuxListener so that
// targets registering over each pipe are recognised as carrier-attached.
//
// One pipe is one carrier. The hooks give its exact lifetime: the id is
// allocated when the pipe comes up and released when it goes, so a contact
// naming a dead carrier resolves to nothing.
func (s *Server) CarrierHooks() carrier.PipeHooks {
	return carrier.PipeHooks{
		Open: func(pipeID uint64) {
			s.mu.Lock()
			s.nextID++
			id := s.nextID
			s.mu.Unlock()
			s.carriers.open(pipeID, id)
			s.log.Info("carrier attached", "carrier", id, "pipe", pipeID)
		},
		Close: func(pipeID uint64) {
			if id, ok := s.carriers.closePipe(pipeID); ok {
				s.log.Info("carrier detached", "carrier", id, "pipe", pipeID)
			}
		},
	}
}

// carrierOf reports the carrier a connection arrived on, if any.
func (s *Server) carrierOf(c net.Conn) (uint64, bool) {
	pipeID, ok := carrier.PipeIDOf(c)
	if !ok {
		return 0, false
	}
	return s.carriers.forPipe(pipeID)
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
