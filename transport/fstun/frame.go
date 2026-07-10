// Package fstun implements a reliable, ordered, full-duplex byte pipe (a net.Conn)
// carried over a shared directory with NFS-like semantics, for CCB tunneling
// where the inside and outside brokers cannot open a socket to each other. See
// docs/TRANSPORTS.md for the design; §4 there is the normative wire format.
//
// A single directory subtree is one pipe. yamux is layered on top by the caller
// to multiplex the many logical CCB connections; fstun itself is not aware of
// multiplexing -- it delivers one good pipe.
package fstun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// frameType is the 1-byte type tag leading every frame (§4.3).
type frameType uint8

const (
	frameSYN       frameType = 1 // open a direction; payload = synParams
	frameDATA      frameType = 2 // stream bytes
	frameACK       frameType = 3 // payload = uint64 cumulative DATA bytes consumed in the opposite direction
	frameHeartbeat frameType = 4 // payload = uint64 wall-clock nanos (debug); liveness
	frameFIN       frameType = 5 // half-close: no more DATA from this writer
	frameError     frameType = 6 // abort the whole pipe; payload = UTF-8 reason
	frameROLL      frameType = 7 // last frame in a segment; payload = uint32 next segment index
)

func (t frameType) String() string {
	switch t {
	case frameSYN:
		return "SYN"
	case frameDATA:
		return "DATA"
	case frameACK:
		return "ACK"
	case frameHeartbeat:
		return "HEARTBEAT"
	case frameFIN:
		return "FIN"
	case frameError:
		return "ERROR"
	case frameROLL:
		return "ROLL"
	default:
		return fmt.Sprintf("frameType(%d)", uint8(t))
	}
}

const (
	// headerLen is the fixed frame header: type(1) flags(1) seq(8) dataOff(8) length(4).
	headerLen = 22
	// crcLen is the trailing CRC32C.
	crcLen = 4
	// frameOverhead is the non-payload cost of a frame on disk.
	frameOverhead = headerLen + crcLen
	// maxPayload bounds a single frame's payload so a torn tail is cheap to
	// re-read and a hostile length cannot force a huge allocation.
	maxPayload = 1 << 20 // 1 MiB
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// errIncompleteFrame means the bytes for a full frame are not yet present at the
// tail of a segment (a partial NFS-visible append, or plain EOF). The caller
// should wait and re-read from the same offset; it is not corruption. §4.2.
var errIncompleteFrame = errors.New("fstun: incomplete frame")

// errCorruptFrame means a frame whose declared bytes are fully present failed its
// CRC, or declared an impossible length. Fatal for the pipe.
var errCorruptFrame = errors.New("fstun: corrupt frame")

// frame is one decoded wire frame.
type frame struct {
	typ     frameType
	flags   uint8
	seq     uint64
	dataOff uint64 // cumulative DATA payload bytes BEFORE this frame
	payload []byte
}

// encodedLen is the number of bytes this frame occupies on disk.
func (f *frame) encodedLen() int { return frameOverhead + len(f.payload) }

// appendTo encodes f (header, payload, CRC) onto dst and returns the extended
// slice.
func (f *frame) appendTo(dst []byte) []byte {
	var hdr [headerLen]byte
	hdr[0] = byte(f.typ)
	hdr[1] = f.flags
	binary.BigEndian.PutUint64(hdr[2:10], f.seq)
	binary.BigEndian.PutUint64(hdr[10:18], f.dataOff)
	binary.BigEndian.PutUint32(hdr[18:22], uint32(len(f.payload)))

	crc := crc32.New(crcTable)
	_, _ = crc.Write(hdr[:])
	_, _ = crc.Write(f.payload)

	dst = append(dst, hdr[:]...)
	dst = append(dst, f.payload...)
	var tr [crcLen]byte
	binary.BigEndian.PutUint32(tr[:], crc.Sum32())
	return append(dst, tr[:]...)
}

// decodeFrame decodes one frame from the front of buf. It returns the frame and
// the number of bytes consumed. If buf does not yet hold a complete frame it
// returns errIncompleteFrame (consumed == 0); the caller should wait for more
// bytes. A fully-present frame that fails its CRC or declares an impossible
// length returns errCorruptFrame.
//
// The returned frame's payload aliases buf; callers that retain it past the next
// read must copy.
func decodeFrame(buf []byte) (frame, int, error) {
	if len(buf) < headerLen {
		return frame{}, 0, errIncompleteFrame
	}
	length := binary.BigEndian.Uint32(buf[18:22])
	if length > maxPayload {
		return frame{}, 0, fmt.Errorf("%w: payload length %d exceeds max %d", errCorruptFrame, length, maxPayload)
	}
	total := headerLen + int(length) + crcLen
	if len(buf) < total {
		return frame{}, 0, errIncompleteFrame
	}

	payload := buf[headerLen : headerLen+int(length)]
	want := binary.BigEndian.Uint32(buf[headerLen+int(length) : total])
	crc := crc32.New(crcTable)
	_, _ = crc.Write(buf[:headerLen])
	_, _ = crc.Write(payload)
	if crc.Sum32() != want {
		return frame{}, 0, errCorruptFrame
	}

	f := frame{
		typ:     frameType(buf[0]),
		flags:   buf[1],
		seq:     binary.BigEndian.Uint64(buf[2:10]),
		dataOff: binary.BigEndian.Uint64(buf[10:18]),
		payload: payload,
	}
	return f, total, nil
}
