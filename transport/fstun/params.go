package fstun

import (
	"encoding/binary"
	"fmt"
)

func encodeUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func decodeUint32(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, fmt.Errorf("fstun: bad uint32 payload len %d", len(b))
	}
	return binary.BigEndian.Uint32(b), nil
}

func encodeUint64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func decodeUint64(b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, fmt.Errorf("fstun: bad uint64 payload len %d", len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

// protocolVersion is the fstun wire version, exchanged in SYN. A peer speaking a
// higher version is expected to be backward compatible; a lower one is rejected.
const protocolVersion uint16 = 1

// synParams is a SYN frame's payload: the protocol version and the sender's own
// send-side parameters. Each side chooses its own segment size / window / max
// frame independently (the reader is agnostic, bounded only by maxPayload), so
// these are not negotiated -- they are carried for the version check and for
// diagnostics.
type synParams struct {
	version     uint16
	segmentSize uint64 // bytes per segment file before rolling
	window      uint64 // max outstanding unacked DATA bytes (backpressure)
	maxFrame    uint32 // max DATA payload per frame
}

func (p synParams) encode() []byte {
	b := make([]byte, 2+8+8+4)
	binary.BigEndian.PutUint16(b[0:2], p.version)
	binary.BigEndian.PutUint64(b[2:10], p.segmentSize)
	binary.BigEndian.PutUint64(b[10:18], p.window)
	binary.BigEndian.PutUint32(b[18:22], p.maxFrame)
	return b
}

func decodeSynParams(b []byte) (synParams, error) {
	if len(b) != 22 {
		return synParams{}, fmt.Errorf("fstun: bad SYN payload len %d", len(b))
	}
	return synParams{
		version:     binary.BigEndian.Uint16(b[0:2]),
		segmentSize: binary.BigEndian.Uint64(b[2:10]),
		window:      binary.BigEndian.Uint64(b[10:18]),
		maxFrame:    binary.BigEndian.Uint32(b[18:22]),
	}, nil
}
