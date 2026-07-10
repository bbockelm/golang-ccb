package fstun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// segName is the on-disk name of segment index i within a direction directory.
func segName(i uint32) string { return fmt.Sprintf("%06d.seg", i) }

// segWriter appends frames to an append-only sequence of segment files in one
// direction directory. A single process is the only writer of that directory
// (§4.1), so no cross-writer locking is needed; the mutex only guards concurrent
// callers within this process.
type segWriter struct {
	dir     string
	maxSeg  int64 // roll when the current segment would exceed this
	syncEnb bool

	mu      sync.Mutex
	cur     uint32   // current segment index
	f       *os.File // current segment file
	size    int64    // bytes written to the current segment
	closed  bool
	reapOff []segEnd // closed segments awaiting reap, in order
}

// segEnd records a closed segment's index and the cumulative DATA byte offset at
// its end, so the writer can unlink it once the reader ACKs past that offset.
type segEnd struct {
	idx     uint32
	dataEnd uint64
}

// newSegWriter creates dir and opens segment 0 for appending.
func newSegWriter(dir string, maxSeg int64, sync bool) (*segWriter, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &segWriter{dir: dir, maxSeg: maxSeg, syncEnb: sync}
	if err := w.openCur(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *segWriter) openCur() error {
	f, err := os.OpenFile(filepath.Join(w.dir, segName(w.cur)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	w.f = f
	w.size = 0
	return nil
}

// append writes one frame, rolling to a new segment first if this frame would
// push the current one past maxSeg. dataEnd is the cumulative DATA byte offset
// after this frame (used for reap accounting); pass the writer's running total.
func (w *segWriter) append(f *frame, dataEnd uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}

	enc := f.appendTo(nil)
	if w.size > 0 && w.size+int64(len(enc)) > w.maxSeg {
		if err := w.roll(dataEnd); err != nil {
			return err
		}
		enc = f.appendTo(nil)
	}
	if _, err := w.f.Write(enc); err != nil {
		return err
	}
	w.size += int64(len(enc))
	if w.syncEnb {
		_ = w.f.Sync()
	}
	return nil
}

// roll closes the current segment with a ROLL frame and opens the next. Caller
// holds mu. dataEnd is the cumulative DATA offset at the roll point.
func (w *segWriter) roll(dataEnd uint64) error {
	next := w.cur + 1
	rollFrame := &frame{typ: frameROLL, payload: encodeUint32(next)}
	if _, err := w.f.Write(rollFrame.appendTo(nil)); err != nil {
		return err
	}
	if w.syncEnb {
		_ = w.f.Sync()
	}
	_ = w.f.Close()
	w.reapOff = append(w.reapOff, segEnd{idx: w.cur, dataEnd: dataEnd})
	w.cur = next
	return w.openCur()
}

// reap unlinks every closed segment the reader has fully consumed, i.e. whose
// ending DATA offset is <= ackedDataOff. The current segment is never reaped.
func (w *segWriter) reap(ackedDataOff uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	kept := w.reapOff[:0]
	for _, s := range w.reapOff {
		if s.dataEnd <= ackedDataOff {
			_ = os.Remove(filepath.Join(w.dir, segName(s.idx)))
		} else {
			kept = append(kept, s)
		}
	}
	// Copy to release the aliased backing array of removed entries.
	w.reapOff = append([]segEnd(nil), kept...)
}

func (w *segWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	if w.f != nil {
		if w.syncEnb {
			_ = w.f.Sync()
		}
		_ = w.f.Close()
	}
}

// segReader reads frames sequentially across a direction's segment files. It
// tolerates a partial tail (returns errIncompleteFrame so the caller waits) and
// follows ROLL frames to the next segment. Not safe for concurrent use.
type segReader struct {
	dir string

	cur uint32   // current segment index
	f   *os.File // current segment file (nil until first read)
	off int64    // read offset within the current segment
	buf []byte   // carry-over bytes of a partially-read frame
}

func newSegReader(dir string) *segReader {
	return &segReader{dir: dir}
}

// next returns the next frame, or errIncompleteFrame if a complete frame is not
// yet available (EOF or torn tail) -- the caller should wait and retry. A ROLL is
// consumed internally (advancing to the next segment) and never returned. The
// returned frame's payload is owned by the reader until the following next call.
func (r *segReader) next() (frame, error) {
	for {
		if r.f == nil {
			f, err := openWait(filepath.Join(r.dir, segName(r.cur)))
			if err != nil {
				return frame{}, err // ErrNotExist => not created yet; caller waits
			}
			r.f = f
			r.off = 0
		}

		// Try to decode from carry-over first.
		if fr, n, err := decodeFrame(r.buf); err == nil {
			// Copy payload out of the shared buffer before advancing.
			fr.payload = append([]byte(nil), fr.payload...)
			r.buf = r.buf[n:]
			if fr.typ == frameROLL {
				if err := r.advance(fr); err != nil {
					return frame{}, err
				}
				continue
			}
			return fr, nil
		} else if errors.Is(err, errCorruptFrame) {
			return frame{}, err
		}

		// Need more bytes: read the next chunk of the file from r.off.
		grew, err := r.fill()
		if err != nil {
			return frame{}, err
		}
		if !grew {
			return frame{}, errIncompleteFrame
		}
	}
}

// fill appends any newly-visible bytes of the current segment (past r.off) into
// r.buf. It returns whether any bytes were read.
func (r *segReader) fill() (bool, error) {
	fi, err := r.f.Stat()
	if err != nil {
		return false, err
	}
	if fi.Size() <= r.off {
		return false, nil
	}
	toRead := fi.Size() - r.off
	tmp := make([]byte, toRead)
	n, err := r.f.ReadAt(tmp, r.off)
	if n > 0 {
		r.buf = append(r.buf, tmp[:n]...)
		r.off += int64(n)
	}
	if err != nil && n == 0 {
		// EOF with nothing new is not an error to the caller.
		return false, nil
	}
	return n > 0, nil
}

// advance moves to the segment named by a ROLL frame.
func (r *segReader) advance(roll frame) error {
	next, err := decodeUint32(roll.payload)
	if err != nil {
		return err
	}
	_ = r.f.Close()
	r.f = nil
	r.cur = next
	r.buf = r.buf[:0]
	return nil
}

func (r *segReader) close() {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
}

// openWait opens path, returning os.ErrNotExist (unwrapped-comparable) if it does
// not exist yet so the caller can poll for it.
func openWait(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return f, nil
}
