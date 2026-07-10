package fstun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type role int

const (
	roleInitiator role = iota // writes c2s, reads s2c
	roleAcceptor              // writes s2c, reads c2s
)

func (r role) sendDir() string {
	if r == roleInitiator {
		return "c2s"
	}
	return "s2c"
}
func (r role) recvDir() string {
	if r == roleInitiator {
		return "s2c"
	}
	return "c2s"
}

// Conn is one fstun byte pipe: a reliable, ordered, full-duplex net.Conn carried
// over a <root>/<conn-id>/ subtree. Safe for one concurrent Read and one
// concurrent Write (the net.Conn contract); yamux, the intended user, honours it.
type Conn struct {
	cfg     resolvedConfig
	connDir string
	role    role
	params  synParams

	w *segWriter
	r *segReader

	// Send/flow state, all under sendMu.
	sendMu      sync.Mutex
	sendSeq     uint64
	sentData    uint64 // cumulative DATA bytes written
	peerAck     uint64 // highest ACK received (our data the peer has consumed)
	lastAckSent uint64 // cumulative recvData we have ACKed to the peer
	sendClosed  bool

	// Recv state, all under recvMu.
	recvMu   sync.Mutex
	recvBuf  []byte
	recvData uint64 // cumulative DATA bytes delivered to Read (== what we ACK)
	recvEOF  bool   // peer sent FIN
	recvErr  error  // peer sent ERROR, or the pipe failed

	// Signals (buffered size 1, coalescing).
	dataSig chan struct{} // recv state changed (data/EOF/err)
	flowSig chan struct{} // peerAck advanced / send closed / err

	// Deadlines.
	dlMu  sync.Mutex
	rdDdl time.Time
	wrDdl time.Time

	lastRecv atomicTime // time of the last frame observed (idle detection)

	closeOnce sync.Once
	closed    chan struct{}
	recvDone  chan struct{}

	// dead is closed once the pipe is terminal for ANY reason -- local Close, a
	// peer FIN/ERROR, or an idle/heartbeat timeout. The acceptor watches it to
	// reap the on-disk subtree (see Listener).
	deadOnce sync.Once
	dead     chan struct{}
}

func newConn(cfg resolvedConfig, connDir string, r role, w *segWriter, sr *segReader, sendSeq uint64, params synParams) *Conn {
	c := &Conn{
		cfg:      cfg,
		connDir:  connDir,
		role:     r,
		params:   params,
		w:        w,
		r:        sr,
		sendSeq:  sendSeq,
		dataSig:  make(chan struct{}, 1),
		flowSig:  make(chan struct{}, 1),
		closed:   make(chan struct{}),
		recvDone: make(chan struct{}),
		dead:     make(chan struct{}),
	}
	c.lastRecv.set(time.Now())
	go c.recvLoop()
	go c.maintLoop()
	return c
}

// --- net.Conn ---

func (c *Conn) Read(p []byte) (int, error) {
	for {
		c.recvMu.Lock()
		if len(c.recvBuf) > 0 {
			n := copy(p, c.recvBuf)
			c.recvBuf = c.recvBuf[n:]
			c.recvData += uint64(n)
			c.recvMu.Unlock()
			c.maybeAck()
			return n, nil
		}
		if c.recvErr != nil {
			err := c.recvErr
			c.recvMu.Unlock()
			return 0, err
		}
		if c.recvEOF {
			c.recvMu.Unlock()
			return 0, io.EOF
		}
		c.recvMu.Unlock()

		timer, stop := c.deadline(true)
		select {
		case <-c.dataSig:
			stop()
		case <-timer:
			stop()
			return 0, timeoutErr{}
		case <-c.closed:
			stop()
			return 0, net.ErrClosed
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		room, err := c.waitSendWindow()
		if err != nil {
			return total, err
		}
		n := len(p)
		if int64(n) > room {
			n = int(room)
		}
		if n > int(c.params.maxFrame) {
			n = int(c.params.maxFrame)
		}
		if err := c.emit(frameDATA, p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.emit(frameFIN, nil) // best-effort half-close
		c.sendMu.Lock()
		c.sendClosed = true
		c.sendMu.Unlock()
		close(c.closed)
		<-c.recvDone // let recvLoop stop touching the reader
		c.w.close()
		c.r.close()
		c.markDead()
	})
	return nil
}

// Done is closed once the pipe is terminal (local Close, peer FIN/ERROR, or an
// idle/heartbeat timeout). The acceptor uses it to reap the on-disk subtree.
func (c *Conn) Done() <-chan struct{} { return c.dead }

func (c *Conn) markDead() { c.deadOnce.Do(func() { close(c.dead) }) }

func (c *Conn) LocalAddr() net.Addr  { return fstunAddr{c.connDir, c.role, false} }
func (c *Conn) RemoteAddr() net.Addr { return fstunAddr{c.connDir, c.role, true} }

func (c *Conn) SetDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.rdDdl, c.wrDdl = t, t
	c.dlMu.Unlock()
	c.wake()
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.rdDdl = t
	c.dlMu.Unlock()
	c.wake()
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.wrDdl = t
	c.dlMu.Unlock()
	c.wake()
	return nil
}

// --- send path ---

// emit assigns a sequence number and appends one frame. DATA advances the data
// offset (and is subject to Write's window); control frames are never blocked.
func (c *Conn) emit(typ frameType, payload []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.sendClosed && typ != frameFIN && typ != frameError {
		return net.ErrClosed
	}
	f := &frame{typ: typ, seq: c.sendSeq, dataOff: c.sentData, payload: payload}
	c.sendSeq++
	dataEnd := c.sentData
	if typ == frameDATA {
		c.sentData += uint64(len(payload))
		dataEnd = c.sentData
	}
	return c.w.append(f, dataEnd)
}

// waitSendWindow blocks until there is room in the flow-control window, returning
// the number of bytes that may be sent now.
func (c *Conn) waitSendWindow() (int64, error) {
	for {
		c.sendMu.Lock()
		closed := c.sendClosed
		room := int64(c.params.window) - int64(c.sentData-c.peerAck)
		c.sendMu.Unlock()

		c.recvMu.Lock()
		rerr := c.recvErr
		c.recvMu.Unlock()
		if rerr != nil {
			return 0, rerr
		}
		if closed {
			return 0, net.ErrClosed
		}
		if room > 0 {
			return room, nil
		}

		timer, stop := c.deadline(false)
		select {
		case <-c.flowSig:
			stop()
		case <-timer:
			stop()
			return 0, timeoutErr{}
		case <-c.closed:
			stop()
			return 0, net.ErrClosed
		}
	}
}

// maybeAck sends an ACK if enough data has been consumed since the last one.
func (c *Conn) maybeAck() {
	c.recvMu.Lock()
	rd := c.recvData
	c.recvMu.Unlock()
	c.sendMu.Lock()
	due := rd-c.lastAckSent >= uint64(c.params.window)/4
	c.sendMu.Unlock()
	if due {
		c.sendAck(rd)
	}
}

func (c *Conn) sendAck(upTo uint64) {
	if err := c.emit(frameACK, encodeUint64(upTo)); err == nil {
		c.sendMu.Lock()
		if upTo > c.lastAckSent {
			c.lastAckSent = upTo
		}
		c.sendMu.Unlock()
	}
}

// --- recv path ---

func (c *Conn) recvLoop() {
	defer close(c.recvDone)
	poll := time.NewTimer(c.cfg.pollInterval)
	defer poll.Stop()
	for {
		select {
		case <-c.closed:
			return
		default:
		}
		f, err := c.r.next()
		switch {
		case err == nil:
			c.lastRecv.set(time.Now())
			c.dispatch(f)
			if f.typ == frameError {
				return
			}
			continue
		case errors.Is(err, errIncompleteFrame) || errors.Is(err, os.ErrNotExist):
			// No complete frame yet (torn tail, EOF, or next segment not created).
		default:
			c.failRecv(fmt.Errorf("fstun: reader: %w", err))
			return
		}

		poll.Reset(c.cfg.pollInterval)
		select {
		case <-poll.C:
		case <-c.closed:
			return
		}
	}
}

func (c *Conn) dispatch(f frame) {
	switch f.typ {
	case frameDATA:
		c.recvMu.Lock()
		c.recvBuf = append(c.recvBuf, f.payload...)
		c.recvMu.Unlock()
		c.signal(c.dataSig)
	case frameACK:
		if v, err := decodeUint64(f.payload); err == nil {
			c.sendMu.Lock()
			if v > c.peerAck {
				c.peerAck = v
			}
			ack := c.peerAck
			c.sendMu.Unlock()
			c.w.reap(ack)
			c.signal(c.flowSig)
		}
	case frameFIN:
		c.recvMu.Lock()
		c.recvEOF = true
		c.recvMu.Unlock()
		c.signal(c.dataSig)
	case frameError:
		msg := string(f.payload)
		if msg == "" {
			msg = "peer signalled error"
		}
		c.failRecv(errors.New("fstun: " + msg))
	case frameHeartbeat, frameSYN:
		// liveness only (SYN should not recur post-handshake; ignore if it does).
	}
}

func (c *Conn) failRecv(err error) {
	c.recvMu.Lock()
	if c.recvErr == nil {
		c.recvErr = err
	}
	c.recvMu.Unlock()
	c.signal(c.dataSig)
	c.signal(c.flowSig)
	// A hard failure (peer ERROR, idle/heartbeat timeout, reader error) is
	// terminal -- unlike a FIN half-close -- so the pipe is reap-eligible.
	c.markDead()
}

// maintLoop emits periodic heartbeats + a catch-up ACK, and enforces the idle
// timeout (a peer that has gone silent past IdleTimeout fails the pipe).
func (c *Conn) maintLoop() {
	t := time.NewTicker(c.cfg.heartbeat)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			if time.Since(c.lastRecv.get()) > c.cfg.idleTimeout {
				c.failRecv(fmt.Errorf("fstun: peer idle > %s", c.cfg.idleTimeout))
				return
			}
			c.recvMu.Lock()
			rd := c.recvData
			c.recvMu.Unlock()
			c.sendMu.Lock()
			ackDue := rd > c.lastAckSent
			c.sendMu.Unlock()
			if ackDue {
				c.sendAck(rd)
			}
			_ = c.emit(frameHeartbeat, encodeUint64(uint64(time.Now().UnixNano())))
		}
	}
}

// --- helpers ---

func (c *Conn) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// wake nudges any blocked Read/Write so it re-evaluates its deadline.
func (c *Conn) wake() {
	c.signal(c.dataSig)
	c.signal(c.flowSig)
}

// deadline returns a timer channel for the current read (or write) deadline and a
// stop func. A zero deadline yields a nil channel (never fires).
func (c *Conn) deadline(read bool) (<-chan time.Time, func()) {
	c.dlMu.Lock()
	d := c.wrDdl
	if read {
		d = c.rdDdl
	}
	c.dlMu.Unlock()
	if d.IsZero() {
		return nil, func() {}
	}
	t := time.NewTimer(time.Until(d))
	return t.C, func() { t.Stop() }
}

type fstunAddr struct {
	dir    string
	role   role
	remote bool
}

func (a fstunAddr) Network() string { return "fstun" }
func (a fstunAddr) String() string {
	side := "local"
	if a.remote {
		side = "remote"
	}
	return fmt.Sprintf("fstun://%s[%s]", a.dir, side)
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "fstun: i/o deadline exceeded" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// atomicTime is a mutex-guarded time.Time (avoids importing sync/atomic gymnastics
// for a value type).
type atomicTime struct {
	mu sync.Mutex
	t  time.Time
}

func (a *atomicTime) set(t time.Time) { a.mu.Lock(); a.t = t; a.mu.Unlock() }
func (a *atomicTime) get() time.Time  { a.mu.Lock(); defer a.mu.Unlock(); return a.t }
