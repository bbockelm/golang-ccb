package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-ccb/transport/fstun"
)

func fstunPair(t *testing.T) (*MuxListener, *MuxDialer) {
	t.Helper()
	root := t.TempDir()
	cfg := fstun.Config{
		Root:             root,
		PollInterval:     2 * time.Millisecond,
		Heartbeat:        100 * time.Millisecond,
		IdleTimeout:      30 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		SegmentSize:      256 << 10,
		MaxFrame:         16 << 10,
		Window:           128 << 10,
	}
	ln, err := fstun.Listen(cfg)
	if err != nil {
		t.Fatalf("fstun.Listen: %v", err)
	}
	ml := NewMuxListener(ln)
	t.Cleanup(func() { _ = ml.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pipe, err := fstun.Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("fstun.Dial: %v", err)
	}
	md, err := NewMuxDialer(pipe)
	if err != nil {
		t.Fatalf("NewMuxDialer: %v", err)
	}
	t.Cleanup(func() { _ = md.Close() })
	return ml, md
}

// echoServer accepts streams off the listener and echoes each until it closes.
func echoServer(t *testing.T, ml *MuxListener) {
	t.Helper()
	go func() {
		for {
			c, err := ml.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
}

func TestMuxManyConcurrentStreams(t *testing.T) {
	ml, md := fstunPair(t)
	echoServer(t, ml)

	const streams = 20
	var wg sync.WaitGroup
	errCh := make(chan error, streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := md.Open(ctx)
			if err != nil {
				errCh <- fmt.Errorf("open %d: %w", i, err)
				return
			}
			defer c.Close()
			msg := []byte(fmt.Sprintf("stream-%d-hello-world", i))
			if _, err := c.Write(msg); err != nil {
				errCh <- fmt.Errorf("write %d: %w", i, err)
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(c, got); err != nil {
				errCh <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if !bytes.Equal(got, msg) {
				errCh <- fmt.Errorf("stream %d: got %q want %q", i, got, msg)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestMuxBulkOverOneStream(t *testing.T) {
	ml, md := fstunPair(t)
	echoServer(t, ml)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := md.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()

	const total = 2 << 20 // 2 MiB round-trip through the echo, over fstun
	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, total)
	var rerr error
	done := make(chan struct{})
	go func() {
		_, rerr = io.ReadFull(c, got)
		close(done)
	}()

	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("bulk round-trip timed out")
	}
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("bulk payload mismatch")
	}
}

// A relay endpoint must be able to end its sending side without ending the
// connection, or the peer waits for data that will never come and the relay
// tears the transfer down when its drain grace expires. yamux spells that
// Close rather than CloseWrite, which a relay probing for CloseWrite does not
// find -- so the streams this package hands out adapt it.
func TestStreamsSupportHalfClose(t *testing.T) {
	ml, md := fstunPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := md.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = client.Close() }()

	server, err := ml.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = server.Close() }()

	cw, ok := client.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("a dialed stream (%T) has no CloseWrite; a relay cannot half-close it", client)
	}
	if _, ok := server.(interface{ CloseWrite() error }); !ok {
		t.Fatalf("an accepted stream (%T) has no CloseWrite", server)
	}

	// The client sends a request and says it is done sending.
	req := []byte("request bytes")
	if _, err := client.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// The server must see the request, then EOF -- that is what tells it to
	// stop waiting and reply.
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, req) {
		t.Fatalf("server read %q, want %q", got, req)
	}

	// And the reverse direction must still work after the half-close. This is
	// the half that a plain Close would have destroyed.
	reply := []byte("reply after the client half-closed")
	if _, err := server.Write(reply); err != nil {
		t.Fatalf("server write after client half-close: %v", err)
	}
	if err := server.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("server CloseWrite: %v", err)
	}
	back, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("client read after half-close: %v", err)
	}
	if !bytes.Equal(back, reply) {
		t.Fatalf("client read %q after half-closing, want %q", back, reply)
	}
}
