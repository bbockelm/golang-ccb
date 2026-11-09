package carrier

import (
	"errors"
	"net"
	"testing"
	"time"
)

// pipePair returns a connected pair over a real TCP loopback listener, plus the
// listener the MuxListener will accept from.
func probationListener(t *testing.T, opts ...MuxOption) (*MuxListener, string) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewMuxListener(inner, opts...)
	t.Cleanup(func() { _ = l.Close() })
	return l, inner.Addr().String()
}

// TestProbationDropsIdlePipe: a peer that establishes a carrier pipe and then
// opens no logical connection must be dropped. This is what keeps an
// unauthenticated upgrade from being a place to park connections.
func TestProbationDropsIdlePipe(t *testing.T) {
	_, addr := probationListener(t, WithFirstStreamTimeout(300*time.Millisecond))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Never speak yamux: just hold the socket. The server must close it.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("read succeeded; expected the probation timer to close the pipe")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("pipe was still open after the probation interval; the timer is not applied")
	}
}

// TestProbationSparesActivePipe: a pipe that opens a stream must survive well
// past the probation interval, or a legitimate carrier would be torn down
// under load.
func TestProbationSparesActivePipe(t *testing.T) {
	l, addr := probationListener(t, WithFirstStreamTimeout(300*time.Millisecond))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	d, err := NewMuxDialer(c)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	st, err := d.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srvSide, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer srvSide.Close()

	// Well past the interval, the session must still carry data.
	time.Sleep(900 * time.Millisecond)
	if _, err := st.Write([]byte("still here")); err != nil {
		t.Fatalf("write after the probation interval: %v", err)
	}
	buf := make([]byte, len("still here"))
	_ = srvSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := srvSide.Read(buf); err != nil {
		t.Fatalf("read after the probation interval: %v", err)
	}
	if string(buf) != "still here" {
		t.Fatalf("got %q", buf)
	}
}

// TestProbationDisabled: a zero/negative interval leaves an idle pipe alone,
// so an operator can turn the check off.
func TestProbationDisabled(t *testing.T) {
	_, addr := probationListener(t, WithFirstStreamTimeout(-1))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("idle pipe was closed with probation disabled: %v", err)
	}
}
