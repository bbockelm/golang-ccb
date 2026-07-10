package wscarrier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-ccb/transport/carrier"
)

// goodToken verifier: accepts "letmein", rejects everything else.
func goodTokenVerifier(_ context.Context, token string) (string, error) {
	if token == "letmein" {
		return "tester@pool", nil
	}
	return "", fmt.Errorf("bad token")
}

func startWS(t *testing.T, tlsCfg *tls.Config) *Listener {
	t.Helper()
	ln, err := Listen(ListenConfig{Addr: "127.0.0.1:0", Verify: goodTokenVerifier, TLS: tlsCfg})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func wsURL(ln *Listener, tls bool) string {
	scheme := "ws"
	if tls {
		scheme = "wss"
	}
	return fmt.Sprintf("%s://%s%s", scheme, ln.Addr().String(), DefaultPath)
}

func TestWSCarrierAuthAndDuplex(t *testing.T) {
	ln := startWS(t, nil)

	accCh := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accCh <- c
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := Dial(ctx, DialConfig{URL: wsURL(ln, false), Token: "letmein"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = cli.Close() }()

	var srv net.Conn
	select {
	case srv = <-accCh:
	case <-time.After(10 * time.Second):
		t.Fatal("no Accept")
	}
	defer func() { _ = srv.Close() }()

	// client -> server
	if _, err := cli.Write([]byte("ping")); err != nil {
		t.Fatalf("cli write: %v", err)
	}
	buf := make([]byte, 16)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := srv.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("srv read = %q, %v", buf[:n], err)
	}
	// server -> client
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatalf("srv write: %v", err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = cli.Read(buf)
	if err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("cli read = %q, %v", buf[:n], err)
	}
}

func TestWSCarrierRejectsBadToken(t *testing.T) {
	ln := startWS(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := Dial(ctx, DialConfig{URL: wsURL(ln, false), Token: "nope"}); err == nil {
		t.Fatal("expected Dial to fail with a bad token")
	}
}

func TestWSCarrierTLS(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	ln := startWS(t, serverTLS)

	accCh := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accCh <- c
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := Dial(ctx, DialConfig{URL: wsURL(ln, true), Token: "letmein", TLS: clientTLS})
	if err != nil {
		t.Fatalf("wss Dial: %v", err)
	}
	defer func() { _ = cli.Close() }()

	var srv net.Conn
	select {
	case srv = <-accCh:
	case <-time.After(10 * time.Second):
		t.Fatal("no Accept over wss")
	}
	defer func() { _ = srv.Close() }()

	if _, err := cli.Write([]byte("secure")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := srv.Read(buf)
	if err != nil || string(buf[:n]) != "secure" {
		t.Fatalf("srv read over wss = %q, %v", buf[:n], err)
	}
}

// TestWSCarrierMux runs yamux over the WebSocket pipe -- the real CCB usage --
// with many concurrent streams echoed back.
func TestWSCarrierMux(t *testing.T) {
	ln := startWS(t, nil)
	ml := carrier.NewMuxListener(ln)
	t.Cleanup(func() { _ = ml.Close() })
	go func() {
		for {
			c, err := ml.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pipe, err := Dial(ctx, DialConfig{URL: wsURL(ln, false), Token: "letmein"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	md, err := carrier.NewMuxDialer(pipe)
	if err != nil {
		t.Fatalf("NewMuxDialer: %v", err)
	}
	defer func() { _ = md.Close() }()

	const streams = 10
	var wg sync.WaitGroup
	errCh := make(chan error, streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			octx, ocancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer ocancel()
			c, err := md.Open(octx)
			if err != nil {
				errCh <- fmt.Errorf("open %d: %w", i, err)
				return
			}
			defer c.Close()
			msg := []byte(fmt.Sprintf("ws-stream-%d", i))
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

// selfSignedTLS returns a server tls.Config (with a fresh self-signed cert for
// 127.0.0.1) and a client tls.Config that trusts it.
func selfSignedTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{Certificates: []tls.Certificate{cert}}, &tls.Config{RootCAs: pool}
}
