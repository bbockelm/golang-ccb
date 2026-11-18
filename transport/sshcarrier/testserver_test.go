package sshcarrier

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

// execHandler runs in place of the remote command. Writing to stderr and
// returning a non-zero status is how a test plays a command that failed.
type execHandler func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int

// testSSHServer is an in-process sshd: enough of one to exercise the carrier
// without a real daemon, a real account, or a real key on disk.
type testSSHServer struct {
	addr      string
	hostKey   ssh.PublicKey
	clientKey ssh.Signer
	ln        net.Listener
}

func newTestSSHServer(t *testing.T, handle execHandler) *testSSHServer {
	t.Helper()
	return newTestSSHServerWith(t, handle, nil)
}

// interactiveServer demands a keyboard-interactive answer instead of a key,
// standing in for a site that requires a one-time code or a password.
func interactiveServer(t *testing.T, want string, handle execHandler) *testSSHServer {
	t.Helper()
	return newTestSSHServerWith(t, handle, func(cfg *ssh.ServerConfig) {
		cfg.PublicKeyCallback = nil
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, chal ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := chal("", "Two-factor required", []string{"Verification code:"}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != want {
				return nil, fmt.Errorf("bad code")
			}
			return &ssh.Permissions{}, nil
		}
	})
}

func newTestSSHServerWith(t *testing.T, handle execHandler, tweak func(*ssh.ServerConfig)) *testSSHServer {
	t.Helper()

	hostSigner, hostPub := genKey(t)
	clientSigner, clientPub := genKey(t)

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown public key")
		},
	}
	if tweak != nil {
		tweak(cfg)
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSSHServer{addr: ln.Addr().String(), hostKey: hostPub, clientKey: clientSigner, ln: ln}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveConn(nc, cfg, handle)
		}
	}()
	return s
}

func serveConn(nc net.Conn, cfg *ssh.ServerConfig, handle execHandler) {
	defer func() { _ = nc.Close() }()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go serveSession(ch, chReqs, handle)
	}
}

func serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, handle execHandler) {
	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		// "exec" payload is a length-prefixed command string.
		var payload struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		go func() {
			status := handle(payload.Command, ch, ch, ch.Stderr())
			// Tell the client the command is done, the way sshd does, then
			// close so its stdout sees EOF.
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
			_ = ch.Close()
		}()
		return
	}
}

func genKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, signer.PublicKey()
}

// config returns a carrier Config pinned to this server's host key and
// authenticating with the key it accepts.
func (s *testSSHServer) config(command string) Config {
	return Config{
		Addr:            s.addr,
		User:            "tester",
		Command:         command,
		HostKeyCallback: ssh.FixedHostKey(s.hostKey),
		authOverride:    []ssh.AuthMethod{ssh.PublicKeys(s.clientKey)},
	}
}

// echo copies stdin to stdout, so the pipe is a loopback.
func echo(_ string, stdin io.Reader, stdout, _ io.Writer) int {
	_, _ = io.Copy(stdout, stdin)
	return 0
}
