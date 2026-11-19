// Package sshtest is an in-process SSH server for tests.
//
// It exists so the carrier's unit tests and the integration tests that drive
// the real binary can share one server rather than keep two in step. Nothing
// here is for production: it accepts a single configured key and has no
// authorization beyond that.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ExecHandler runs in place of the remote command. Returning a non-zero status
// plays a command that failed.
type ExecHandler func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int

// Server is an in-process sshd.
type Server struct {
	Addr string
	// HostKey is what it presents; pin this in a client's host-key policy.
	HostKey ssh.PublicKey
	// ClientKey is the credential it accepts.
	ClientKey ssh.Signer
	// clientPriv backs ClientKey, so a test can write it out as an identity
	// file. ssh.Signer does not expose the key it wraps.
	clientPriv ed25519.PrivateKey

	ln net.Listener
}

// ClientKeyPEM renders the accepted credential as an OpenSSH private key, for
// a test that needs it on disk as an identity file.
func (s *Server) ClientKeyPEM() ([]byte, error) {
	blk, err := ssh.MarshalPrivateKey(s.clientPriv, "")
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(blk), nil
}

// Option adjusts the server before it starts.
type Option func(*ssh.ServerConfig)

// WithKeyboardInteractive makes the server demand a keyboard-interactive
// answer instead of a key, standing in for a site that requires a one-time
// code.
func WithKeyboardInteractive(instruction, question, want string) Option {
	return func(cfg *ssh.ServerConfig) {
		cfg.PublicKeyCallback = nil
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, chal ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := chal("", instruction, []string{question}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != want {
				return nil, fmt.Errorf("bad answer")
			}
			return &ssh.Permissions{}, nil
		}
	}
}

// WithPassword makes the server demand a password.
func WithPassword(want string) Option {
	return func(cfg *ssh.ServerConfig) {
		cfg.PublicKeyCallback = nil
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, got []byte) (*ssh.Permissions, error) {
			if string(got) != want {
				return nil, fmt.Errorf("bad password")
			}
			return &ssh.Permissions{}, nil
		}
	}
}

// Start brings up a server on loopback. Close it when done.
func Start(handle ExecHandler, opts ...Option) (*Server, error) {
	hostSigner, hostPub, _, err := genKey()
	if err != nil {
		return nil, err
	}
	clientSigner, clientPub, clientPriv, err := genKey()
	if err != nil {
		return nil, err
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown public key")
		},
	}
	for _, o := range opts {
		o(cfg)
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{Addr: ln.Addr().String(), HostKey: hostPub, ClientKey: clientSigner, clientPriv: clientPriv, ln: ln}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveConn(nc, cfg, handle)
		}
	}()
	return s, nil
}

// Close stops the server.
func (s *Server) Close() error { return s.ln.Close() }

// KnownHostsLine is the known_hosts entry a client needs to trust it.
func (s *Server) KnownHostsLine() string {
	return knownHostsLine(s.Addr, s.HostKey)
}

func serveConn(nc net.Conn, cfg *ssh.ServerConfig, handle ExecHandler) {
	defer func() { _ = nc.Close() }()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() == "direct-tcpip" {
			// Acting as a jump host: forward the channel where it asks.
			go forwardDirectTCPIP(newCh)
			continue
		}
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

func serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, handle ExecHandler) {
	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
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
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
			_ = ch.Close()
		}()
		return
	}
}

// forwardDirectTCPIP makes the server usable as a jump host.
func forwardDirectTCPIP(newCh ssh.NewChannel) {
	var req struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &req); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "bad direct-tcpip request")
		return
	}
	up, err := net.Dial("tcp", net.JoinHostPort(req.DestAddr, fmt.Sprintf("%d", req.DestPort)))
	if err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		_ = up.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { _, _ = io.Copy(up, ch); _ = up.Close() }()
	_, _ = io.Copy(ch, up)
	_ = ch.Close()
}

// Echo copies stdin to stdout, making the session a loopback.
func Echo(_ string, stdin io.Reader, stdout, _ io.Writer) int {
	_, _ = io.Copy(stdout, stdin)
	return 0
}

// RunReal actually executes the command, with the SSH channel as its standard
// streams -- which is what a real sshd does, and what an integration test
// needs in order to drive a genuine binary rather than a stand-in.
//
// The command is handed to a shell because that is how sshd runs an exec
// request, and the carrier relies on it: a staged broker is started with
// `env -i CONDOR_CONFIG=... binary -carrier-stdio`.
func RunReal(cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
	c := exec.Command("/bin/sh", "-c", cmd)
	c.Stdin = stdin
	c.Stdout = stdout
	c.Stderr = stderr
	c.Env = os.Environ()
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			return ee.ExitCode()
		}
		fmt.Fprintf(stderr, "sshtest: %v\n", err)
		return 127
	}
	return 0
}

func genKey() (ssh.Signer, ssh.PublicKey, ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, nil, err
	}
	return signer, signer.PublicKey(), priv, nil
}

// knownHostsLine renders the entry for a host and key.
func knownHostsLine(addr string, key ssh.PublicKey) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
	}
	return knownhosts.Line([]string{knownhosts.Normalize(net.JoinHostPort(host, port))}, key)
}

func asExitError(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}
