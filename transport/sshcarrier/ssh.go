package sshcarrier

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	// DefaultPort is the SSH port when the address names none.
	DefaultPort = "22"
	// DefaultTimeout bounds the TCP connect and the SSH handshake.
	DefaultTimeout = 30 * time.Second
	// DefaultStderrLines is how many of the remote command's last stderr lines
	// are kept to explain a carrier that died.
	DefaultStderrLines = 20
	// settleGrace bounds the wait at end-of-stream for the remote command's
	// exit status.
	settleGrace = time.Second
)

// Config describes the SSH session that carries the tunnel.
type Config struct {
	// Addr is the server, "host" or "host:port" (DefaultPort if absent).
	Addr string
	// User is the login name. Empty uses the current user.
	User string

	// KnownHosts are the files to verify the server's host key against,
	// in the format ssh(1) uses. One of KnownHosts or HostKeyCallback is
	// REQUIRED: there is no mode that accepts any key.
	KnownHosts []string
	// HostKeyCallback overrides KnownHosts. Tests use it with a pinned key;
	// production should not need it.
	HostKeyCallback ssh.HostKeyCallback

	// IdentityFiles are private keys to offer, in order.
	IdentityFiles []string
	// Agent consults SSH_AUTH_SOCK when set.
	Agent bool

	// Prompter answers a server that asks for a password or a
	// keyboard-interactive challenge. Nil means this carrier cannot satisfy
	// such a server at all, and it will not offer those methods.
	Prompter Prompter

	// Command runs on the far host; its stdin and stdout become the carrier
	// pipe. Empty requests the default shell, which is almost never what a
	// carrier wants.
	Command string

	// Timeout bounds the connect and handshake. Zero uses DefaultTimeout.
	Timeout time.Duration

	// Logger receives the remote command's stderr as it arrives, at debug
	// level, and the last lines are attached to an error when the pipe dies.
	Logger *slog.Logger

	// StderrLines overrides DefaultStderrLines.
	StderrLines int

	// authOverride supplies credentials directly, bypassing the agent and
	// identity files. Unexported: it exists so tests need neither a key on
	// disk nor an agent, and production has no way to reach it.
	authOverride []ssh.AuthMethod
}

// Diagnostics is implemented by the net.Conn Dial returns, so a staged carrier
// check can report why a session ended rather than a bare EOF.
type Diagnostics interface {
	// Stderr returns the remote command's most recent stderr lines.
	Stderr() string
	// Exited reports the command's exit error and whether it has exited.
	Exited() (error, bool)
}

// HostKeyError reports a server whose key is not in known_hosts, or does not
// match the entry there.
//
// It is called out as its own type because it is the archetype of a failure no
// amount of retrying fixes: a person has to look at the key and decide. The
// carrier's retry policy uses this to stop hammering a host nobody has
// approved. A changed key is the more serious case and says so.
type HostKeyError struct {
	Addr    string
	Err     error
	Changed bool
}

func (e *HostKeyError) Error() string {
	if e.Changed {
		return fmt.Sprintf("sshcarrier: the host key for %s does not match known_hosts: %v", e.Addr, e.Err)
	}
	return fmt.Sprintf("sshcarrier: the host key for %s is not in known_hosts: %v", e.Addr, e.Err)
}

func (e *HostKeyError) Unwrap() error { return e.Err }

// NeedsHuman reports that this failure will not clear on its own.
func (e *HostKeyError) NeedsHuman() bool { return true }

// Dial opens the SSH session and returns its stdin/stdout as a carrier pipe.
//
// ctx bounds establishing the session, not its life: the returned pipe outlives
// ctx and is torn down by Close, matching the carrier contract.
func Dial(ctx context.Context, cfg Config) (net.Conn, error) {
	client, err := Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	conn, err := Start(client, cfg)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return conn, nil
}

// DialStaged is Dial with a zero-touch install in between: it connects, asks
// the far host what it is, puts the binary there if it is not already, and runs
// the staged copy.
//
// The command is derived from where the binary landed, so an operator
// configures a host and a binary rather than a path they would otherwise have
// to keep in step with the install. An explicit cfg.Command still wins, for a
// site that puts the binary somewhere itself.
//
// Closing the returned pipe closes the SSH connection with it; the staged file
// stays, which is the point -- the next broker to arrive finds it already
// there.
func DialStaged(ctx context.Context, cfg Config, stage StageConfig) (net.Conn, error) {
	client, err := Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	conn, err := startStaged(ctx, client, cfg, stage)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return conn, nil
}

func startStaged(ctx context.Context, client *ssh.Client, cfg Config, stage StageConfig) (net.Conn, error) {
	if stage.Platform == (Platform{}) {
		p, err := DetectPlatform(ctx, client)
		if err != nil {
			return nil, err
		}
		stage.Platform = p
	}
	if stage.Logger == nil {
		stage.Logger = cfg.Logger
	}
	remote, err := Stage(ctx, client, stage)
	if err != nil {
		return nil, err
	}
	if cfg.Command == "" {
		cfg.Command = shellQuote(remote) + " " + StdioFlag
	}
	return Start(client, cfg)
}

// StdioFlag is what the staged broker is told to be: the far end of this
// carrier, taking the pipe it was started with.
const StdioFlag = "-carrier-stdio"

// Connect performs the TCP connect, the host-key check and authentication,
// and returns the live client.
//
// It is separate from Start because a zero-touch install has to happen in
// between: the binary is put there over this same connection, before anything
// is run.
func Connect(ctx context.Context, cfg Config) (*ssh.Client, error) {
	addr, err := normalizeAddr(cfg.Addr)
	if err != nil {
		return nil, err
	}
	hostKey, err := cfg.hostKeyCallback()
	if err != nil {
		return nil, err
	}
	st := &authState{}
	auths, err := cfg.authMethods()
	if err != nil {
		return nil, err
	}
	if cfg.Prompter != nil {
		// Offered after the key methods: a host that takes a key should never
		// wake an operator.
		auths = append(auths, interactiveAuth(ctx, cfg, st), passwordAuth(ctx, cfg, st))
	}
	user := cfg.User
	if user == "" {
		if u := os.Getenv("USER"); u != "" {
			user = u
		} else {
			return nil, fmt.Errorf("sshcarrier: no user configured for %s and USER is unset", addr)
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client, err := dialClient(ctx, addr, &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: hostKey,
		Timeout:         timeout,
	})
	if err != nil {
		return nil, st.classify(err)
	}
	return client, nil
}

// Start opens the session, wires stderr to the log, and runs cfg.Command. It
// takes ownership of client: closing the returned pipe closes the connection.
func Start(client *ssh.Client, cfg Config) (net.Conn, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	addr, err := normalizeAddr(cfg.Addr)
	if err != nil {
		return nil, err
	}
	if cfg.Command == "" {
		return nil, fmt.Errorf("sshcarrier: no remote command configured for %s", addr)
	}
	conn, err := startSession(client, cfg, addr, log)
	if err != nil {
		return nil, err
	}
	log.Debug("ssh carrier session started", "addr", addr, "command", cfg.Command)
	return conn, nil
}

// dialClient makes the TCP connection under ctx and then runs the SSH
// handshake, classifying a host-key refusal so the retry policy can see it.
func dialClient(ctx context.Context, addr string, cc *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: cc.Timeout}
	tcp, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshcarrier: dialing %s: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(tcp, addr, cc)
	if err != nil {
		_ = tcp.Close()
		if ke := asKeyError(err); ke != nil {
			return nil, &HostKeyError{Addr: addr, Err: err, Changed: len(ke.Want) > 0}
		}
		return nil, fmt.Errorf("sshcarrier: ssh handshake with %s: %w", addr, err)
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// asKeyError digs a knownhosts.KeyError out of whatever the handshake wrapped
// it in.
func asKeyError(err error) *knownhosts.KeyError {
	var ke *knownhosts.KeyError
	if errorsAs(err, &ke) {
		return ke
	}
	return nil
}

// startSession opens the channel, wires stderr to the log, and starts the
// remote command.
func startSession(client *ssh.Client, cfg Config, addr string, log *slog.Logger) (net.Conn, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshcarrier: opening a session on %s: %w", addr, err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("sshcarrier: session stdin: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("sshcarrier: session stdout: %w", err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("sshcarrier: session stderr: %w", err)
	}

	r := &remote{
		label: addr + " " + cfg.Command,
		tail:  newTail(orInt(cfg.StderrLines, DefaultStderrLines)),
		log:   log,
		done:  make(chan struct{}),
	}
	go r.drainStderr(stderr)

	if err := sess.Start(cfg.Command); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("sshcarrier: starting %q on %s: %w", cfg.Command, addr, err)
	}
	go r.wait(sess)

	return &sshConn{
		sessionConn: sessionConn{
			r:        stdout,
			w:        stdin,
			sess:     sess,
			client:   client,
			addr:     sshAddr{label: addr},
			annotate: r.annotate,
			settle:   r.settle,
		},
		remote: r,
	}, nil
}

// sshConn is a session pipe that can say why it died.
type sshConn struct {
	sessionConn
	remote *remote
}

func (c *sshConn) Stderr() string        { return c.remote.tail.String() }
func (c *sshConn) Exited() (error, bool) { return c.remote.exited() }

// remote tracks the far command: its stderr and how it ended.
type remote struct {
	label string
	tail  *tail
	log   *slog.Logger

	done    chan struct{}
	mu      sync.Mutex
	exitErr error
}

func (r *remote) wait(sess *ssh.Session) {
	err := sess.Wait()
	r.mu.Lock()
	r.exitErr = err
	r.mu.Unlock()
	close(r.done)
}

// settle waits a bounded time for the command's exit status to be recorded.
// The status normally lands within microseconds of the stream ending -- the
// same event produces both -- so this is a race margin, not a timeout.
func (r *remote) settle() {
	select {
	case <-r.done:
	case <-time.After(settleGrace):
	}
}

func (r *remote) exited() (error, bool) {
	select {
	case <-r.done:
	default:
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exitErr, true
}

func (r *remote) drainStderr(rd interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(newReader(rd))
	sc.Buffer(make([]byte, 0, 4096), 4<<10)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		r.tail.add(line)
		r.log.Debug("ssh carrier remote stderr", "line", line)
	}
}

// annotate explains an I/O error with what the far command said and how it
// exited -- the same reasoning as the cmd: carrier, where a bare EOF told an
// operator nothing.
func (r *remote) annotate(err error) error {
	r.settle()
	exitErr, exited := r.exited()
	detail := r.tail.String()
	switch {
	case exited && exitErr != nil && detail != "":
		return fmt.Errorf("ssh carrier %s exited (%w); its last output was: %s: %w", r.label, exitErr, detail, err)
	case exited && exitErr != nil:
		return fmt.Errorf("ssh carrier %s exited (%w) without explaining why: %w", r.label, exitErr, err)
	case exited && detail != "":
		return fmt.Errorf("ssh carrier %s ended; its last output was: %s: %w", r.label, detail, err)
	case exited:
		return fmt.Errorf("ssh carrier %s ended: %w", r.label, err)
	case detail != "":
		return fmt.Errorf("ssh carrier %s is still running; its last output was: %s: %w", r.label, detail, err)
	default:
		return fmt.Errorf("ssh carrier %s: %w", r.label, err)
	}
}

// hostKeyCallback builds the host-key policy. There is deliberately no way to
// accept an unknown key: a carrier that did would hand the whole tunnel to
// whoever answered on that address.
func (cfg Config) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if cfg.HostKeyCallback != nil {
		return cfg.HostKeyCallback, nil
	}
	if len(cfg.KnownHosts) == 0 {
		return nil, fmt.Errorf("sshcarrier: no known_hosts configured; the carrier will not accept an unverified host key")
	}
	cb, err := knownhosts.New(cfg.KnownHosts...)
	if err != nil {
		return nil, fmt.Errorf("sshcarrier: reading known_hosts %v: %w", cfg.KnownHosts, err)
	}
	return cb, nil
}

// authMethods assembles the credentials to offer, agent first.
func (cfg Config) authMethods() ([]ssh.AuthMethod, error) {
	if len(cfg.authOverride) > 0 {
		return cfg.authOverride, nil
	}
	var auths []ssh.AuthMethod
	if cfg.Agent {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if c, err := net.Dial("unix", sock); err == nil {
				auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(c).Signers))
			}
		}
	}
	for _, path := range cfg.IdentityFiles {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("sshcarrier: reading identity %s: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("sshcarrier: parsing identity %s: %w", path, err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if len(auths) == 0 && cfg.Prompter == nil {
		return nil, fmt.Errorf("sshcarrier: no credentials configured (no agent, no identity files, no operator prompter)")
	}
	return auths, nil
}

func normalizeAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("sshcarrier: no address configured")
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr, nil
	}
	return net.JoinHostPort(addr, DefaultPort), nil
}

func orInt(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}
