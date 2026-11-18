package cmdcarrier

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultStderrLines is how many of the child's most recent stderr lines are
	// kept to explain a carrier that died. ssh says why it failed in one or two
	// lines ("Permission denied (publickey)."), usually after a banner.
	DefaultStderrLines = 20
	// DefaultStderrLineLimit caps one retained line, so a child that writes a
	// megabyte without a newline cannot grow the buffer.
	DefaultStderrLineLimit = 4 << 10
	// DefaultTerminateGrace is how long a closing carrier waits after SIGTERM
	// before SIGKILL. Closing the pipes already gives the child EOF on stdin, so
	// a well-behaved ssh is gone well inside this.
	DefaultTerminateGrace = 2 * time.Second
	// exitReportGrace is how long an I/O error waits for the child's exit status
	// before reporting without it. The child has normally already exited -- that
	// is why the read failed -- so this is a race margin, not a timeout.
	exitReportGrace = time.Second
)

// DialConfig describes the child process whose stdin and stdout are the carrier
// pipe.
type DialConfig struct {
	// Argv is the command and its arguments, already split. ParseArgv produces
	// one from a configured string; the command is executed directly and never
	// through a shell.
	//
	// Argv[0] is resolved against PATH when it names no directory. On a broker
	// running as root that makes PATH part of a security decision, so an
	// absolute path is preferred and the resolved path is logged either way.
	Argv []string

	// Dir is the child's working directory; empty means the broker's own.
	Dir string

	// Env is the child's environment. Nil inherits the broker's, which is what
	// lets ssh find HOME (for ~/.ssh/config), SSH_AUTH_SOCK and KRB5CCNAME.
	Env []string

	// Logger receives the child's stderr as it arrives, at debug level -- ssh is
	// chatty in normal operation ("Warning: Permanently added ..."), so steady
	// state stays quiet while the lines remain available. The most recent lines
	// are also retained and attached to the error when the pipe dies.
	Logger *slog.Logger

	// Label names the carrier in logs and errors; empty derives one from Argv.
	Label string

	// StderrLines overrides DefaultStderrLines.
	StderrLines int

	// TerminateGrace overrides DefaultTerminateGrace.
	TerminateGrace time.Duration
}

// Diagnostics is implemented by the net.Conn Dial returns. The staged carrier
// check uses it to report *why* a carrier command failed, which for ssh is
// something only the child's stderr knows.
type Diagnostics interface {
	// Stderr returns the child's most recent stderr lines, oldest first,
	// joined by "; ". Empty when it has written none.
	Stderr() string
	// Exited reports the child's exit error (nil for a clean exit) and whether
	// it has exited at all.
	Exited() (error, bool)
	// Program is the absolute path actually executed.
	Program() string
}

// Dial spawns the configured command and returns its stdin/stdout as a carrier
// byte pipe.
//
// ctx bounds starting the child, not its life: the returned pipe outlives ctx
// and is torn down by Close, matching the carrier contract (a pipe is
// established once and then carries every logical connection).
//
// Starting the child is not the same as the carrier working. ssh takes seconds
// to authenticate and, when it fails, says so on stderr and exits -- which
// reaches the caller as a read error from the pipe, carrying the exit status and
// those stderr lines. The staged carrier check turns that into a report before
// anything depends on the carrier.
func Dial(ctx context.Context, cfg DialConfig) (net.Conn, error) {
	if len(cfg.Argv) == 0 {
		return nil, errors.New("cmdcarrier: no command configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prog, err := resolveProgram(cfg.Argv[0])
	if err != nil {
		return nil, err
	}
	label := cfg.Label
	if label == "" {
		label = describeArgv(cfg.Argv)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	log = log.With("carrier", label, "program", prog)

	// Our halves come from os.Pipe rather than cmd.StdinPipe, which hands back
	// an io.WriteCloser that is not an *os.File -- and the *os.File is what
	// carries working deadlines and lets os/exec hand the descriptor straight to
	// the child instead of running a copying goroutine.
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("cmdcarrier: stdin pipe: %w", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW)
		return nil, fmt.Errorf("cmdcarrier: stdout pipe: %w", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW, outR, outW)
		return nil, fmt.Errorf("cmdcarrier: stderr pipe: %w", err)
	}

	cmd := exec.Command(prog, cfg.Argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	cmd.Dir = cfg.Dir
	cmd.Env = cfg.Env
	isolateProcess(cmd)

	if err := cmd.Start(); err != nil {
		closeAll(inR, inW, outR, outW, errR, errW)
		return nil, fmt.Errorf("cmdcarrier: starting %s: %w", label, err)
	}
	// The child owns these now; holding them open in the broker would keep the
	// pipe from ever reporting EOF when the child exits.
	closeAll(inR, outW, errW)

	p := &process{
		cmd:    cmd,
		label:  label,
		prog:   prog,
		grace:  orDuration(cfg.TerminateGrace, DefaultTerminateGrace),
		waited: make(chan struct{}),
		tail:   newTail(orInt(cfg.StderrLines, DefaultStderrLines)),
		log:    log,
	}
	go p.drainStderr(errR)
	go p.reap()

	log.Debug("carrier command started", "pid", cmd.Process.Pid)

	return &cmdConn{
		pipeConn: pipeConn{
			rf:       outR,
			wf:       inW,
			addr:     pipeAddr{network: "cmd", label: label},
			onClose:  p.shutdown,
			annotate: p.annotate,
		},
		proc: p,
	}, nil
}

// cmdConn is a pipe backed by a child process, exposing Diagnostics.
type cmdConn struct {
	pipeConn
	proc *process
}

func (c *cmdConn) Stderr() string        { return c.proc.tail.String() }
func (c *cmdConn) Exited() (error, bool) { return c.proc.exited() }
func (c *cmdConn) Program() string       { return c.proc.prog }

// process owns the child: its exit status, its stderr, and its teardown.
type process struct {
	cmd   *exec.Cmd
	label string
	prog  string
	grace time.Duration
	log   *slog.Logger
	tail  *tail

	waited  chan struct{} // closed once Wait has returned
	mu      sync.Mutex
	exitErr error
}

func (p *process) reap() {
	err := p.cmd.Wait()
	p.mu.Lock()
	p.exitErr = err
	p.mu.Unlock()
	close(p.waited)
}

func (p *process) exited() (error, bool) {
	select {
	case <-p.waited:
	default:
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitErr, true
}

func (p *process) drainStderr(r *os.File) {
	defer func() { _ = r.Close() }()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), DefaultStderrLineLimit)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		p.tail.add(line)
		p.log.Debug("carrier command stderr", "line", line)
	}
}

// annotate explains an I/O error on the pipe. A carrier command that failed to
// connect shows up as a bare EOF, and the reason is in the child's exit status
// and its last stderr lines -- which is the whole diagnosis for ssh.
//
// Both the I/O error and the child's exit status are wrapped (fmt.Errorf takes
// more than one %w since Go 1.20), so a caller can still recognize the
// underlying io.EOF AND reach the *exec.ExitError for the exit code, rather
// than having to scrape either out of the message.
func (p *process) annotate(err error) error {
	select {
	case <-p.waited:
	case <-time.After(exitReportGrace):
	}
	exitErr, exited := p.exited()
	detail := p.tail.String()

	switch {
	case exited && exitErr != nil && detail != "":
		return fmt.Errorf("carrier command %s exited (%w); its last output was: %s: %w", p.label, exitErr, detail, err)
	case exited && exitErr != nil:
		return fmt.Errorf("carrier command %s exited (%w) without explaining why; run it by hand to see what it reports: %w", p.label, exitErr, err)
	case exited && detail != "":
		return fmt.Errorf("carrier command %s exited cleanly, closing the carrier; its last output was: %s: %w", p.label, detail, err)
	case exited:
		return fmt.Errorf("carrier command %s exited cleanly, closing the carrier: %w", p.label, err)
	case detail != "":
		return fmt.Errorf("carrier command %s is still running; its last output was: %s: %w", p.label, detail, err)
	default:
		return fmt.Errorf("carrier command %s: %w", p.label, err)
	}
}

// shutdown stops the child. The pipes are already closed by the time this runs,
// so the child has EOF on stdin and a well-behaved one is leaving anyway; the
// signals are for one that is not.
func (p *process) shutdown() error {
	select {
	case <-p.waited:
		return nil
	default:
	}
	terminate(p.cmd)
	select {
	case <-p.waited:
		return nil
	case <-time.After(p.grace):
	}
	p.log.Warn("carrier command did not exit on SIGTERM; killing", "grace", p.grace)
	kill(p.cmd)
	select {
	case <-p.waited:
	case <-time.After(p.grace):
		// Unkillable (uninterruptible sleep, most likely a hung network
		// filesystem). Report it rather than blocking the broker's teardown on
		// a process the kernel will not let go of.
		p.log.Error("carrier command survived SIGKILL; abandoning it", "pid", p.cmd.Process.Pid)
		return fmt.Errorf("cmdcarrier: %s (pid %d) did not exit", p.label, p.cmd.Process.Pid)
	}
	return nil
}

// tail retains the most recent stderr lines.
type tail struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newTail(max int) *tail { return &tail{max: max} }

func (t *tail) add(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, s)
	if len(t.lines) > t.max {
		t.lines = t.lines[len(t.lines)-t.max:]
	}
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.lines, "; ")
}

// resolveProgram turns argv[0] into the path to execute.
func resolveProgram(name string) (string, error) {
	if strings.ContainsRune(name, filepath.Separator) {
		if !filepath.IsAbs(name) {
			return "", fmt.Errorf("cmdcarrier: %q is a relative path; give an absolute one, since the broker's working directory is not a stable base", name)
		}
		return name, nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("cmdcarrier: %q not found on PATH: %w", name, err)
	}
	return path, nil
}

// describeArgv renders an argv compactly for a log line.
func describeArgv(argv []string) string {
	s := strings.Join(argv, " ")
	const max = 120
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return `"` + s + `"`
}

func closeAll(fs ...*os.File) {
	for _, f := range fs {
		if f != nil {
			_ = f.Close()
		}
	}
}

func orDuration(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func orInt(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}

var _ Diagnostics = (*cmdConn)(nil)
var _ net.Conn = (*cmdConn)(nil)
var _ io.ReadWriteCloser = (*cmdConn)(nil)
