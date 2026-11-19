package sshcarrier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-ccb/transport/sshcarrier/remotebin"
)

// DefaultRemoteDir is where a staged binary lands when none is configured. It
// is under the login account rather than /usr/local, because the whole point is
// a host where we have an account and nothing else.
const DefaultRemoteDir = "~/.cache/htc-ccb"

// Platform is a remote host's operating system and architecture, named the way
// Go names them, so a caller can pick the matching build.
type Platform struct {
	OS   string // "linux", "darwin"
	Arch string // "amd64", "arm64"
}

func (p Platform) String() string { return p.OS + "/" + p.Arch }

// DetectPlatform asks the far host what it is.
//
// `uname -s -m` is the one probe that answers on everything this would ever
// run on, long before anything of ours is installed -- which is the situation
// by definition.
func DetectPlatform(ctx context.Context, client *ssh.Client) (Platform, error) {
	out, err := runCommand(ctx, client, "uname -s -m")
	if err != nil {
		return Platform{}, fmt.Errorf("sshcarrier: detecting the remote platform: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) != 2 {
		return Platform{}, fmt.Errorf("sshcarrier: cannot read %q as a platform", strings.TrimSpace(out))
	}
	p := Platform{OS: normalizeOS(fields[0]), Arch: normalizeArch(fields[1])}
	if p.OS == "" || p.Arch == "" {
		return Platform{}, fmt.Errorf("sshcarrier: unsupported remote platform %q", strings.TrimSpace(out))
	}
	return p, nil
}

func normalizeOS(s string) string {
	switch strings.ToLower(s) {
	case "linux":
		return "linux"
	case "darwin":
		return "darwin"
	default:
		return ""
	}
}

func normalizeArch(s string) string {
	switch strings.ToLower(s) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return ""
	}
}

// StageConfig describes a zero-touch install.
type StageConfig struct {
	// Binary is the local file to put on the far host. It must be the build
	// for that host's platform; Stage refuses to send one that is not.
	//
	// Naming one file is the simple case: a single-architecture site, or a
	// test. A site with a mixed fleet names BinaryDir instead and lets the
	// detected platform choose.
	Binary string
	// BinaryDir holds per-platform builds named htc-ccb-<os>-<arch>, as the
	// release tarballs name them. Used when Binary is empty: the build is
	// chosen by what the far host reported, so one configuration serves an
	// amd64 login node and an arm64 one.
	//
	// With neither set, a binary compiled into this one is used if there is
	// one for that platform -- see the remotebin package, which carries them
	// only under the `embedremote` build tag.
	BinaryDir string
	// Platform is what the far host reported. Stage checks the local binary
	// against it rather than discovering a mismatch as "Exec format error"
	// minutes later.
	Platform Platform
	// LocalPlatform names what Binary was built for. Empty skips the check.
	LocalPlatform Platform
	// RemoteDir is where the binary goes; empty uses DefaultRemoteDir.
	RemoteDir string

	// CondorConfig is a local configuration file to stage beside the binary
	// and point the remote broker at.
	//
	// Without it the staged broker reads whatever configuration the far host
	// happens to have, which on a login node is either nothing or -- worse --
	// another pool's: its security settings, its trust domain, its token
	// directory. Staging one makes the remote broker depend on nothing it
	// found there.
	CondorConfig string

	Logger *slog.Logger
}

// StagedPaths is what a stage left on the far host.
type StagedPaths struct {
	Binary string
	// Config is empty when none was staged.
	Config string
}

// Stage puts the binary on the far host if it is not already there, and returns
// the path to run.
//
// The remote name contains the content hash, so a host that already has this
// exact build is left alone: reconnecting a hundred brokers does not move 22 MB
// a hundred times, and two brokers staging at once cannot write each other's
// file. The upload is to a temporary name and then renamed, so a half-written
// binary is never at the path anyone executes.
func Stage(ctx context.Context, client *ssh.Client, cfg StageConfig) (StagedPaths, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	body, source, err := resolveBinary(cfg)
	if err != nil {
		return StagedPaths{}, err
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	dir := cfg.RemoteDir
	if dir == "" {
		dir = DefaultRemoteDir
	}
	name := "htc-ccb-" + digest[:16]
	remote := path.Join(dir, name)

	if err := putFile(ctx, client, remote, body, log, "broker binary", cfg.Platform.String(), source); err != nil {
		return StagedPaths{}, err
	}
	out := StagedPaths{Binary: remote}

	if cfg.CondorConfig != "" {
		confBody, err := os.ReadFile(cfg.CondorConfig)
		if err != nil {
			return StagedPaths{}, fmt.Errorf("sshcarrier: reading %s: %w", cfg.CondorConfig, err)
		}
		confSum := sha256.Sum256(confBody)
		conf := path.Join(dir, "htc-ccb-"+hex.EncodeToString(confSum[:])[:16]+".conf")
		if err := putFile(ctx, client, conf, confBody, log, "configuration", "", cfg.CondorConfig); err != nil {
			return StagedPaths{}, err
		}
		out.Config = conf
	}
	return out, nil
}

// putFile stages one content-addressed file, skipping it when that exact
// content is already there.
func putFile(ctx context.Context, client *ssh.Client, remote string, body []byte, log *slog.Logger, what, platform, source string) error {
	present, err := alreadyStaged(ctx, client, remote, len(body))
	if err != nil {
		return err
	}
	if present {
		log.Debug("ssh carrier file already staged", "what", what, "path", remote, "bytes", len(body))
		return nil
	}
	log.Info("staging on the remote host", "what", what, "path", remote, "bytes", len(body), "platform", platform, "from", source)
	if err := upload(ctx, client, remote, body); err != nil {
		return err
	}
	// Confirm what landed, rather than trusting the upload: a truncated binary
	// would otherwise be discovered as a mystifying exec failure.
	ok, err := alreadyStaged(ctx, client, remote, len(body))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("sshcarrier: staged %s but it is not there with the expected size", remote)
	}
	return nil
}

// alreadyStaged reports whether the exact binary is in place. The name carries
// the content hash, so matching the size is enough to distinguish "this build"
// from "a truncated copy of this build".
func alreadyStaged(ctx context.Context, client *ssh.Client, remote string, size int) (bool, error) {
	cmd := fmt.Sprintf("test -x %s && wc -c < %s || true", shellQuote(remote), shellQuote(remote))
	out, err := runCommand(ctx, client, cmd)
	if err != nil {
		return false, fmt.Errorf("sshcarrier: probing %s: %w", remote, err)
	}
	got := strings.TrimSpace(out)
	if got == "" {
		return false, nil
	}
	n, err := strconv.Atoi(got)
	if err != nil {
		return false, nil
	}
	return n == size, nil
}

// upload writes the binary to a temporary name and renames it into place.
func upload(ctx context.Context, client *ssh.Client, remote string, body []byte) error {
	dir := path.Dir(remote)
	tmp := remote + ".tmp." + strconv.Itoa(os.Getpid())
	cmd := fmt.Sprintf("mkdir -p %s && cat > %s && chmod 0755 %s && mv -f %s %s",
		shellQuote(dir), shellQuote(tmp), shellQuote(tmp), shellQuote(tmp), shellQuote(remote))

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("sshcarrier: opening a staging session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	sess.Stdin = bytes.NewReader(body)
	var errOut bytes.Buffer
	sess.Stderr = &errOut

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("sshcarrier: staging the binary: %w (%s)", err, strings.TrimSpace(errOut.String()))
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runCommand runs one command and returns its stdout.
func runCommand(ctx context.Context, client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = sess.Close() }()
	var out, errOut bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errOut

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err := <-done:
		if err != nil {
			return out.String(), fmt.Errorf("%w (%s)", err, strings.TrimSpace(errOut.String()))
		}
		return out.String(), nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// shellQuote renders s as a single-quoted shell word.
//
// These commands do go through the remote login shell -- that is how ssh runs
// an exec request -- so every path has to be quoted. The paths here are built
// from a configured directory and a hash, but "it is not attacker-controlled
// today" is not a property worth relying on.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// resolveBinary picks the build to send and says where it came from.
//
// Three sources, in the order a site would mean them: a file named outright,
// a directory of per-platform builds chosen by what the host reported, and --
// only in a binary built with the `embedremote` tag -- a copy compiled into
// this one. The last exists so a single-file install has something to stage
// on a host it has never seen, which is the whole premise of zero touch.
func resolveBinary(cfg StageConfig) ([]byte, string, error) {
	if cfg.Binary != "" {
		// An explicitly named file is the caller's word for "this build": the
		// only check worth making is that it is not for the wrong machine,
		// which otherwise surfaces as "Exec format error" at the far end.
		if cfg.LocalPlatform != (Platform{}) && cfg.Platform != (Platform{}) && cfg.LocalPlatform != cfg.Platform {
			return nil, "", fmt.Errorf("sshcarrier: refusing to stage a %s binary on a %s host", cfg.LocalPlatform, cfg.Platform)
		}
		body, err := os.ReadFile(cfg.Binary)
		if err != nil {
			return nil, "", fmt.Errorf("sshcarrier: reading %s: %w", cfg.Binary, err)
		}
		return body, cfg.Binary, nil
	}
	if cfg.Platform == (Platform{}) {
		return nil, "", fmt.Errorf("sshcarrier: no binary named and the remote platform is unknown, so none can be chosen")
	}
	body, src, err := remotebin.Find(cfg.BinaryDir, cfg.Platform.OS, cfg.Platform.Arch)
	if err != nil {
		return nil, "", err
	}
	return body, src.String(), nil
}
