//go:build unix

package cmdcarrier

import (
	"os/exec"
	"syscall"
)

// isolateProcess puts the child in its own process group. Two reasons, both
// operational: a terminate aimed at the group reaches whatever ssh itself
// spawned (an askpass helper, a ProxyCommand), and a Ctrl-C in the terminal
// where the broker runs does not race us to kill the carrier.
func isolateProcess(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// signalGroup sends sig to the child's whole process group, falling back to the
// process alone if the group could not be addressed.
func signalGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if err := syscall.Kill(-pid, sig); err != nil {
		_ = syscall.Kill(pid, sig)
	}
}

func terminate(cmd *exec.Cmd) { signalGroup(cmd, syscall.SIGTERM) }
func kill(cmd *exec.Cmd)      { signalGroup(cmd, syscall.SIGKILL) }
