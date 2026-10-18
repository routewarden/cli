//go:build windows

package daemon

import (
	"os"
	"os/exec"
)

func SetDetachedProcAttr(cmd *exec.Cmd) {
	// On Windows, detachment is handled via default process creation flags
}

func CheckProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc != nil
}

func TerminateProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

func KillProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
