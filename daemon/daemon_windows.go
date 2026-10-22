//go:build windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func SetDetachedProcAttr(cmd *exec.Cmd) {
	// Detach background process from the current console window
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x08000008,
	}
}

func CheckProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	const da = syscall.PROCESS_QUERY_INFORMATION | syscall.SYNCHRONIZE
	h, err := syscall.OpenProcess(da, false, uint32(pid))
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_ACCESS_DENIED {
			return true
		}
		return false
	}
	defer syscall.CloseHandle(h)

	var exitCode uint32
	if err := syscall.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	const stillActive = 259
	if exitCode != stillActive {
		return false
	}
	wait, err := syscall.WaitForSingleObject(h, 0)
	if err != nil {
		return true
	}
	return wait == syscall.WAIT_TIMEOUT
}

func TerminateProcess(pid int) error {
	if pid <= 0 {
		return os.ErrProcessDone
	}
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	return syscall.TerminateProcess(h, 1)
}

func KillProcess(pid int) error {
	return TerminateProcess(pid)
}

func SignalProcess(_ int, _ syscall.Signal) error {
	return fmt.Errorf("signals are not supported on Windows")
}


