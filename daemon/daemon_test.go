package daemon

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDaemon_PIDOperations(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	svcName := "daemon-test-service"

	// 1. Non-existent PID
	_, err := ReadPID(svcName)
	if err == nil {
		t.Fatalf("expected error reading non-existent PID, got nil")
	}

	// 2. Write PID
	testPID := 88888
	if err := WritePID(svcName, testPID); err != nil {
		t.Fatalf("failed to write PID: %v", err)
	}

	// 3. Read PID
	gotPID, err := ReadPID(svcName)
	if err != nil {
		t.Fatalf("failed to read PID: %v", err)
	}
	if gotPID != testPID {
		t.Fatalf("expected PID %d, got %d", testPID, gotPID)
	}

	// Verify paths
	expectedPID := filepath.Join(tempHome, ".routewarden", svcName+".pid")
	if PIDPath(svcName) != expectedPID {
		t.Errorf("expected PID path %s, got %s", expectedPID, PIDPath(svcName))
	}
	expectedLog := filepath.Join(tempHome, ".routewarden", svcName+".log")
	if LogPath(svcName) != expectedLog {
		t.Errorf("expected log path %s, got %s", expectedLog, LogPath(svcName))
	}

	// 4. Remove PID
	RemovePID(svcName)
	if _, err := ReadPID(svcName); err == nil {
		t.Fatalf("expected error after removing PID, got nil")
	}
}

func TestDaemon_Status_NotRunning(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	running := Status("not-running-daemon", "Test Daemon")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if running {
		t.Errorf("expected Status to return false")
	}
	if !strings.Contains(out, "🔴 Test Daemon is not running.") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestDaemon_Stop_NotRunning(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	stopped, err := Stop("not-running-daemon", "Test Daemon")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stopped {
		t.Errorf("expected stopped to be false")
	}
	if !strings.Contains(out, "is not currently running") {
		t.Errorf("expected not running message, got: %s", out)
	}
}

func TestDaemon_Stop_RunningProcess(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip("skipping sleep test:", err)
	}
	pid := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
	}()

	if err := WritePID("sleep-daemon", pid); err != nil {
		t.Fatalf("failed to write PID: %v", err)
	}

	running := Status("sleep-daemon", "Sleep Daemon")
	if !running {
		t.Errorf("expected status to report running")
	}

	stopped, err := Stop("sleep-daemon", "Sleep Daemon")
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if !stopped {
		t.Errorf("expected Stop to return true")
	}

	_ = cmd.Wait()

	if CheckProcessAlive(pid) {
		t.Errorf("expected process %d to be dead", pid)
	}

	if _, err := ReadPID("sleep-daemon"); err == nil {
		t.Errorf("expected PID file to be cleaned up")
	}
}

func TestDaemon_GlobalStatusAndStop(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	// Capture output of GlobalStatus
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	GlobalStatus([]string{})

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "RouteWarden Background Services") {
		t.Errorf("expected header in GlobalStatus, got: %s", out)
	}

	// Capture output of GlobalStop
	r2, w2, _ := os.Pipe()
	os.Stdout = w2

	GlobalStop([]string{})

	_ = w2.Close()
	os.Stdout = oldStdout

	var buf2 bytes.Buffer
	_, _ = io.Copy(&buf2, r2)
	stopOut := buf2.String()

	if !strings.Contains(stopOut, "Stopping RouteWarden Background Services") {
		t.Errorf("expected stopping header, got: %s", stopOut)
	}

	// Test arguments: help and specific daemons
	GlobalStatus([]string{"dashboard"})
	GlobalStatus([]string{"push"})
	GlobalStatus([]string{"tcp"})
	GlobalStatus([]string{"--help"})
	GlobalStop([]string{"--help"})
	GlobalStop([]string{"tcp"})
}

func TestDaemon_StalePIDCleanup(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	stalePID := 999999
	_ = WritePID("stale-daemon", stalePID)

	Status("stale-daemon", "Stale Daemon")

	if _, err := ReadPID("stale-daemon"); err == nil {
		t.Errorf("expected stale PID file to be deleted")
	}
}
