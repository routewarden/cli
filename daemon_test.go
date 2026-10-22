package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPIDFileOperations(t *testing.T) {
	tempHome := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tempHome)
	defer func() {
		_ = os.Setenv("HOME", origHome)
	}()

	svcName := "test-service"

	// 1. Initially reading non-existent PID file should error
	_, err := readPID(svcName)
	if err == nil {
		t.Fatalf("expected error reading non-existent PID, got nil")
	}

	// 2. Write PID
	testPID := 99999
	if err := writePID(svcName, testPID); err != nil {
		t.Fatalf("failed to write PID: %v", err)
	}

	// 3. Verify read PID matches
	gotPID, err := readPID(svcName)
	if err != nil {
		t.Fatalf("failed to read PID: %v", err)
	}
	if gotPID != testPID {
		t.Fatalf("expected PID %d, got %d", testPID, gotPID)
	}

	// Verify PID path
	expectedPath := filepath.Join(tempHome, ".routewarden", svcName+".pid")
	if daemonPIDPath(svcName) != expectedPath {
		t.Errorf("expected PID path %s, got %s", expectedPath, daemonPIDPath(svcName))
	}

	// Verify log path
	expectedLogPath := filepath.Join(tempHome, ".routewarden", svcName+".log")
	if daemonLogPath(svcName) != expectedLogPath {
		t.Errorf("expected log path %s, got %s", expectedLogPath, daemonLogPath(svcName))
	}

	// 4. Remove PID
	removePID(svcName)
	if _, err := readPID(svcName); err == nil {
		t.Fatalf("expected error after removing PID, got nil")
	}
}

func TestCheckDaemonStatus_NotRunning(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	running := checkDaemonStatus("test-daemon", "Test Daemon")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if running {
		t.Errorf("expected running to be false")
	}
	if !strings.Contains(output, "🔴 Test Daemon is not running.") {
		t.Errorf("unexpected output: %s", output)
	}
}

func TestStopDaemon_NotRunning(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	stopped, err := stopDaemon("test-daemon", "Test Daemon")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stopped {
		t.Errorf("expected stopped to be false")
	}
	if !strings.Contains(output, "is not currently running") {
		t.Errorf("expected 'is not currently running' in output, got: %s", output)
	}
}

func TestStopDaemon_RunningProcess(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	// Start a mock long-running process (sleep 30)
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip("skipping sleep test:", err)
	}
	pid := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
	}()

	// Write PID file
	if err := writePID("mock-sleep", pid); err != nil {
		t.Fatalf("failed to write pid: %v", err)
	}

	// Verify status reports running
	running := checkDaemonStatus("mock-sleep", "Mock Sleep")
	if !running {
		t.Errorf("expected mock sleep to report running")
	}

	// Now stop daemon
	stopped, err := stopDaemon("mock-sleep", "Mock Sleep")
	if err != nil {
		t.Fatalf("stopDaemon error: %v", err)
	}
	if !stopped {
		t.Errorf("expected stopDaemon to report stopped true")
	}

	// Wait for process to exit and reap it (in Unix, child processes become zombies until reaped)
	_ = cmd.Wait()

	if checkProcessAlive(pid) {
		t.Errorf("expected process %d to be terminated", pid)
	}

	// Verify PID file was removed
	if _, err := readPID("mock-sleep"); err == nil {
		t.Errorf("expected PID file to be removed after stopping")
	}
}

func TestDashboardFlags_Detach(t *testing.T) {
	// Test --detach and -d flags parsing for dashboard
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	detach := fs.Bool("detach", false, "Run in detached mode")
	fs.BoolVar(detach, "d", false, "Alias for --detach")

	// Case 1: --detach
	if err := fs.Parse([]string{"--detach"}); err != nil {
		t.Fatalf("failed to parse --detach: %v", err)
	}
	if !*detach {
		t.Errorf("expected detach to be true with --detach")
	}

	// Case 2: -d
	fs2 := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	detach2 := fs2.Bool("detach", false, "Run in detached mode")
	fs2.BoolVar(detach2, "d", false, "Alias for --detach")
	if err := fs2.Parse([]string{"-d"}); err != nil {
		t.Fatalf("failed to parse -d: %v", err)
	}
	if !*detach2 {
		t.Errorf("expected detach to be true with -d")
	}
}

func TestPushFlags_Detach(t *testing.T) {
	// Test --detach and -d flags parsing for push
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	dockerMode := fs.Bool("docker", false, "Docker discovery")
	detachMode := fs.Bool("detach", false, "Run in detached mode")
	fs.BoolVar(detachMode, "d", false, "Alias for --detach")

	// Case 1: -d
	if err := fs.Parse([]string{"-d"}); err != nil {
		t.Fatalf("failed to parse -d: %v", err)
	}
	if !*detachMode {
		t.Errorf("expected detachMode to be true with -d")
	}
	if *dockerMode {
		t.Errorf("dockerMode should be false when -d is passed")
	}

	// Case 2: --detach --docker
	fs2 := flag.NewFlagSet("push", flag.ContinueOnError)
	dockerMode2 := fs2.Bool("docker", false, "Docker discovery")
	detachMode2 := fs2.Bool("detach", false, "Run in detached mode")
	fs2.BoolVar(detachMode2, "d", false, "Alias for --detach")
	if err := fs2.Parse([]string{"--detach", "--docker"}); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}
	if !*detachMode2 {
		t.Errorf("expected detachMode2 to be true")
	}
	if !*dockerMode2 {
		t.Errorf("expected dockerMode2 to be true")
	}
}

func TestGlobalStatusAndStopDispatch(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	// Capture output of handleGlobalStatus
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleGlobalStatus([]string{})

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "RouteWarden Background Services") {
		t.Errorf("expected header in global status output, got: %s", output)
	}
	if !strings.Contains(output, "Dashboard") || !strings.Contains(output, "Remote Shipper") || !strings.Contains(output, "TCP Proxy") {
		t.Errorf("expected services listed in global status, got: %s", output)
	}

	// Capture output of handleGlobalStop
	r2, w2, _ := os.Pipe()
	os.Stdout = w2

	handleGlobalStop([]string{})

	_ = w2.Close()
	os.Stdout = oldStdout

	var buf2 bytes.Buffer
	_, _ = io.Copy(&buf2, r2)
	stopOutput := buf2.String()

	if !strings.Contains(stopOutput, "Stopping RouteWarden Background Services") {
		t.Errorf("expected stopping header, got: %s", stopOutput)
	}

	// Test targeting specific daemon and help flag
	handleGlobalStatus([]string{"tcp"})
	handleGlobalStatus([]string{"--help"})
	handleGlobalStop([]string{"--help"})
	handleGlobalStop([]string{"all"})
}

func TestStalePIDCleanup(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	// Write non-existent PID (e.g. 999999)
	stalePID := 999999
	_ = writePID("stale-test", stalePID)

	// checkDaemonStatus should detect it's not alive and clean up stale PID file
	checkDaemonStatus("stale-test", "Stale Test")

	if _, err := readPID("stale-test"); err == nil {
		t.Errorf("expected stale PID file to be cleaned up")
	}
}
