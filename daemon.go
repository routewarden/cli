package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func routewardenHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".routewarden"
	}
	return filepath.Join(home, ".routewarden")
}

func daemonPIDPath(name string) string {
	return filepath.Join(routewardenHomeDir(), name+".pid")
}

func daemonLogPath(name string) string {
	return filepath.Join(routewardenHomeDir(), name+".log")
}

func readPID(name string) (int, error) {
	data, err := os.ReadFile(daemonPIDPath(name))
	if err != nil {
		return 0, err
	}
	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func writePID(name string, pid int) error {
	dir := routewardenHomeDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(daemonPIDPath(name), []byte(strconv.Itoa(pid)+"\n"), 0644)
}

func removePID(name string) {
	_ = os.Remove(daemonPIDPath(name))
}

func spawnDetached(name, displayName string, rawArgs []string, port int, url string) error {
	// 1. Check if already running
	if pid, err := readPID(name); err == nil {
		if checkProcessAlive(pid) {
			fmt.Fprintf(os.Stderr, "⚠️  %s is already running in background (PID: %d).\n", displayName, pid)
			fmt.Fprintf(os.Stderr, "   Run 'rwarden %s stop' to terminate it before starting a new instance.\n", name)
			os.Exit(1)
		}
		// Clean up stale PID file left from dead process
		removePID(name)
	}

	execPath, err := os.Executable()
	if err != nil {
		execPath = os.Args[0]
	}

	// Filter out --detach and -d flags from args so child doesn't detach again
	var childArgs []string
	for _, arg := range rawArgs {
		if arg == "--detach" || arg == "-d" {
			continue
		}
		if strings.HasPrefix(arg, "--detach=") || strings.HasPrefix(arg, "-d=") {
			continue
		}
		childArgs = append(childArgs, arg)
	}

	// For dashboard, ensure --no-open is passed so background daemon doesn't pop up browser
	if name == "dashboard" {
		hasNoOpen := false
		for _, arg := range childArgs {
			if arg == "--no-open" {
				hasNoOpen = true
				break
			}
		}
		if !hasNoOpen {
			childArgs = append(childArgs, "--no-open")
		}
	}

	logPath := daemonLogPath(name)
	pidPath := daemonPIDPath(name)

	if err := os.MkdirAll(routewardenHomeDir(), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command(execPath, childArgs...)
	cmd.Env = append(os.Environ(), "_RW_DETACHED=1")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	setDetachedProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start detached process: %w", err)
	}

	pid := cmd.Process.Pid
	if err := writePID(name, pid); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: failed to record PID to %s: %v\n", pidPath, err)
	}

	// Give child a brief moment to verify startup
	time.Sleep(150 * time.Millisecond)
	if !checkProcessAlive(pid) {
		fmt.Fprintf(os.Stderr, "❌ %s failed to start. Check logs at %s\n", displayName, logPath)
		removePID(name)
		os.Exit(1)
	}

	fmt.Printf("🚀 %s started in detached mode\n", displayName)
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("  PID:       %d\n", pid)
	if url != "" {
		fmt.Printf("  URL:       %s\n", url)
	}
	fmt.Printf("  Logs:      %s\n", logPath)
	fmt.Printf("  PID File:  %s\n", pidPath)
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("  View logs:   tail -f %s\n", logPath)
	fmt.Printf("  Status:      rwarden %s status\n", name)
	fmt.Printf("  Stop:        rwarden %s stop\n", name)

	// Detached parent process terminates cleanly after launching child process; return nil satisfies compiler
	os.Exit(0)
	return nil
}

func stopDaemon(name, displayName string) (bool, error) {
	pid, err := readPID(name)
	stoppedAny := false

	if err == nil && pid > 0 {
		if checkProcessAlive(pid) {
			_ = terminateProcess(pid)

			// Wait up to 3 seconds for graceful shutdown
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if !checkProcessAlive(pid) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			// Force kill if process didn't terminate gracefully
			if checkProcessAlive(pid) {
				_ = killProcess(pid)
			}
			fmt.Printf("✅ %s stopped (PID: %d)\n", displayName, pid)
			stoppedAny = true
		}
		removePID(name)
	}

	// If dashboard, also check if Docker container was running
	if name == "dashboard" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=routewarden-dashboard", "--format", "{{.ID}}")
		if out, err := cmd.Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			_ = exec.CommandContext(ctx, "docker", "rm", "-f", "routewarden-dashboard").Run()
			fmt.Println("✅ RouteWarden Dashboard Docker container stopped.")
			stoppedAny = true
		}
	}

	if !stoppedAny {
		fmt.Printf("ℹ️  %s is not currently running.\n", displayName)
	}

	return stoppedAny, nil
}

func checkDaemonStatus(name, displayName string) bool {
	pid, err := readPID(name)
	isRunning := false
	if err == nil && pid > 0 {
		if checkProcessAlive(pid) {
			isRunning = true
			logPath := daemonLogPath(name)
			pidPath := daemonPIDPath(name)
			fmt.Printf("🟢 %s is running (detached process)\n", displayName)
			fmt.Printf("   PID:      %d\n", pid)
			fmt.Printf("   Logs:     %s\n", logPath)
			fmt.Printf("   PID File: %s\n", pidPath)
		} else {
			// Stale PID file
			removePID(name)
		}
	}

	if name == "dashboard" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=routewarden-dashboard", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}").Output()
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			fmt.Printf("🟢 RouteWarden Dashboard is running in Docker:\n   %s\n", strings.TrimSpace(string(out)))
			isRunning = true
		}
	}

	if !isRunning {
		fmt.Printf("🔴 %s is not running.\n", displayName)
	}

	return isRunning
}

func handleGlobalStatus(args []string) {
	target := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target = strings.ToLower(args[0])
	}

	switch target {
	case "dashboard":
		checkDaemonStatus("dashboard", "RouteWarden Dashboard")
	case "push", "agent":
		checkDaemonStatus("push", "RouteWarden Remote Shipper")
	default:
		fmt.Println("RouteWarden Background Services:")
		fmt.Println("─────────────────────────────────────────────────────────────")
		checkDaemonStatus("dashboard", "Dashboard")
		fmt.Println()
		checkDaemonStatus("push", "Remote Shipper")
		fmt.Println("─────────────────────────────────────────────────────────────")
	}
}

func handleGlobalStop(args []string) {
	target := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target = strings.ToLower(args[0])
	}

	switch target {
	case "dashboard":
		_, _ = stopDaemon("dashboard", "RouteWarden Dashboard")
	case "push", "agent":
		_, _ = stopDaemon("push", "RouteWarden Remote Shipper")
	default:
		fmt.Println("Stopping RouteWarden Background Services...")
		fmt.Println("─────────────────────────────────────────────────────────────")
		_, _ = stopDaemon("dashboard", "Dashboard")
		_, _ = stopDaemon("push", "Remote Shipper")
		fmt.Println("─────────────────────────────────────────────────────────────")
	}
}
