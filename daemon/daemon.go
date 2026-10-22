package daemon

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

func RoutewardenHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".routewarden"
	}
	return filepath.Join(home, ".routewarden")
}

func PIDPath(name string) string {
	return filepath.Join(RoutewardenHomeDir(), name+".pid")
}

func LogPath(name string) string {
	return filepath.Join(RoutewardenHomeDir(), name+".log")
}

func ReadPID(name string) (int, error) {
	data, err := os.ReadFile(PIDPath(name))
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

func WritePID(name string, pid int) error {
	dir := RoutewardenHomeDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(PIDPath(name), []byte(strconv.Itoa(pid)+"\n"), 0644)
}

func RemovePID(name string) {
	_ = os.Remove(PIDPath(name))
}

func SpawnDetached(name, displayName string, rawArgs []string, port int, url string) error {
	// 1. Check if already running
	if pid, err := ReadPID(name); err == nil {
		if CheckProcessAlive(pid) {
			fmt.Fprintf(os.Stderr, "⚠️  %s is already running in background (PID: %d).\n", displayName, pid)
			fmt.Fprintf(os.Stderr, "   Run 'rwarden %s stop' to terminate it before starting a new instance.\n", name)
			os.Exit(1)
		} else {
			// Stale PID file left behind by abnormal termination
			RemovePID(name)
		}
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

	logPath := LogPath(name)
	pidPath := PIDPath(name)

	if err := os.MkdirAll(RoutewardenHomeDir(), 0755); err != nil {
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
	SetDetachedProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start detached process: %w", err)
	}

	pid := cmd.Process.Pid
	if err := WritePID(name, pid); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: failed to record PID to %s: %v\n", pidPath, err)
	}

	// Give child a brief moment to verify startup
	time.Sleep(150 * time.Millisecond)
	if !CheckProcessAlive(pid) {
		fmt.Fprintf(os.Stderr, "❌ %s failed to start. Check logs at %s\n", displayName, logPath)
		RemovePID(name)
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

	os.Exit(0)
	return nil
}

func Stop(name, displayName string) (bool, error) {
	pid, err := ReadPID(name)
	stoppedAny := false

	if err == nil && pid > 0 {
		if CheckProcessAlive(pid) {
			_ = TerminateProcess(pid)

			// Wait up to 3 seconds for graceful shutdown
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if !CheckProcessAlive(pid) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			// Force kill if process didn't terminate gracefully
			if CheckProcessAlive(pid) {
				_ = KillProcess(pid)
			}
			fmt.Printf("✅ %s stopped (PID: %d)\n", displayName, pid)
			stoppedAny = true
		}
		RemovePID(name)
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

func Status(name, displayName string) bool {
	pid, err := ReadPID(name)
	isRunning := false
	if err == nil && pid > 0 {
		if CheckProcessAlive(pid) {
			isRunning = true
			logPath := LogPath(name)
			pidPath := PIDPath(name)
			fmt.Printf("🟢 %s is running (detached process)\n", displayName)
			fmt.Printf("   PID:      %d\n", pid)
			fmt.Printf("   Logs:     %s\n", logPath)
			fmt.Printf("   PID File: %s\n", pidPath)
		} else {
			// Stale PID file
			RemovePID(name)
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

func GlobalStatus(args []string) {
	if len(args) > 0 {
		arg := strings.ToLower(args[0])
		if arg == "-h" || arg == "--help" || arg == "help" {
			fmt.Println("Usage: rwarden status [dashboard|push|tcp|all]")
			return
		}
	}

	target := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target = strings.ToLower(args[0])
	}

	switch target {
	case "dashboard":
		Status("dashboard", "RouteWarden Dashboard")
	case "push", "agent", "shipper":
		Status("push", "RouteWarden Remote Shipper")
	case "tcp", "proxy", "tcp-warden":
		Status("tcp", "RouteWarden TCP Proxy")
	case "", "all":
		fmt.Println("RouteWarden Background Services:")
		fmt.Println("─────────────────────────────────────────────────────────────")
		Status("dashboard", "Dashboard")
		fmt.Println()
		Status("push", "Remote Shipper")
		fmt.Println()
		Status("tcp", "TCP Proxy")
		fmt.Println("─────────────────────────────────────────────────────────────")
	default:
		fmt.Fprintf(os.Stderr, "Unknown service %q. Available services: dashboard, push, tcp, all\n", target)
		os.Exit(1)
	}
}

func GlobalStop(args []string) {
	if len(args) > 0 {
		arg := strings.ToLower(args[0])
		if arg == "-h" || arg == "--help" || arg == "help" {
			fmt.Println("Usage: rwarden stop [dashboard|push|tcp|all]")
			return
		}
	}

	target := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target = strings.ToLower(args[0])
	}

	switch target {
	case "dashboard":
		_, _ = Stop("dashboard", "RouteWarden Dashboard")
	case "push", "agent", "shipper":
		_, _ = Stop("push", "RouteWarden Remote Shipper")
	case "tcp", "proxy", "tcp-warden":
		_, _ = Stop("tcp", "RouteWarden TCP Proxy")
	case "", "all":
		fmt.Println("Stopping RouteWarden Background Services...")
		fmt.Println("─────────────────────────────────────────────────────────────")
		_, _ = Stop("dashboard", "Dashboard")
		_, _ = Stop("push", "Remote Shipper")
		_, _ = Stop("tcp", "TCP Proxy")
		fmt.Println("─────────────────────────────────────────────────────────────")
	default:
		fmt.Fprintf(os.Stderr, "Unknown service %q. Available services: dashboard, push, tcp, all\n", target)
		os.Exit(1)
	}
}
