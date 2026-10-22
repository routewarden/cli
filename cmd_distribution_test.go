package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdShipperDistribution_BuildAndHelp(t *testing.T) {
	tmpDir := t.TempDir()
	shipperBin := filepath.Join(tmpDir, "rwarden-shipper")

	// 1. Build cmd/shipper
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", shipperBin, "./cmd/shipper")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build ./cmd/shipper: %v\nOutput: %s", err, string(out))
	}

	// 2. Verify binary size is lean (< 8 MB, whereas full CLI is ~12-18 MB)
	fi, err := os.Stat(shipperBin)
	if err != nil {
		t.Fatalf("failed to stat shipper binary: %v", err)
	}
	sizeMB := float64(fi.Size()) / (1024 * 1024)
	if sizeMB > 8.0 {
		t.Errorf("expected lean shipper binary (< 8MB), got %.2f MB", sizeMB)
	}

	// 3. Test running --help
	helpCmd := exec.Command(shipperBin, "--help")
	helpOut, err := helpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shipper --help failed: %v", err)
	}
	helpStr := string(helpOut)
	if !strings.Contains(helpStr, "RouteWarden Shipper") {
		t.Errorf("expected 'RouteWarden Shipper' in help, got: %s", helpStr)
	}
	if !strings.Contains(helpStr, "push") || !strings.Contains(helpStr, "register") {
		t.Errorf("expected 'push' and 'register' commands in help, got: %s", helpStr)
	}

	// 4. Test running version
	verCmd := exec.Command(shipperBin, "version")
	verOut, err := verCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shipper version failed: %v", err)
	}
	if !strings.Contains(string(verOut), "rwarden-shipper version") {
		t.Errorf("unexpected version output: %s", string(verOut))
	}
}

func TestCmdDashboardDistribution_BuildAndHelp(t *testing.T) {
	tmpDir := t.TempDir()
	dashBin := filepath.Join(tmpDir, "rwarden-dashboard")

	// 1. Build cmd/dashboard
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", dashBin, "./cmd/dashboard")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build ./cmd/dashboard: %v\nOutput: %s", err, string(out))
	}

	// 2. Test running --help
	helpCmd := exec.Command(dashBin, "--help")
	helpOut, err := helpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dashboard --help failed: %v", err)
	}
	helpStr := string(helpOut)
	if !strings.Contains(helpStr, "RouteWarden Dashboard") {
		t.Errorf("expected 'RouteWarden Dashboard' in help, got: %s", helpStr)
	}
	if !strings.Contains(helpStr, "keys") || !strings.Contains(helpStr, "export") {
		t.Errorf("expected 'keys' and 'export' commands in help, got: %s", helpStr)
	}

	// 3. Test running version
	verCmd := exec.Command(dashBin, "version")
	verOut, err := verCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dashboard version failed: %v", err)
	}
	if !strings.Contains(string(verOut), "rwarden-dashboard version") {
		t.Errorf("unexpected version output: %s", string(verOut))
	}
}

func TestCmdTCPWardenDistribution_BuildAndHelp(t *testing.T) {
	tmpDir := t.TempDir()
	tcpBin := filepath.Join(tmpDir, "tcp-warden")

	// 1. Build cmd/tcp-warden
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", tcpBin, "./cmd/tcp-warden")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build ./cmd/tcp-warden: %v\nOutput: %s", err, string(out))
	}

	// 2. Test running --help
	helpCmd := exec.Command(tcpBin, "--help")
	helpOut, err := helpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tcp-warden --help failed: %v", err)
	}
	helpStr := string(helpOut)
	if !strings.Contains(helpStr, "TCP Warden") {
		t.Errorf("expected 'TCP Warden' in help, got: %s", helpStr)
	}
	if !strings.Contains(helpStr, "run") || !strings.Contains(helpStr, "validate") || !strings.Contains(helpStr, "plugins") {
		t.Errorf("expected 'run', 'validate', 'plugins' in help, got: %s", helpStr)
	}

	// 3. Test running version
	verCmd := exec.Command(tcpBin, "version")
	verOut, err := verCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tcp-warden version failed: %v", err)
	}
	if !strings.Contains(string(verOut), "tcp-warden version") {
		t.Errorf("unexpected version output: %s", string(verOut))
	}
}
