package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreremoveScript(t *testing.T) {
	scriptPath := filepath.Join(".", "scripts", "preremove.sh")
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("preremove.sh does not exist: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Errorf("preremove.sh is not executable: mode is %v", info.Mode())
	}

	t.Run("clean execution when rwarden not found", func(t *testing.T) {
		cmd := exec.Command("/bin/sh", scriptPath)
		cmd.Env = []string{"PATH=/bin:/usr/bin"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("preremove.sh failed when rwarden not found: %v, output: %s", err, string(out))
		}
	})

	t.Run("invokes stop and cleanup on mock rwarden", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test-preremove-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		mockLog := filepath.Join(tmpDir, "mock_calls.log")
		mockRwarden := filepath.Join(tmpDir, "rwarden")
		mockContent := "#!/bin/sh\necho \"$@\" >> \"" + mockLog + "\"\nexit 0\n"
		if err := os.WriteFile(mockRwarden, []byte(mockContent), 0755); err != nil {
			t.Fatal(err)
		}

		cmdMock := exec.Command("/bin/sh", scriptPath)
		cmdMock.Env = []string{
			"PATH=" + tmpDir + ":/bin:/usr/bin",
		}
		outMock, err := cmdMock.CombinedOutput()
		if err != nil {
			t.Fatalf("preremove.sh failed with mock rwarden: %v, output: %s", err, string(outMock))
		}

		logBytes, err := os.ReadFile(mockLog)
		if err != nil {
			t.Fatalf("failed to read mock log: %v", err)
		}
		logStr := string(logBytes)
		if !strings.Contains(logStr, "stop") {
			t.Errorf("expected preremove.sh to call 'rwarden stop', got calls:\n%s", logStr)
		}
		if !strings.Contains(logStr, "cleanup") {
			t.Errorf("expected preremove.sh to call 'rwarden cleanup', got calls:\n%s", logStr)
		}
	})

	t.Run("invokes docker rm -f routewarden-dashboard", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test-preremove-docker-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		mockDockerLog := filepath.Join(tmpDir, "docker_calls.log")
		mockDocker := filepath.Join(tmpDir, "docker")
		mockDockerContent := "#!/bin/sh\necho \"$@\" >> \"" + mockDockerLog + "\"\nexit 0\n"
		if err := os.WriteFile(mockDocker, []byte(mockDockerContent), 0755); err != nil {
			t.Fatal(err)
		}

		cmdMock := exec.Command("/bin/sh", scriptPath)
		cmdMock.Env = []string{
			"PATH=" + tmpDir + ":/bin:/usr/bin",
		}
		outMock, err := cmdMock.CombinedOutput()
		if err != nil {
			t.Fatalf("preremove.sh failed with mock docker: %v, output: %s", err, string(outMock))
		}

		logBytes, err := os.ReadFile(mockDockerLog)
		if err != nil {
			t.Fatalf("failed to read docker log: %v", err)
		}
		logStr := string(logBytes)
		if !strings.Contains(logStr, "rm -f routewarden-dashboard") {
			t.Errorf("expected preremove.sh to call 'docker rm -f routewarden-dashboard', got:\n%s", logStr)
		}
	})

	t.Run("resilient when stop or cleanup returns non-zero exit code", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test-preremove-fail-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		mockRwarden := filepath.Join(tmpDir, "rwarden")
		mockContent := "#!/bin/sh\nexit 1\n"
		if err := os.WriteFile(mockRwarden, []byte(mockContent), 0755); err != nil {
			t.Fatal(err)
		}

		cmdMock := exec.Command("/bin/sh", scriptPath)
		cmdMock.Env = []string{
			"PATH=" + tmpDir + ":/bin:/usr/bin",
		}
		outMock, err := cmdMock.CombinedOutput()
		if err != nil {
			t.Fatalf("preremove.sh should tolerate command failures and exit 0, got err: %v, output: %s", err, string(outMock))
		}
	})
}

func TestUniversalUninstallScript(t *testing.T) {
	candidates := []string{
		filepath.Join(".", "scripts", "uninstall.sh"),
		filepath.Join("..", "docs", "docs", "public", "uninstall.sh"),
		filepath.Join("..", "docs", "public", "uninstall.sh"),
	}

	var primaryScript string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			primaryScript = p
			break
		}
	}

	if primaryScript == "" {
		t.Skip("uninstall.sh not found (skipping in standalone environment)")
	}

	// Check bash syntax
	cmdSyntax := exec.Command("bash", "-n", primaryScript)
	if out, err := cmdSyntax.CombinedOutput(); err != nil {
		t.Fatalf("syntax error in %s: %v, output: %s", primaryScript, err, string(out))
	}

	t.Run("clean execution when binary not present", func(t *testing.T) {
		tmpHome, err := os.MkdirTemp("", "test-uninstall-clean-home-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpHome)

		cmd := exec.Command("bash", primaryScript)
		cmd.Env = []string{
			"HOME=" + tmpHome,
			"PATH=/bin:/usr/bin",
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("uninstall.sh failed on clean system: %v, output: %s", err, string(out))
		}
		outStr := string(out)
		if !strings.Contains(outStr, "No rwarden binary found") {
			t.Errorf("expected 'No rwarden binary found' notice, got:\n%s", outStr)
		}
		if !strings.Contains(outStr, "RouteWarden uninstallation complete") {
			t.Errorf("expected completion notice, got:\n%s", outStr)
		}
	})

	t.Run("stops services, removes binary from .local/bin, and cleans ~/.routewarden", func(t *testing.T) {
		tmpHome, err := os.MkdirTemp("", "test-uninstall-full-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpHome)

		localBin := filepath.Join(tmpHome, ".local", "bin")
		if err := os.MkdirAll(localBin, 0755); err != nil {
			t.Fatal(err)
		}

		mockLog := filepath.Join(tmpHome, "mock_calls.log")
		rwardenBin := filepath.Join(localBin, "rwarden")
		mockScript := "#!/bin/sh\necho \"$@\" >> \"" + mockLog + "\"\nexit 0\n"
		if err := os.WriteFile(rwardenBin, []byte(mockScript), 0755); err != nil {
			t.Fatal(err)
		}

		// Create ~/.routewarden directory
		rwDataDir := filepath.Join(tmpHome, ".routewarden")
		if err := os.MkdirAll(rwDataDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rwDataDir, "state.json"), []byte(`{"active":true}`), 0644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command("bash", primaryScript)
		cmd.Env = []string{
			"HOME=" + tmpHome,
			"PATH=" + localBin + ":/bin:/usr/bin",
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("uninstall.sh failed: %v, output: %s", err, string(out))
		}
		outStr := string(out)

		// 1. Verify binary removal
		if _, err := os.Stat(rwardenBin); !os.IsNotExist(err) {
			t.Errorf("expected rwarden binary %s to be removed, but still exists", rwardenBin)
		}

		// 2. Verify runtime dir removal
		if _, err := os.Stat(rwDataDir); !os.IsNotExist(err) {
			t.Errorf("expected ~/.routewarden directory %s to be removed, but still exists", rwDataDir)
		}

		// 3. Verify services were stopped
		calls, err := os.ReadFile(mockLog)
		if err != nil {
			t.Fatalf("failed to read mock calls: %v", err)
		}
		callsStr := string(calls)
		if !strings.Contains(callsStr, "stop") {
			t.Errorf("expected 'rwarden stop' call, got:\n%s", callsStr)
		}
		if !strings.Contains(callsStr, "cleanup") {
			t.Errorf("expected 'rwarden cleanup' call, got:\n%s", callsStr)
		}

		// 4. Verify user output messages
		if !strings.Contains(outStr, "Successfully uninstalled rwarden") {
			t.Errorf("expected success message, got:\n%s", outStr)
		}
		if !strings.Contains(outStr, "Removing ~/.routewarden runtime data") {
			t.Errorf("expected runtime data cleanup message, got:\n%s", outStr)
		}
	})

	t.Run("invokes docker rm -f routewarden-dashboard", func(t *testing.T) {
		tmpHome, err := os.MkdirTemp("", "test-uninstall-docker-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpHome)

		binDir := filepath.Join(tmpHome, "bin")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}

		dockerLog := filepath.Join(tmpHome, "docker.log")
		dockerBin := filepath.Join(binDir, "docker")
		mockDocker := "#!/bin/sh\necho \"$@\" >> \"" + dockerLog + "\"\nexit 0\n"
		if err := os.WriteFile(dockerBin, []byte(mockDocker), 0755); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command("bash", primaryScript)
		cmd.Env = []string{
			"HOME=" + tmpHome,
			"PATH=" + binDir + ":/bin:/usr/bin",
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("uninstall.sh failed: %v, output: %s", err, string(out))
		}

		logBytes, err := os.ReadFile(dockerLog)
		if err != nil {
			t.Fatalf("failed to read docker log: %v", err)
		}
		if !strings.Contains(string(logBytes), "rm -f routewarden-dashboard") {
			t.Errorf("expected docker rm -f routewarden-dashboard, got: %s", string(logBytes))
		}
	})

	t.Run("removes symlinked rwarden binary", func(t *testing.T) {
		tmpHome, err := os.MkdirTemp("", "test-uninstall-symlink-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpHome)

		realBinDir := filepath.Join(tmpHome, "real_bin")
		localBinDir := filepath.Join(tmpHome, ".local", "bin")
		if err := os.MkdirAll(realBinDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(localBinDir, 0755); err != nil {
			t.Fatal(err)
		}

		targetBin := filepath.Join(realBinDir, "rwarden_actual")
		if err := os.WriteFile(targetBin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}

		symlinkPath := filepath.Join(localBinDir, "rwarden")
		if err := os.Symlink(targetBin, symlinkPath); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command("bash", primaryScript)
		cmd.Env = []string{
			"HOME=" + tmpHome,
			"PATH=" + localBinDir + ":/bin:/usr/bin",
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("uninstall.sh failed with symlink: %v, output: %s", err, string(out))
		}

		if _, err := os.Lstat(symlinkPath); !os.IsNotExist(err) {
			t.Errorf("expected symlink %s to be removed, but it still exists", symlinkPath)
		}
	})

	t.Run("resilient when stop or cleanup returns non-zero exit code", func(t *testing.T) {
		tmpHome, err := os.MkdirTemp("", "test-uninstall-error-resilience-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpHome)

		localBin := filepath.Join(tmpHome, ".local", "bin")
		if err := os.MkdirAll(localBin, 0755); err != nil {
			t.Fatal(err)
		}

		rwardenBin := filepath.Join(localBin, "rwarden")
		mockScript := "#!/bin/sh\nexit 1\n"
		if err := os.WriteFile(rwardenBin, []byte(mockScript), 0755); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command("bash", primaryScript)
		cmd.Env = []string{
			"HOME=" + tmpHome,
			"PATH=" + localBin + ":/bin:/usr/bin",
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("uninstall.sh should succeed even if stop/cleanup fail: %v, output: %s", err, string(out))
		}

		if _, err := os.Stat(rwardenBin); !os.IsNotExist(err) {
			t.Errorf("expected binary to still be removed even when stop fails, but it still exists")
		}
	})
}
