package main_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_KeysCommand(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Keys without subcommands prints usage
	stdout, _, code := runCLI(t, "keys")
	if code != 0 || !strings.Contains(stdout, "Usage: rwarden keys <subcommand> [options]") {
		t.Errorf("expected usage for keys command, got code %d, out:\n%s", code, stdout)
	}

	// 2. Keys create without agent name errors
	_, stderr, code := runCLI(t, "keys", "create", "--dir", tempDir)
	if code == 0 || !strings.Contains(stderr, "Usage: rwarden keys create <agent-name>") {
		t.Errorf("expected missing name error, got code %d, stderr: %s", code, stderr)
	}

	// 3. Keys create success
	stdout, _, code = runCLI(t, "keys", "create", "edge-prod-01", "--dir", tempDir)
	if code != 0 {
		t.Fatalf("keys create failed with code %d", code)
	}
	if !strings.Contains(stdout, "Agent Key Created Successfully!") || !strings.Contains(stdout, "edge-prod-01") {
		t.Errorf("expected key creation output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "rw_sec_") {
		t.Errorf("expected token prefix rw_sec_ in output, got:\n%s", stdout)
	}

	// 4. Keys list shows created key with ACTIVE status
	stdout, _, code = runCLI(t, "keys", "list", "--dir", tempDir)
	if code != 0 {
		t.Fatalf("keys list failed with code %d", code)
	}
	if !strings.Contains(stdout, "edge-prod-01") || !strings.Contains(stdout, "ACTIVE") {
		t.Errorf("expected edge-prod-01 with ACTIVE status in list, got:\n%s", stdout)
	}

	// 5. Create a second key and list multiple
	_, _, code = runCLI(t, "keys", "create", "cloud-worker-02", "--dir", tempDir)
	if code != 0 {
		t.Fatalf("second key create failed with code %d", code)
	}
	stdout, _, code = runCLI(t, "keys", "list", "--dir", tempDir)
	if !strings.Contains(stdout, "edge-prod-01") || !strings.Contains(stdout, "cloud-worker-02") {
		t.Errorf("expected both agents in list, got:\n%s", stdout)
	}

	// 6. Keys revoke without ID errors
	_, stderr, code = runCLI(t, "keys", "revoke", "--dir", tempDir)
	if code == 0 || !strings.Contains(stderr, "Usage: rwarden keys revoke <id-or-name>") {
		t.Errorf("expected missing agent error for revoke, got code %d, stderr: %s", code, stderr)
	}

	// 7. Keys revoke nonexistent agent errors
	_, stderr, code = runCLI(t, "keys", "revoke", "nonexistent-agent", "--dir", tempDir)
	if code == 0 || !strings.Contains(stderr, "not found") {
		t.Errorf("expected not found error for nonexistent revoke, got code %d, stderr: %s", code, stderr)
	}

	// 8. Keys revoke success
	stdout, _, code = runCLI(t, "keys", "revoke", "edge-prod-01", "--dir", tempDir)
	if code != 0 {
		t.Fatalf("revoke failed with code %d", code)
	}
	if !strings.Contains(stdout, "Agent key \"edge-prod-01\" has been revoked") {
		t.Errorf("expected revocation confirmation, got:\n%s", stdout)
	}

	// Verify status updated to REVOKED in list
	stdout, _, code = runCLI(t, "keys", "list", "--dir", tempDir)
	if !strings.Contains(stdout, "REVOKED") {
		t.Errorf("expected REVOKED status in list, got:\n%s", stdout)
	}

	// 9. Unknown subcommand displays usage
	stdout, _, code = runCLI(t, "keys", "invalid-subcmd")
	if code != 0 || !strings.Contains(stdout, "Usage: rwarden keys <subcommand>") {
		t.Errorf("expected usage for unknown keys subcommand, got code %d, stdout: %s", code, stdout)
	}
}

func TestCLI_RegisterCommand_Validation(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Missing flags errors out with helpful message
	_, stderr, code := runCLI(t, "register")
	if code == 0 || !strings.Contains(stderr, "Both --url and --key are required") {
		t.Errorf("expected missing flags error, got code %d, stderr: %s", code, stderr)
	}

	// 2. Missing url only
	_, stderr, code = runCLI(t, "register", "--key", "some-token")
	if code == 0 || !strings.Contains(stderr, "Both --url and --key are required") {
		t.Errorf("expected missing url error, got code %d, stderr: %s", code, stderr)
	}

	// 3. Missing key only
	_, stderr, code = runCLI(t, "register", "--url", "http://198.51.100.1:7890")
	if code == 0 || !strings.Contains(stderr, "Both --url and --key are required") {
		t.Errorf("expected missing key error, got code %d, stderr: %s", code, stderr)
	}

	// 4. Register against unreachable server fails gracefully with exit code 1
	customConfig := filepath.Join(tempDir, "agent.json")
	_, stderr, code = runCLI(t, "register", "--url", "http://127.0.0.1:59999", "--key", "rw_sec_test", "--config", customConfig)
	if code == 0 {
		t.Errorf("expected non-zero exit code when server is unreachable, got %d", code)
	}
	if !strings.Contains(stderr, "Registration failed") {
		t.Errorf("expected 'Registration failed' in stderr, got:\n%s", stderr)
	}
}

func TestCLI_PushCommand_Validation(t *testing.T) {
	// 1. Push with no registration and no flags displays helpful error and registration guidance
	tempConfig := filepath.Join(t.TempDir(), "nonexistent.json")
	_, stderr, code := runCLI(t, "push", "--config", tempConfig)
	if code == 0 || !strings.Contains(stderr, "RouteWarden is not registered on this node") {
		t.Errorf("expected registration required error, got code %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "rwarden register --url") {
		t.Errorf("expected registration instructions in error, got:\n%s", stderr)
	}

	// 2. Push with --help shows all options including multi-file and docker flags
	stdout, stderr, _ := runCLI(t, "push", "--help")
	combined := stdout + stderr
	if !strings.Contains(combined, "-docker") && !strings.Contains(combined, "--docker") {
		t.Errorf("push help missing --docker flag, got:\n%s", combined)
	}
	if !strings.Contains(combined, "-file") && !strings.Contains(combined, "--file") {
		t.Errorf("push help missing --file flag, got:\n%s", combined)
	}
	if !strings.Contains(combined, "-container") && !strings.Contains(combined, "--container") {
		t.Errorf("push help missing --container flag, got:\n%s", combined)
	}
	if !strings.Contains(combined, "-batch-size") && !strings.Contains(combined, "--batch-size") {
		t.Errorf("push help missing --batch-size flag, got:\n%s", combined)
	}
	if !strings.Contains(combined, "-flush-interval") && !strings.Contains(combined, "--flush-interval") {
		t.Errorf("push help missing --flush-interval flag, got:\n%s", combined)
	}
}

func TestCLI_DashboardCommand_SubcommandValidation(t *testing.T) {
	// 1. Unknown dashboard subcommand displays error and usage
	_, stderr, code := runCLI(t, "dashboard", "invalid-subcommand-xyz")
	if code == 0 || !strings.Contains(stderr, "Unknown dashboard subcommand") {
		t.Errorf("expected error for unknown dashboard subcommand, got code %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "Usage: rwarden dashboard [up|down|status|export]") {
		t.Errorf("expected dashboard usage in error, got:\n%s", stderr)
	}

	// 2. Dashboard status on empty dir
	tempDir := t.TempDir()
	stdout, _, code := runCLI(t, "dashboard", "status", "--dir", tempDir)
	if code != 0 {
		t.Fatalf("expected status command to exit with 0, got %d", code)
	}
	if !strings.Contains(stdout, "dashboard") && !strings.Contains(stdout, "Dashboard") {
		t.Errorf("expected dashboard status output, got:\n%s", stdout)
	}
}
