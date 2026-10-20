package main_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newLocalTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test in sandbox: socket bind not permitted: %v", err)
		return nil
	}
	ts := httptest.NewUnstartedServer(handler)
	ts.Listener = l
	ts.Start()
	return ts
}

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
	if !strings.Contains(combined, "-event") && !strings.Contains(combined, "--event") {
		t.Errorf("push help missing --event flag, got:\n%s", combined)
	}
	if !strings.Contains(combined, "-stdin") && !strings.Contains(combined, "--stdin") {
		t.Errorf("push help missing --stdin flag, got:\n%s", combined)
	}
}

func TestCLI_Push_ManualEventDirect(t *testing.T) {
	var receivedEvents []string
	var receivedAuth string
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			receivedAuth = r.Header.Get("Authorization")
			var body struct {
				Events []string `json:"events"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			receivedEvents = append(receivedEvents, body.Events...)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	stdout, stderr, code := runCLI(t, "push", "--url", ts.URL, "--key", "rw_sec_manualkey", "-e", `{"client_ip":"198.51.100.1","verdict":"BLOCK"}`)
	if code != 0 {
		t.Fatalf("expected push -e to succeed with code 0, got %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Successfully pushed 1 event(s)") {
		t.Errorf("expected success message in stdout, got:\n%s", stdout)
	}
	if receivedAuth != "Bearer rw_sec_manualkey" {
		t.Errorf("expected auth Bearer rw_sec_manualkey, got %s", receivedAuth)
	}
	if len(receivedEvents) != 1 || !strings.Contains(receivedEvents[0], "198.51.100.1") {
		t.Errorf("expected received event, got %v", receivedEvents)
	}
}

func TestCLI_Push_ManualMultipleEvents(t *testing.T) {
	var receivedEvents []string
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			var body struct {
				Events []string `json:"events"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			receivedEvents = append(receivedEvents, body.Events...)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	stdout, stderr, code := runCLI(t, "push", "--url", ts.URL, "--key", "test-key", "-e", "event_one", "-e", "event_two")
	if code != 0 {
		t.Fatalf("push failed with code %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Successfully pushed 2 event(s)") {
		t.Errorf("expected 2 events confirmation, got:\n%s", stdout)
	}
	if len(receivedEvents) != 2 {
		t.Fatalf("expected 2 events received, got %d", len(receivedEvents))
	}
}

func TestCLI_Push_StdinPiped(t *testing.T) {
	var receivedEvents []string
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			var body struct {
				Events []string `json:"events"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			receivedEvents = append(receivedEvents, body.Events...)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	stdinData := "line1\nline2\nline3\n"
	stdout, stderr, code := runCLIWithStdin(t, stdinData, "push", "--url", ts.URL, "--key", "test-key", "--stdin")
	if code != 0 {
		t.Fatalf("push --stdin failed with code %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Successfully pushed 3 event(s) from STDIN") {
		t.Errorf("expected STDIN push confirmation, got:\n%s", stdout)
	}
	if len(receivedEvents) != 3 {
		t.Fatalf("expected 3 events received, got %d: %v", len(receivedEvents), receivedEvents)
	}
}

func TestCLI_Push_DashFileStdin(t *testing.T) {
	var receivedEvents []string
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			var body struct {
				Events []string `json:"events"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			receivedEvents = append(receivedEvents, body.Events...)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	stdinData := "piped_event_alpha\npiped_event_beta\n"
	stdout, stderr, code := runCLIWithStdin(t, stdinData, "push", "--url", ts.URL, "--key", "test-key", "-f", "-")
	if code != 0 {
		t.Fatalf("push -f - failed with code %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Successfully pushed 2 event(s) from STDIN") {
		t.Errorf("expected 2 events confirmation from STDIN, got:\n%s", stdout)
	}
	if len(receivedEvents) != 2 {
		t.Fatalf("expected 2 events received, got %d", len(receivedEvents))
	}
}

func TestCLI_Push_PositionalDashStdin(t *testing.T) {
	var receivedEvents []string
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			var body struct {
				Events []string `json:"events"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			receivedEvents = append(receivedEvents, body.Events...)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	stdinData := "positional_dash_event\n"
	stdout, stderr, code := runCLIWithStdin(t, stdinData, "push", "--url", ts.URL, "--key", "test-key", "-")
	if code != 0 {
		t.Fatalf("push - failed with code %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Successfully pushed 1 event(s) from STDIN") {
		t.Errorf("expected 1 event confirmation from STDIN, got:\n%s", stdout)
	}
	if len(receivedEvents) != 1 || receivedEvents[0] != "positional_dash_event" {
		t.Fatalf("expected positional_dash_event, got %v", receivedEvents)
	}
}

func TestCLI_Push_ManualEmptyEventError(t *testing.T) {
	_, stderr, code := runCLI(t, "push", "--url", "http://127.0.0.1:7890", "--key", "test-key", "-e", "", "-e", "   ")
	if code == 0 {
		t.Fatalf("expected push with empty -e flags to fail, got code %d", code)
	}
	if !strings.Contains(stderr, "no non-empty event strings provided") {
		t.Errorf("expected empty events error message, got: %s", stderr)
	}
}

func TestCLI_Push_EmptyStdin(t *testing.T) {
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	stdout, stderr, code := runCLIWithStdin(t, "", "push", "--url", ts.URL, "--key", "test-key", "--stdin")
	if code != 0 {
		t.Fatalf("push --stdin with empty input failed with code %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Successfully pushed 0 event(s) from STDIN") {
		t.Errorf("expected 0 events pushed message, got:\n%s", stdout)
	}
}

func TestCLI_Push_StdinBatched(t *testing.T) {
	var batchCount int
	var totalReceived int
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			batchCount++
			var body struct {
				Events []string `json:"events"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			totalReceived += len(body.Events)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	stdinData := "line1\nline2\nline3\nline4\nline5\n"
	stdout, stderr, code := runCLIWithStdin(t, stdinData, "push", "--url", ts.URL, "--key", "test-key", "--stdin", "--batch-size", "2")
	if code != 0 {
		t.Fatalf("push --stdin batched failed with code %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Successfully pushed 5 event(s) from STDIN") {
		t.Errorf("expected 5 events confirmation from STDIN, got:\n%s", stdout)
	}
	if totalReceived != 5 {
		t.Errorf("expected 5 total events, got %d", totalReceived)
	}
	if batchCount != 3 {
		t.Errorf("expected 3 batches (2+2+1), got %d", batchCount)
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

func TestCLI_Push_Logging_DirectBatchAndVerbose(t *testing.T) {
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	stdout, stderr, code := runCLI(t, "push", "--url", ts.URL, "--key", "rw_sec_logkey", "-e", `{"client_ip":"198.51.100.5","path":"/login"}`, "--verbose")
	if code != 0 {
		t.Fatalf("expected push with --verbose to succeed, got %d, stderr: %s", code, stderr)
	}

	if !strings.Contains(stdout, "📦 Pushed batch of 1 event(s) to dashboard (total: 1)") {
		t.Errorf("expected batch push log in stdout, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "↳ {\"client_ip\":\"198.51.100.5\",\"path\":\"/login\"}") {
		t.Errorf("expected verbose event preview in stdout, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Successfully pushed 1 event(s)") {
		t.Errorf("expected success message in stdout, got:\n%s", stdout)
	}
}

func TestCLI_Push_Logging_StdinBatchedLogs(t *testing.T) {
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	stdinData := "event1\nevent2\nevent3\n"
	stdout, stderr, code := runCLIWithStdin(t, stdinData, "push", "--url", ts.URL, "--key", "test-key", "--stdin", "--batch-size", "2")
	if code != 0 {
		t.Fatalf("expected push --stdin to succeed, got %d, stderr: %s", code, stderr)
	}

	if !strings.Contains(stdout, "📦 Pushed batch of 2 event(s) to dashboard (total: 2)") {
		t.Errorf("expected first batch log in stdout, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "📦 Pushed batch of 1 event(s) to dashboard (total: 3)") {
		t.Errorf("expected second batch log in stdout, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Successfully pushed 3 event(s) from STDIN") {
		t.Errorf("expected STDIN push completion message, got:\n%s", stdout)
	}
}

func TestCLI_Push_Logging_FailureLoggedToStderr(t *testing.T) {
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, stderr, code := runCLI(t, "push", "--url", ts.URL, "--key", "test-key", "-e", `{"test":"event"}`)
	if code == 0 {
		t.Fatal("expected push to fail when server returns 500")
	}

	if !strings.Contains(stderr, "❌ Failed to push event(s)") || !strings.Contains(stderr, "500") {
		t.Errorf("expected descriptive failure log on stderr, got:\n%s", stderr)
	}
}
