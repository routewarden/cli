package observability_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/routewarden/cli/crypto"
	"github.com/routewarden/cli/observability"
)

func TestEventStore_AddAndGetStats(t *testing.T) {
	store := observability.NewEventStore()

	// Ingest sample events
	store.Add(&observability.SecurityEvent{
		ClientIP:  "198.51.100.10",
		Method:    "GET",
		Path:      "/index.html",
		Status:    200,
		Verdict:   "ALLOW",
		LatencyMs: 1.5,
	})

	store.Add(&observability.SecurityEvent{
		ClientIP:  "203.0.113.5",
		Method:    "POST",
		Path:      "/login",
		Status:    403,
		Verdict:   "BLOCK",
		Rule:      "sql-injection",
		LatencyMs: 0.9,
	})

	store.Add(&observability.SecurityEvent{
		ClientIP:  "203.0.113.5",
		Method:    "GET",
		Path:      "/wp-login.php",
		Status:    429,
		Verdict:   "TARPIT",
		Rule:      "scanner",
		LatencyMs: 5000.0,
	})

	stats := store.GetStats()
	if stats.TotalEvents == 0 {
		t.Errorf("expected non-zero total events, got %d", stats.TotalEvents)
	}

	// Verify top IP
	if len(stats.TopIPs) == 0 || stats.TopIPs[0].Name != "203.0.113.5" {
		t.Errorf("expected top IP 203.0.113.5, got %+v", stats.TopIPs)
	}
	if stats.TopIPs[0].Blocked != 1 || stats.TopIPs[0].Tarpit != 1 {
		t.Errorf("expected 1 blocked and 1 tarpit for top IP, got %+v", stats.TopIPs[0])
	}

	// Verify top rule
	if len(stats.TopRules) == 0 {
		t.Errorf("expected top rules, got empty")
	}

	// Verify recent events
	if len(stats.RecentEvents) != 3 {
		t.Errorf("expected 3 recent events, got %d", len(stats.RecentEvents))
	}
}

func TestEventStore_ParseAndIngest(t *testing.T) {
	store := observability.NewEventStore()

	// Test JSON parse
	jsonLine := `{"time":"2026-10-18T12:00:00Z","client_ip":"192.0.2.1","method":"DELETE","path":"/api/keys","status":403,"verdict":"BLOCK","rule":"unauthorized"}`
	ev1 := store.ParseAndIngest(jsonLine, "test-source")
	if ev1 == nil {
		t.Fatalf("expected non-nil event from JSON parse")
	}
	if ev1.Verdict != "BLOCK" || ev1.Rule != "unauthorized" || ev1.Method != "DELETE" {
		t.Errorf("unexpected event content: %+v", ev1)
	}

	// Test Combined log parse with verdict tag
	combinedLine := `198.51.100.99 - - [18/Oct/2026:12:00:00 +0000] "GET /etc/passwd HTTP/1.1" 403 0 "-" "[BLOCK: path-traversal]"`
	ev2 := store.ParseAndIngest(combinedLine, "file")
	if ev2 == nil {
		t.Fatalf("expected non-nil event from combined parse")
	}
	if ev2.Verdict != "BLOCK" || ev2.Rule != "path-traversal" || ev2.ClientIP != "198.51.100.99" {
		t.Errorf("unexpected combined event content: %+v", ev2)
	}
}

func TestEventStore_Subscription(t *testing.T) {
	store := observability.NewEventStore()
	ch, unsub := store.Subscribe()
	defer unsub()

	testEv := &observability.SecurityEvent{
		ClientIP: "1.2.3.4",
		Method:   "GET",
		Path:     "/test",
		Verdict:  "ALLOW",
		Status:   200,
	}

	go store.Add(testEv)

	received := <-ch
	if received.ClientIP != "1.2.3.4" || received.Path != "/test" {
		t.Errorf("unexpected received event: %+v", received)
	}
}

func TestCustomDashboard_HTTPEndpoints(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-soc-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	serverPubStr := crypto.EncodePublicKey(serverPriv.PublicKey())

	logFilePath := tempDir + "/access.log"
	logFile, _ := os.Create(logFilePath)
	defer logFile.Close()

	handler := observability.NewDashboardHandler(tempDir, serverPriv, serverPubStr, logFile, nil, "")

	// 1. GET / should return 200 with custom SOC dashboard HTML
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for GET /, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "RouteWarden") || !strings.Contains(body, "SOC INTELLIGENCE") {
		t.Errorf("expected RouteWarden SOC dashboard HTML, got: %s", body[:min(200, len(body))])
	}
	if !strings.Contains(body, `id="select-node"`) {
		t.Errorf("expected select-node in dashboard HTML")
	}
	if !strings.Contains(body, "filterByNode") {
		t.Errorf("expected filterByNode function in dashboard script")
	}
	if !strings.Contains(body, "All Nodes") {
		t.Errorf("expected 'All Nodes' in dashboard HTML")
	}

	// 2. GET /api/stats should return valid JSON
	reqStats := httptest.NewRequest("GET", "/api/stats", nil)
	rrStats := httptest.NewRecorder()
	handler.ServeHTTP(rrStats, reqStats)

	if rrStats.Code != http.StatusOK {
		t.Errorf("expected 200 OK for GET /api/stats, got %d", rrStats.Code)
	}
	var stats map[string]interface{}
	if err := json.Unmarshal(rrStats.Body.Bytes(), &stats); err != nil {
		t.Errorf("failed to parse /api/stats JSON: %v", err)
	}
	if _, ok := stats["total_events"]; !ok {
		t.Errorf("expected total_events key in /api/stats")
	}

	// 3. GET /api/ip-lookup with private IP should return 200 and is_private=true
	reqIP := httptest.NewRequest("GET", "/api/ip-lookup?ip=127.0.0.1", nil)
	rrIP := httptest.NewRecorder()
	handler.ServeHTTP(rrIP, reqIP)

	if rrIP.Code != http.StatusOK {
		t.Errorf("expected 200 OK for GET /api/ip-lookup?ip=127.0.0.1, got %d", rrIP.Code)
	}
	var ipInfo observability.IPDetails
	if err := json.Unmarshal(rrIP.Body.Bytes(), &ipInfo); err != nil {
		t.Fatalf("failed to parse /api/ip-lookup JSON: %v", err)
	}
	if !ipInfo.IsPrivate {
		t.Errorf("expected is_private=true for 127.0.0.1")
	}
	if ipInfo.CountryCode != "LAN" {
		t.Errorf("expected country_code=LAN, got %q", ipInfo.CountryCode)
	}

	// 4. GET /api/ip-lookup without IP parameter should return 400 Bad Request
	reqNoIP := httptest.NewRequest("GET", "/api/ip-lookup", nil)
	rrNoIP := httptest.NewRecorder()
	handler.ServeHTTP(rrNoIP, reqNoIP)
	if rrNoIP.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for /api/ip-lookup without IP, got %d", rrNoIP.Code)
	}

	// 5. GET /favicon.ico should return 200 with image/x-icon
	reqFavicon := httptest.NewRequest("GET", "/favicon.ico", nil)
	rrFavicon := httptest.NewRecorder()
	handler.ServeHTTP(rrFavicon, reqFavicon)
	if rrFavicon.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /favicon.ico, got %d", rrFavicon.Code)
	}
	if ct := rrFavicon.Header().Get("Content-Type"); ct != "image/x-icon" {
		t.Errorf("expected Content-Type image/x-icon, got %q", ct)
	}
	if rrFavicon.Body.Len() == 0 {
		t.Errorf("expected non-empty favicon.ico body")
	}

	// 6. GET /icon.svg should return 200 with image/svg+xml
	reqIcon := httptest.NewRequest("GET", "/icon.svg", nil)
	rrIcon := httptest.NewRecorder()
	handler.ServeHTTP(rrIcon, reqIcon)
	if rrIcon.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /icon.svg, got %d", rrIcon.Code)
	}
	if ct := rrIcon.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("expected Content-Type image/svg+xml, got %q", ct)
	}
	if rrIcon.Body.Len() == 0 {
		t.Errorf("expected non-empty icon.svg body")
	}

	// 5. Test direct LookupIP function for invalid and empty inputs
	emptyLookup := observability.LookupIP("")
	if emptyLookup.Status != "fail" {
		t.Errorf("expected fail status for empty IP, got %s", emptyLookup.Status)
	}

	invalidLookup := observability.LookupIP("not-an-ip")
	if invalidLookup.Status != "fail" {
		t.Errorf("expected fail status for invalid IP, got %s", invalidLookup.Status)
	}

	privLookup := observability.LookupIP("192.168.1.50")
	if !privLookup.IsPrivate || privLookup.Status != "success" {
		t.Errorf("expected success and is_private=true for 192.168.1.50")
	}
}

func TestAutoDetectCountry(t *testing.T) {
	tests := []struct {
		ip          string
		wantCountry string
		wantCode    string
	}{
		{"127.0.0.1", "Localhost / Loopback", "LAN"},
		{"10.20.30.40", "Private Network (RFC 1918)", "LAN"},
		{"192.168.1.1", "Private Network (RFC 1918)", "LAN"},
		{"172.16.0.1", "Private Network (RFC 1918)", "LAN"},
		{"198.51.100.24", "TEST-NET-2 (RFC 5737)", "US"},
		{"203.0.113.88", "TEST-NET-3 (RFC 5737)", "US"},
		{"1.1.1.1", "United States", "US"},
		{"88.198.50.10", "Germany", "DE"},
		{"", "Unknown", ""},
		{"not-a-valid-ip", "Unknown", ""},
	}

	for _, tt := range tests {
		country, code := observability.AutoDetectCountry(tt.ip)
		if country != tt.wantCountry || code != tt.wantCode {
			t.Errorf("AutoDetectCountry(%q) = (%q, %q), want (%q, %q)",
				tt.ip, country, code, tt.wantCountry, tt.wantCode)
		}
	}
}

func TestEventStore_CountryStats(t *testing.T) {
	store := observability.NewEventStore()

	// Ingest events
	store.Add(&observability.SecurityEvent{
		ClientIP: "198.51.100.24",
		Method:   "GET",
		Path:     "/",
		Status:   200,
		Verdict:  "ALLOW",
	})
	store.Add(&observability.SecurityEvent{
		ClientIP: "88.198.50.10",
		Method:   "POST",
		Path:     "/admin",
		Status:   403,
		Verdict:  "BLOCK",
		Rule:     "scanner",
	})
	store.Add(&observability.SecurityEvent{
		ClientIP: "127.0.0.1",
		Method:   "GET",
		Path:     "/health",
		Status:   200,
		Verdict:  "ALLOW",
	})

	stats := store.GetStats()
	if len(stats.TopCountries) == 0 {
		t.Fatalf("expected TopCountries to be populated")
	}

	// Verify top IPs have country populated
	for _, ipItem := range stats.TopIPs {
		if ipItem.Country == "" || ipItem.CountryCode == "" {
			t.Errorf("expected IP %s to have Country and CountryCode, got (%q, %q)",
				ipItem.Name, ipItem.Country, ipItem.CountryCode)
		}
	}

	// Verify recent events have Country populated
	for _, ev := range stats.RecentEvents {
		if ev.Country == "" || ev.CountryCode == "" {
			t.Errorf("expected Event for %s to have Country and CountryCode, got (%q, %q)",
				ev.ClientIP, ev.Country, ev.CountryCode)
		}
	}
}

func TestCustomDashboard_TimeRangeFilterElements(t *testing.T) {
	html := observability.CustomSOCDashboardHTML
	elements := []string{
		`id="select-time-range"`,
		`value="1m"`,
		`value="5m"`,
		`value="15m"`,
		`value="30m"`,
		`value="1h"`,
		`value="6h"`,
		`value="24h"`,
		`value="custom"`,
		`id="custom-time-row"`,
		`id="custom-time-start"`,
		`id="custom-time-end"`,
		`id="btn-apply-custom-time"`,
		`id="prompt-stream-cmd"`,
	}
	for _, el := range elements {
		if !strings.Contains(html, el) {
			t.Errorf("expected dashboard HTML to contain %s", el)
		}
	}
}

func TestCustomDashboard_PaginationElements(t *testing.T) {
	html := observability.CustomSOCDashboardHTML
	elements := []string{
		`id="stream-pagination-bar"`,
		`id="select-page-size"`,
		`id="pagination-info"`,
		`id="btn-page-first"`,
		`id="btn-page-prev"`,
		`id="input-page-num"`,
		`id="pagination-total-pages"`,
		`id="btn-page-next"`,
		`id="btn-page-last"`,
		`id="btn-load-more-db"`,
		`goToPage`,
		`goToPrevPage`,
		`goToNextPage`,
		`changePageSize`,
		`fetchFilteredLogs`,
		`matchesCurrentFilters`,
		`buildFilterQueryString`,
		`href="/icon.svg"`,
		`href="/favicon.ico"`,
		`src="/icon.svg"`,
	}
	for _, el := range elements {
		if !strings.Contains(html, el) {
			t.Errorf("expected dashboard HTML to contain %s", el)
		}
	}
}

func TestDashboard_Authentication(t *testing.T) {
	tempDir := t.TempDir()
	logFilePath := tempDir + "/access.log"
	logFile, _ := os.Create(logFilePath)
	defer logFile.Close()

	// 1. Create handler with auth configured: admin:supersecret
	handler := observability.NewDashboardHandlerWithAuth(tempDir, nil, "", logFile, nil, "", "admin:supersecret")

	// A. Unauthenticated request to GET / should return 401 with WWW-Authenticate
	reqNoAuth := httptest.NewRequest("GET", "/", nil)
	rrNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrNoAuth, reqNoAuth)
	if rrNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized without credentials, got %d", rrNoAuth.Code)
	}
	if !strings.Contains(rrNoAuth.Header().Get("WWW-Authenticate"), "Basic") {
		t.Errorf("expected WWW-Authenticate header with Basic, got %q", rrNoAuth.Header().Get("WWW-Authenticate"))
	}

	// B. Request with incorrect credentials should return 401
	reqWrong := httptest.NewRequest("GET", "/", nil)
	reqWrong.SetBasicAuth("admin", "wrongpassword")
	rrWrong := httptest.NewRecorder()
	handler.ServeHTTP(rrWrong, reqWrong)
	if rrWrong.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for wrong password, got %d", rrWrong.Code)
	}

	// C. Request with valid Basic Auth should return 200 OK
	reqValid := httptest.NewRequest("GET", "/", nil)
	reqValid.SetBasicAuth("admin", "supersecret")
	rrValid := httptest.NewRecorder()
	handler.ServeHTTP(rrValid, reqValid)
	if rrValid.Code != http.StatusOK {
		t.Errorf("expected 200 OK with valid Basic Auth, got %d", rrValid.Code)
	}

	// D. Unauthenticated request to /api/logs should return 401 JSON
	reqLogsNoAuth := httptest.NewRequest("GET", "/api/logs", nil)
	rrLogsNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrLogsNoAuth, reqLogsNoAuth)
	if rrLogsNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for /api/logs without credentials, got %d", rrLogsNoAuth.Code)
	}
	if !strings.Contains(rrLogsNoAuth.Body.String(), "unauthorized") {
		t.Errorf("expected JSON error for unauthorized API, got %s", rrLogsNoAuth.Body.String())
	}

	// E. /api/stats with valid Basic Auth should return auth_enabled=true and auth_user="admin"
	reqStats := httptest.NewRequest("GET", "/api/stats", nil)
	reqStats.SetBasicAuth("admin", "supersecret")
	rrStats := httptest.NewRecorder()
	handler.ServeHTTP(rrStats, reqStats)
	if rrStats.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/stats with valid credentials, got %d", rrStats.Code)
	}
	var stats map[string]interface{}
	if err := json.Unmarshal(rrStats.Body.Bytes(), &stats); err != nil {
		t.Fatalf("failed to decode /api/stats JSON: %v", err)
	}
	if authEn, ok := stats["auth_enabled"].(bool); !ok || !authEn {
		t.Errorf("expected auth_enabled=true in /api/stats, got %v", stats["auth_enabled"])
	}
	if authUser, ok := stats["auth_user"].(string); !ok || authUser != "admin" {
		t.Errorf("expected auth_user='admin' in /api/stats, got %v", stats["auth_user"])
	}

	// F. /api/logs with ?auth=admin:supersecret query param should return 200 OK
	reqQueryAuth := httptest.NewRequest("GET", "/api/logs?auth=admin:supersecret", nil)
	rrQueryAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrQueryAuth, reqQueryAuth)
	if rrQueryAuth.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/logs with ?auth=, got %d", rrQueryAuth.Code)
	}

	// G. /api/logs with ?token=supersecret query param should return 200 OK
	reqQueryToken := httptest.NewRequest("GET", "/api/logs?token=supersecret", nil)
	rrQueryToken := httptest.NewRecorder()
	handler.ServeHTTP(rrQueryToken, reqQueryToken)
	if rrQueryToken.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/logs with ?token=, got %d", rrQueryToken.Code)
	}

	// H. /api/logs with Bearer token should return 200 OK
	reqBearer := httptest.NewRequest("GET", "/api/logs", nil)
	reqBearer.Header.Set("Authorization", "Bearer supersecret")
	rrBearer := httptest.NewRecorder()
	handler.ServeHTTP(rrBearer, reqBearer)
	if rrBearer.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/logs with Bearer token, got %d", rrBearer.Code)
	}

	// I. Static assets /favicon.ico and /icon.svg should be exempt from auth
	reqFav := httptest.NewRequest("GET", "/favicon.ico", nil)
	rrFav := httptest.NewRecorder()
	handler.ServeHTTP(rrFav, reqFav)
	if rrFav.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /favicon.ico without auth, got %d", rrFav.Code)
	}

	// J. Agent API /api/v1/pubkey should be exempt from auth
	reqPub := httptest.NewRequest("GET", "/api/v1/pubkey", nil)
	rrPub := httptest.NewRecorder()
	handler.ServeHTTP(rrPub, reqPub)
	if rrPub.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/v1/pubkey without dashboard basic auth, got %d", rrPub.Code)
	}

	// K. Handler with empty auth should allow unauthenticated access
	openHandler := observability.NewDashboardHandlerWithAuth(tempDir, nil, "", logFile, nil, "", "")
	reqOpen := httptest.NewRequest("GET", "/api/logs", nil)
	rrOpen := httptest.NewRecorder()
	openHandler.ServeHTTP(rrOpen, reqOpen)
	if rrOpen.Code != http.StatusOK {
		t.Errorf("expected 200 OK for open handler without auth, got %d", rrOpen.Code)
	}
}
