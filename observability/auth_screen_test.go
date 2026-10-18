package observability_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/routewarden/cli/observability"
)

func TestCustomAuthScreen_ContentAndElements(t *testing.T) {
	html := observability.CustomAuthScreenHTML

	// Check essential HTML elements
	expectedSnippets := []string{
		"<!DOCTYPE html>",
		`name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0"`,
		`id="auth-form"`,
		`id="username"`,
		`id="password"`,
		`id="toggle-pass"`,
		`id="btn-submit"`,
		`id="auth-alert"`,
		`/api/auth/login`,
		`ROUTEWARDEN SOC`,
		`RESTRICTED CONSOLE // AUTH REQUIRED`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(html, snippet) {
			t.Errorf("CustomAuthScreenHTML missing expected snippet: %q", snippet)
		}
	}
}

func TestDashboard_MobileOptimizationElements(t *testing.T) {
	html := observability.CustomSOCDashboardHTML

	expectedSnippets := []string{
		`maximum-scale=5.0`,
		`mobile-section-nav`,
		`soc-section`,
		`sec-kpis`,
		`sec-stream`,
		`sec-geo`,
		`sec-charts`,
		`sec-intel`,
		`@media (max-width: 768px)`,
		`@media (max-width: 480px)`,
		`btn-logout`,
		`logoutDashboard()`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(html, snippet) {
			t.Errorf("CustomSOCDashboardHTML missing mobile optimization snippet: %q", snippet)
		}
	}
}

func TestCustomAuth_LoginFlowAndCookies(t *testing.T) {
	tempDir := t.TempDir()
	logFilePath := tempDir + "/access.log"
	logFile, _ := os.Create(logFilePath)
	defer logFile.Close()

	handler := observability.NewDashboardHandlerWithAuth(tempDir, nil, "", logFile, nil, "", "admin:secret123")

	// 1. GET /login without auth should return 200 OK with custom auth screen
	reqLogin := httptest.NewRequest("GET", "/login", nil)
	rrLogin := httptest.NewRecorder()
	handler.ServeHTTP(rrLogin, reqLogin)
	if rrLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET /login, got %d", rrLogin.Code)
	}
	if !strings.Contains(rrLogin.Body.String(), "ROUTEWARDEN SOC") {
		t.Errorf("expected login page content on GET /login, got %s", rrLogin.Body.String())
	}

	// 2. Browser GET / with Accept: text/html and no auth should redirect to /login
	reqBrowser := httptest.NewRequest("GET", "/", nil)
	reqBrowser.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	rrBrowser := httptest.NewRecorder()
	handler.ServeHTTP(rrBrowser, reqBrowser)
	if rrBrowser.Code != http.StatusFound {
		t.Fatalf("expected 302 Found redirect to /login for browser GET /, got %d", rrBrowser.Code)
	}
	if loc := rrBrowser.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect location '/login', got %q", loc)
	}

	// 3. POST /api/auth/login with invalid credentials should return 401
	badCreds, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	reqBadLogin := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(badCreds))
	rrBadLogin := httptest.NewRecorder()
	handler.ServeHTTP(rrBadLogin, reqBadLogin)
	if rrBadLogin.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for invalid credentials, got %d", rrBadLogin.Code)
	}

	// 4. POST /api/auth/login with valid credentials should return 200 and set routewarden_auth cookie
	goodCreds, _ := json.Marshal(map[string]string{"username": "admin", "password": "secret123"})
	reqGoodLogin := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(goodCreds))
	rrGoodLogin := httptest.NewRecorder()
	handler.ServeHTTP(rrGoodLogin, reqGoodLogin)
	if rrGoodLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid credentials, got %d", rrGoodLogin.Code)
	}
	cookies := rrGoodLogin.Result().Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "routewarden_auth" {
			authCookie = c
			break
		}
	}
	if authCookie == nil {
		t.Fatalf("expected routewarden_auth cookie to be set")
	}
	expectedToken := base64.StdEncoding.EncodeToString([]byte("admin:secret123"))
	if authCookie.Value != expectedToken {
		t.Errorf("expected cookie value %q, got %q", expectedToken, authCookie.Value)
	}

	// 5. Subsequent request to GET / with routewarden_auth cookie should return 200 OK
	reqAuthed := httptest.NewRequest("GET", "/", nil)
	reqAuthed.AddCookie(authCookie)
	rrAuthed := httptest.NewRecorder()
	handler.ServeHTTP(rrAuthed, reqAuthed)
	if rrAuthed.Code != http.StatusOK {
		t.Errorf("expected 200 OK for GET / with valid cookie, got %d", rrAuthed.Code)
	}

	// 6. GET /login when already authenticated should redirect to /
	reqLoginAuthed := httptest.NewRequest("GET", "/login", nil)
	reqLoginAuthed.AddCookie(authCookie)
	rrLoginAuthed := httptest.NewRecorder()
	handler.ServeHTTP(rrLoginAuthed, reqLoginAuthed)
	if rrLoginAuthed.Code != http.StatusFound {
		t.Errorf("expected 302 redirect on GET /login when already logged in, got %d", rrLoginAuthed.Code)
	}
	if loc := rrLoginAuthed.Header().Get("Location"); loc != "/" {
		t.Errorf("expected redirect location '/', got %q", loc)
	}

	// 7. POST /api/auth/logout should clear the routewarden_auth cookie
	reqLogout := httptest.NewRequest("POST", "/api/auth/logout", nil)
	rrLogout := httptest.NewRecorder()
	handler.ServeHTTP(rrLogout, reqLogout)
	if rrLogout.Code != http.StatusOK {
		t.Errorf("expected 200 OK on POST /api/auth/logout, got %d", rrLogout.Code)
	}
	logoutCookies := rrLogout.Result().Cookies()
	var clearedCookie *http.Cookie
	for _, c := range logoutCookies {
		if c.Name == "routewarden_auth" {
			clearedCookie = c
			break
		}
	}
	if clearedCookie == nil || clearedCookie.MaxAge >= 0 {
		t.Errorf("expected cleared cookie with negative MaxAge, got %+v", clearedCookie)
	}
}
