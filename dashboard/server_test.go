package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleGeoIP(t *testing.T) {
	srv := NewServer(Options{NoDocker: true})

	req := httptest.NewRequest(http.MethodGet, "/api/geoip?ip=127.0.0.1", nil)
	w := httptest.NewRecorder()

	srv.handleGeoIP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var res GeoResult
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if res.CountryCode != "LAN" || res.FlagEmoji != "🏠" {
		t.Errorf("expected LAN/🏠, got %+v", res)
	}
}

func TestHandleConfigLocalFallback(t *testing.T) {
	srv := NewServer(Options{NoDocker: true})

	req := httptest.NewRequest(http.MethodGet, "/api/config/test-source", nil)
	w := httptest.NewRecorder()

	srv.handleConfig(w, req)

	// Since samples/json/routewarden.json exists in repo root (cli/), it should load successfully!
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var res ConfigResponse
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("decode config: %v", err)
	}

	if !res.HasConfig {
		t.Errorf("expected has_config = true, got %+v", res)
	}
	if res.Config == nil {
		t.Errorf("expected parsed config object")
	}
}

func TestHandleIPDetails(t *testing.T) {
	srv := NewServer(Options{NoDocker: true})
	// Push a sample security event
	srv.buf.Push(SecurityEvent{
		ClientIP:     "192.168.1.50",
		Method:       "GET",
		Path:         "/.env",
		Pattern:      "dotfile",
		Action:       "blocked",
		ResponseMode: "tarpit",
		Source:       "traefik",
	})

	// Test GET /api/ip/192.168.1.50
	req := httptest.NewRequest(http.MethodGet, "/api/ip/192.168.1.50", nil)
	w := httptest.NewRecorder()
	srv.handleIPDetails(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var res IPDetailsResponse
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("decode ip details: %v", err)
	}

	if res.IP != "192.168.1.50" {
		t.Errorf("expected IP 192.168.1.50, got %s", res.IP)
	}
	if !res.Geo.IsPrivate || res.Geo.FlagEmoji != "🏠" {
		t.Errorf("expected private LAN geo result, got %+v", res.Geo)
	}
	if res.TotalEvents != 1 {
		t.Errorf("expected 1 event, got %d", res.TotalEvents)
	}
	if res.RiskScore != "critical" { // because of .env probe
		t.Errorf("expected risk critical, got %s", res.RiskScore)
	}
	if len(res.Events) != 1 || res.Events[0].Path != "/.env" {
		t.Errorf("expected 1 event with path /.env, got %+v", res.Events)
	}

	// Test GET /api/ip?ip=8.8.8.8 (query param form)
	reqQuery := httptest.NewRequest(http.MethodGet, "/api/ip?ip=8.8.8.8", nil)
	wQuery := httptest.NewRecorder()
	srv.handleIPDetails(wQuery, reqQuery)
	if wQuery.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", wQuery.Code)
	}
	var resQuery IPDetailsResponse
	if err := json.NewDecoder(wQuery.Body).Decode(&resQuery); err != nil {
		t.Fatalf("decode ip details: %v", err)
	}
	if resQuery.IP != "8.8.8.8" || resQuery.Geo.CountryCode != "US" {
		t.Errorf("expected 8.8.8.8 US, got %+v", resQuery)
	}

	// Test GET /api/ip without IP returns 400
	reqMissing := httptest.NewRequest(http.MethodGet, "/api/ip", nil)
	wMissing := httptest.NewRecorder()
	srv.handleIPDetails(wMissing, reqMissing)
	if wMissing.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for missing IP, got %d", wMissing.Code)
	}

	// Test through full Server.Handler() routing: GET /api/ip/203.0.113.195
	handler := srv.Handler()
	reqFull := httptest.NewRequest(http.MethodGet, "/api/ip/203.0.113.195", nil)
	wFull := httptest.NewRecorder()
	handler.ServeHTTP(wFull, reqFull)
	if wFull.Code != http.StatusOK {
		t.Fatalf("expected status 200 from handler, got %d: %s", wFull.Code, wFull.Body.String())
	}
	var resFull IPDetailsResponse
	if err := json.NewDecoder(wFull.Body).Decode(&resFull); err != nil {
		t.Fatalf("decode ip details from handler: %v", err)
	}
	if resFull.IP != "203.0.113.195" {
		t.Errorf("expected IP 203.0.113.195, got %s", resFull.IP)
	}

	// Test through full Server.Handler() routing: GET /api/ip?ip=203.0.113.195
	reqFullQuery := httptest.NewRequest(http.MethodGet, "/api/ip?ip=203.0.113.195", nil)
	wFullQuery := httptest.NewRecorder()
	handler.ServeHTTP(wFullQuery, reqFullQuery)
	if wFullQuery.Code != http.StatusOK {
		t.Fatalf("expected status 200 from handler for query form, got %d: %s", wFullQuery.Code, wFullQuery.Body.String())
	}
	var resFullQuery IPDetailsResponse
	if err := json.NewDecoder(wFullQuery.Body).Decode(&resFullQuery); err != nil {
		t.Fatalf("decode ip details from handler for query: %v", err)
	}
	if resFullQuery.IP != "203.0.113.195" {
		t.Errorf("expected IP 203.0.113.195, got %s", resFullQuery.IP)
	}
}




