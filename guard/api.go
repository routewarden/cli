package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/routewarden/cli/guard/crowdsec"
)

// APIServer exposes guard health, banlist management, stats, and real-time SSE events.
type APIServer struct {
	listen    string
	token     string
	cfg       *Config
	banlist   *BanList
	stats     *StatsRegistry
	bus       *EventBus
	csClient  *crowdsec.Client
	startTime time.Time

	srv *http.Server
}

// NewAPIServer creates an APIServer instance.
func NewAPIServer(
	cfg *Config,
	bl *BanList,
	stats *StatsRegistry,
	bus *EventBus,
	cs *crowdsec.Client,
) *APIServer {
	listen := cfg.API.Listen
	if listen == "" {
		listen = "127.0.0.1:9091"
	}

	return &APIServer{
		listen:    listen,
		token:     cfg.API.Token,
		cfg:       cfg,
		banlist:   bl,
		stats:     stats,
		bus:       bus,
		csClient:  cs,
		startTime: time.Now(),
	}
}

// Start runs the HTTP server in background and blocks until ctx is canceled or an error occurs.
func (a *APIServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/api/guard/health", a.handleHealth)
	mux.HandleFunc("/api/guard/services", a.auth(a.handleServices))
	mux.HandleFunc("/api/guard/stats", a.auth(a.handleStats))
	mux.HandleFunc("/api/guard/banlist", a.auth(a.handleBanlist))
	mux.HandleFunc("/api/guard/unban", a.auth(a.handleUnban))
	mux.HandleFunc("/api/guard/ban", a.auth(a.handleBan))
	mux.HandleFunc("/api/guard/events", a.auth(a.handleEventsSSE))

	a.srv = &http.Server{
		Addr:    a.listen,
		Handler: a.corsMiddleware(mux),
	}

	log.Printf("[guard:api] listening on http://%s", a.listen)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = a.srv.Shutdown(shutdownCtx)
	}()

	if err := a.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("guard api server on %s: %w", a.listen, err)
	}
	return nil
}

func (a *APIServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Guard-Token")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *APIServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.token != "" {
			authHeader := r.Header.Get("Authorization")
			tokenHeader := r.Header.Get("X-Guard-Token")

			token := ""
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			} else if tokenHeader != "" {
				token = tokenHeader
			}

			if token != a.token {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func (a *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(a.startTime)
	csConnected := false
	csIpCount, csRangeCount := 0, 0
	if a.csClient != nil {
		csConnected = true
		csIpCount, csRangeCount = a.csClient.DecisionCount()
	}

	resp := map[string]interface{}{
		"status":              "healthy",
		"version":             "guard-v4.0.0",
		"uptime":              uptime.String(),
		"uptime_seconds":      int64(uptime.Seconds()),
		"services_count":      len(a.cfg.Services),
		"crowdsec_connected":  csConnected,
		"crowdsec_decisions":  csIpCount + csRangeCount,
		"active_bans_count":   len(a.banlist.Snapshot()),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *APIServer) handleServices(w http.ResponseWriter, r *http.Request) {
	type svcItem struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Listen   string `json:"listen"`
		Upstream string `json:"upstream"`
		Enabled  bool   `json:"enabled"`
	}

	services := make([]svcItem, 0, len(a.cfg.Services))
	for _, s := range a.cfg.Services {
		services = append(services, svcItem{
			Name:     s.Name,
			Protocol: s.Protocol,
			Listen:   s.Listen,
			Upstream: s.Upstream,
			Enabled:  s.Enabled,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"services": services,
	})
}

func (a *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	services, totals, uptime := a.stats.SnapshotAll()

	resp := map[string]interface{}{
		"services": services,
		"totals":   totals,
		"uptime":   uptime.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *APIServer) handleBanlist(w http.ResponseWriter, r *http.Request) {
	bans := a.banlist.Snapshot()

	type banView struct {
		IP               string    `json:"ip"`
		Reason           string    `json:"reason"`
		Service          string    `json:"service"`
		BannedAt         time.Time `json:"banned_at"`
		ExpiresAt        time.Time `json:"expires_at"`
		RemainingSeconds int64     `json:"remaining_seconds"`
	}

	now := time.Now()
	view := make([]banView, 0, len(bans))
	for _, b := range bans {
		rem := int64(b.ExpiresAt.Sub(now).Seconds())
		if rem < 0 {
			rem = 0
		}
		view = append(view, banView{
			IP:               b.IP,
			Reason:           b.Reason,
			Service:          b.Service,
			BannedAt:         b.BannedAt,
			ExpiresAt:        b.ExpiresAt,
			RemainingSeconds: rem,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"count": len(view),
		"bans":  view,
	})
}

func (a *APIServer) handleUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, `{"error":"invalid ip in request body"}`, http.StatusBadRequest)
		return
	}

	a.banlist.Unban(req.IP)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("unbanned %s", req.IP),
	})
}

func (a *APIServer) handleBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP              string `json:"ip"`
		DurationSeconds int    `json:"duration_seconds"`
		Reason          string `json:"reason"`
		Service         string `json:"service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, `{"error":"invalid ip in request body"}`, http.StatusBadRequest)
		return
	}

	dur := 3600 * time.Second
	if req.DurationSeconds > 0 {
		dur = time.Duration(req.DurationSeconds) * time.Second
	}
	reason := "manual ban"
	if req.Reason != "" {
		reason = req.Reason
	}
	svc := "admin"
	if req.Service != "" {
		svc = req.Service
	}

	a.banlist.Ban(req.IP, reason, svc, dur)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("banned %s for %v", req.IP, dur),
	})
}

func (a *APIServer) handleEventsSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := a.bus.Subscribe(100)
	defer unsub()

	// Initial comment to confirm connection
	_, _ = fmt.Fprintf(w, ": connected to guard event stream\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(ev)
			if err == nil {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}
