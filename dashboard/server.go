package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Server is the dashboard HTTP server. It serves:
//   - The embedded SPA static files (GET /)
//   - REST API endpoints (GET /api/*)
//   - WebSocket event stream (GET /ws/events)
type Server struct {
	opts    Options
	buf     *RingBuffer
	hub     *Hub
	docker  *DockerWatcher  // nil when Docker mode is disabled
	tailer  *FileTailer     // nil when no log files are configured
	version string
}

// Options configures the dashboard server.
type Options struct {
	Host       string   // bind host, default "127.0.0.1"
	Port       int      // bind port, default 9090
	LogFiles   []string // glob patterns for log files
	NoDocker   bool     // skip Docker socket discovery
	SocketPath string   // Docker socket path
	HistoryN   int      // number of past events to replay on page load
	Version    string   // rwarden binary version string
}

// NewServer creates and wires up all dashboard components.
func NewServer(opts Options) *Server {
	if opts.Port == 0 {
		opts.Port = 9090
	}
	if opts.Host == "" {
		opts.Host = "127.0.0.1"
	}
	if opts.SocketPath == "" {
		opts.SocketPath = "/var/run/docker.sock"
	}
	if opts.HistoryN <= 0 {
		opts.HistoryN = 1000
	}

	buf := NewRingBuffer(defaultRingSize)
	hub := NewHub()

	s := &Server{
		opts:    opts,
		buf:     buf,
		hub:     hub,
		version: opts.Version,
	}

	if !opts.NoDocker {
		s.docker = NewDockerWatcher(opts.SocketPath, buf, hub, "1h")
	}

	if len(opts.LogFiles) > 0 {
		s.tailer = NewFileTailer(opts.LogFiles, buf, hub)
	}

	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Static SPA assets — served from embedded FS defined in embed.go
	mux.Handle("/", http.FileServer(getSPAFileSystem()))

	// API routes
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/sources", s.handleSources)
	mux.HandleFunc("/api/sources/clear", s.handleClearSources)
	mux.HandleFunc("/api/config/", s.handleConfig)
	mux.HandleFunc("/api/geoip", s.handleGeoIP)
	mux.HandleFunc("/api/ip/", s.handleIPDetails)
	mux.HandleFunc("/api/ip", s.handleIPDetails)
	mux.HandleFunc("/api/health", s.handleHealth)

	// WebSocket
	mux.HandleFunc("/ws/events", s.handleWS)

	return corsMiddleware(mux)
}

// Run starts all background watchers and serves HTTP until the context is
// cancelled or the process receives SIGTERM.
func (s *Server) Run(ctx context.Context) error {
	// Start watchers
	if s.docker != nil {
		go s.docker.Run(ctx)
	}
	if s.tailer != nil {
		go s.tailer.Run(ctx)
	}

	addr := net.JoinHostPort(s.opts.Host, strconv.Itoa(s.opts.Port))
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // streaming responses need unlimited write time
		IdleTimeout:  120 * time.Second,
	}

	// Shut down gracefully when ctx is cancelled.
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Printf("RouteWarden Dashboard listening on http://%s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("dashboard server: %w", err)
	}
	return nil
}

// --- API handlers ---

// GET /api/events?n=1000&source=containerName
// Returns the last n events as JSON (initial page load).
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	n := s.opts.HistoryN
	if raw := r.URL.Query().Get("n"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			n = v
		}
	}
src := r.URL.Query().Get("source")
	events := s.buf.RecentFiltered(n, src)
	for i := range events {
		if events[i].CountryCode == "" && events[i].ClientIP != "" {
			events[i] = EnrichGeoIP(events[i])
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

// GET /api/stats?hours=24&source=containerName
// Returns aggregated statistics from the ring buffer.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if raw := r.URL.Query().Get("hours"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			hours = v
		}
	}
	src := r.URL.Query().Get("source")
	snap := s.buf.Stats(hours, src)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

// GET /api/sources — list sources
// DELETE /api/sources — clear stopped/inactive sources
func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.handleClearSources(w, r)
		return
	}
	sources := s.allSources()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sources)
}

// POST /api/sources/clear — clear stopped/inactive sources
func (s *Server) handleClearSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.docker != nil {
		s.docker.ClearStopped()
	}
	if s.tailer != nil {
		s.tailer.ClearStopped()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.allSources())
}

// GET /api/config/:id — returns routewarden.json configuration for a container/source
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/config/")
	id = strings.TrimSpace(id)
	if id == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ConfigResponse{
			Error: "Missing container or source ID in URL path",
		})
		return
	}

	var resp ConfigResponse

	// 1. Check Docker if available
	if s.docker != nil {
		resp = s.docker.GetContainerConfig(id)
		if resp.HasConfig {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// 2. Check local filesystem fallback (for file sources, local testing, or standalone)
	localPaths := []string{
		"routewarden.json",
		"./routewarden.json",
		"../routewarden.json",
		"samples/json/routewarden.json",
		"../samples/json/routewarden.json",
		"/etc/routewarden/routewarden.json",
	}
	for _, p := range localPaths {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			var parsed map[string]any
			if err := json.Unmarshal(data, &parsed); err == nil {
				resp = ConfigResponse{
					ID:        id,
					Name:      id,
					Kind:      "file",
					HasConfig: true,
					LabelKey:  p,
					Config:    parsed,
					Raw:       string(data),
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
		}
	}

	// If container was found in Docker but lacked routewarden.json label, return Docker's helpful message
	if resp.Name != "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// Container/source not found
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(ConfigResponse{
		ID:        id,
		HasConfig: false,
		Error:     fmt.Sprintf("Container or log source %q not found", id),
		Hint:      "Make sure the Docker container is running and has label routewarden.json='{...}'",
	})
}

// GET /api/geoip?ip=1.1.1.1 — returns GeoIP country and flag emoji
func (s *Server) handleGeoIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		http.Error(w, `{"error":"missing ip query parameter"}`, http.StatusBadRequest)
		return
	}

	res := LookupIP(ipStr)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// GET /api/ip/:ip or /api/ip?ip=...
// Returns complete geolocation, threat intelligence, and event history for an IP address.
func (s *Server) handleIPDetails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	ipStr := strings.TrimPrefix(r.URL.Path, "/api/ip/")
	ipStr = strings.TrimPrefix(ipStr, "/api/ip")
	ipStr = strings.Trim(ipStr, "/")
	if ipStr == "" {
		ipStr = r.URL.Query().Get("ip")
	}
	ipStr = strings.TrimSpace(ipStr)

	if ipStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "Missing IP parameter in path or query string",
		})
		return
	}

	resp := s.buf.IPDetails(ipStr)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}


// GET /api/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"version": s.version,
		"clients": s.hub.ClientCount(),
	})
}

// GET /ws/events — WebSocket upgrade
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	// We implement a minimal WebSocket handshake without any external library.
	// For v1 we use Server-Sent Events (SSE) instead, which requires no
	// upgrade and works in every browser natively — simpler than WebSocket for
	// unidirectional streaming.
	//
	// Clients connect to /ws/events and receive a continuous stream of
	// text/event-stream payloads:
	//   data: {"msg_type":"event","payload":{...}}\n\n
	//
	// SSE auto-reconnects on disconnect, making it ideal for the live feed.

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send a heartbeat comment every 15 s to keep the connection alive
	// through proxies and load balancers.
	ch := make(chan []byte, 64)
	s.hub.Register(ch)
	defer s.hub.Unregister(ch)

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	// Send current source list immediately on connect
	if sources := s.allSources(); len(sources) > 0 {
		msg := wsMessage{MsgType: "sources", Payload: sources}
		if data, err := json.Marshal(msg); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// allSources merges sources from the Docker watcher and file tailer.
func (s *Server) allSources() []Source {
	var out []Source
	if s.docker != nil {
		out = append(out, s.docker.SourceList()...)
	}
	if s.tailer != nil {
		out = append(out, s.tailer.SourceList()...)
	}
	return out
}

// corsMiddleware adds permissive CORS headers so the Vite dev server can
// proxy API requests during local frontend development.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}


