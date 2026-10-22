package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/routewarden/cli/proxy/config"
	"github.com/routewarden/cli/proxy/crowdsec"
	"github.com/routewarden/cli/proxy/geoip"
	"github.com/routewarden/cli/proxy/plugins"
	_ "github.com/routewarden/cli/proxy/plugins/all"
)

// Daemon coordinates listeners, pipeline, CrowdSec client, and API server.
type Daemon struct {
	cfg       *config.Config
	banlist   *BanList
	failures  *FailureTracker
	limiter   *RateLimiter
	stats     *StatsRegistry
	bus       *EventBus
	logger    *LogWriter
	oplog     *Logger // operational (human-readable) logger
	crowdsec  *crowdsec.Client
	pipeline  *Pipeline
	apiServer *APIServer

	listeners []net.Listener
	udpConns  []*net.UDPConn // tracked for graceful shutdown
	mu        sync.Mutex
	wg        sync.WaitGroup
}

// NewDaemon initializes a Daemon instance from configuration.
func NewDaemon(cfg *config.Config) (*Daemon, error) {
	// Wire operational logger immediately so all init steps below can use it.
	oplog := NewLogger(ParseLevel(cfg.Global.LogLevel), nil)
	SetDefaultLogger(oplog)

	// 0. Sync plugins declared with a source in configuration (using cache or pulling fresh)
	for name, entry := range cfg.Plugins.Entries {
		if entry.Source != "" {
			res, err := plugins.SyncPluginFromSource(name, entry.Source, plugins.InstallOptions{
				NoBuild: true,
			})
			if err != nil {
				oplog.Warn("[PLUGIN SYNC] Failed syncing plugin %q from %s: %v", name, entry.Source, err)
			} else if !res.TestPassed {
				oplog.Warn("[PLUGIN SYNC] Plugin %q tests FAILED; plugin remains DISABLED", name)
			}
		}
	}

	// 1. Apply configured plugin enablement (pre-shipped non-standard plugins disabled by default)
	enabledList := append([]string(nil), cfg.Plugins.Enabled...)
	disabledList := append([]string(nil), cfg.Plugins.Disabled...)

	if pEnabled, pDisabled, err := plugins.GetPluginEnablement(plugins.ResolveProjectDir("")); err == nil {
		for _, pe := range pEnabled {
			if _, exists := cfg.Plugins.Entries[pe]; !exists {
				disabledList = removeFromList(disabledList, pe)
				if !contains(enabledList, pe) {
					enabledList = append(enabledList, pe)
				}
			}
		}
		for _, pd := range pDisabled {
			if _, exists := cfg.Plugins.Entries[pd]; !exists {
				enabledList = removeFromList(enabledList, pd)
				if !contains(disabledList, pd) {
					disabledList = append(disabledList, pd)
				}
			}
		}
	}

	// Auto-enable any installed plugin that is actively configured on an enabled service (unless explicitly disabled)
	for _, svc := range cfg.Services {
		if svc.IsEnabled() {
			proto := strings.ToLower(strings.TrimSpace(svc.Protocol))
			if proto != "" && proto != "tcp" && proto != "udp" && proto != "generic" {
				if !contains(disabledList, proto) && !contains(enabledList, proto) {
					enabledList = append(enabledList, proto)
				}
			}
		}
	}

	pluginErrs := plugins.ApplyConfiguration(enabledList, disabledList)
	for name, err := range pluginErrs {
		oplog.Warn("[PLUGIN] %q self-test FAILED and remains DISABLED: %v", name, err)
	}

	for _, pInfo := range plugins.List() {
		if pInfo.Enabled && pInfo.Status == plugins.StatusActive {
			oplog.Info("✓  [PLUGIN] %s (%s) is ACTIVE and healthy", pInfo.Name, pInfo.Version)
		}
	}

	// Check if any active service uses a disabled plugin
	for name, svc := range cfg.Services {
		if svc.IsEnabled() {
			switch strings.ToLower(strings.TrimSpace(svc.Protocol)) {
			case "tcp", "udp", "generic", "":
				// Standard built-in core protocol
			default:
				if !plugins.IsActive(svc.Protocol) {
					st, reason, testErr := plugins.GetStatus(svc.Protocol)
					oplog.Warn("[WARN] Service %q uses protocol %q, but plugin is %s (%s: %v). Inbound connections will be rejected.",
						name, svc.Protocol, st, reason, testErr)
				}
			}
		}
	}

	// Initialize GeoIP if DB path configured
	geoip.InitGeoIP(cfg.Global.GeoIPDB)

	bl := NewBanList(cfg.Global.DataDir)
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	stats := NewStatsRegistry()
	bus := NewEventBus()

	var logger *LogWriter
	if cfg.Global.LogFile != "" {
		l, err := NewLogWriter(cfg.Global.LogFile)
		if err != nil {
			oplog.Warn("could not initialize log file %s: %v (falling back to stdout)", cfg.Global.LogFile, err)
		}
		logger = l
	} else {
		logger, _ = NewLogWriter("")
	}
	// Apply the configured level to the security-event JSONL writer too.
	if logger != nil {
		logger.SetLevel(ParseLevel(cfg.Global.LogLevel))
	}

	var cs *crowdsec.Client
	if cfg.CrowdSec.Enabled {
		cs = crowdsec.NewClient(crowdsec.Config{
			LAPIURL:        cfg.CrowdSec.LAPIURL,
			APIKey:         cfg.CrowdSec.APIKey,
			UpdateInterval: cfg.CrowdSec.UpdateFrequency.Duration(),
			WarnFunc:       oplog.Warn,
		})
	}

	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, logger, cs)

	var apiSrv *APIServer
	if cfg.API.Enabled {
		apiSrv = NewAPIServer(cfg, bl, stats, bus, cs)
	}

	return &Daemon{
		cfg:       cfg,
		banlist:   bl,
		failures:  ft,
		limiter:   rl,
		stats:     stats,
		bus:       bus,
		logger:    logger,
		oplog:     oplog,
		crowdsec:  cs,
		pipeline:  pipe,
		apiServer: apiSrv,
		listeners: make([]net.Listener, 0),
		udpConns:  make([]*net.UDPConn, 0),
	}, nil
}

// Run starts all listeners and services, blocking until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	// 1. Start CrowdSec sync if enabled
	if d.crowdsec != nil {
		if err := d.crowdsec.Start(ctx); err != nil {
			d.oplog.Warn("Failed to start CrowdSec sync: %v", err)
		}
	}

	// 2. Start API server if enabled
	if d.apiServer != nil {
		go func() {
			if err := d.apiServer.Start(); err != nil && err != net.ErrClosed {
				d.oplog.Warn("API server error: %v", err)
			}
		}()
	}

	// 3. Start listeners for all enabled services (including port ranges)
	for name, svc := range d.cfg.Services {
		if !svc.IsEnabled() {
			continue
		}

		transport := strings.ToLower(strings.TrimSpace(svc.Transport))

		lHost, ports, err := svc.ListenPorts()
		if err != nil {
			d.Stop()
			return fmt.Errorf("parsing listen address for service %q (%s): %w", name, svc.Listen, err)
		}

		for _, port := range ports {
			listenAddr := config.FormatHostPort(lHost, port)

			// ── TCP listener (default / "tcp" / "both") ──────────────────
			if transport != "udp" {
				ln, err := net.Listen("tcp", listenAddr)
				if err != nil {
					d.Stop()
					return fmt.Errorf("starting TCP listener for service %q on %s: %w", name, listenAddr, err)
				}
				d.mu.Lock()
				d.listeners = append(d.listeners, ln)
				d.mu.Unlock()
				d.wg.Add(1)
				go d.serveService(ctx, ln, svc)
			}

			// ── UDP listener ("udp" / "both") ────────────────────────────
			if transport == "udp" || transport == "both" {
				udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
				if err != nil {
					d.Stop()
					return fmt.Errorf("resolving UDP address for service %q (%s): %w", name, listenAddr, err)
				}
				udpConn, err := net.ListenUDP("udp", udpAddr)
				if err != nil {
					d.Stop()
					return fmt.Errorf("starting UDP listener for service %q on %s: %w", name, listenAddr, err)
				}
				d.mu.Lock()
				d.udpConns = append(d.udpConns, udpConn)
				d.mu.Unlock()
				d.wg.Add(1)
				go d.serveUDPService(ctx, udpConn, svc)
			}
		}
	}

	// Wait for context cancellation
	<-ctx.Done()
	d.Stop()
	d.wg.Wait()
	return nil
}

func (d *Daemon) serveService(ctx context.Context, ln net.Listener, svc config.ServiceConfig) {
	defer d.wg.Done()
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				// Fatal: listener was deliberately closed.
				if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed") {
					return
				}
				// Transient OS error (e.g. "too many open files") — log and retry.
				d.oplog.Warn("[%s] Accept error (retrying in 100ms): %v", svc.Name, err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		go d.pipeline.Handle(ctx, conn, &svc)
	}
}

// Stop cleanly terminates all listeners, API server, and logs.
func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, ln := range d.listeners {
		ln.Close()
	}
	d.listeners = nil

	for _, conn := range d.udpConns {
		conn.Close()
	}
	d.udpConns = nil

	if d.apiServer != nil {
		d.apiServer.Close()
	}
	if d.crowdsec != nil {
		d.crowdsec.Stop()
	}
	if d.limiter != nil {
		d.limiter.Stop()
	}
	if d.failures != nil {
		d.failures.Stop()
	}
	if d.banlist != nil {
		d.banlist.Close()
	}
	if d.bus != nil {
		d.bus.Close()
	}
	if d.logger != nil {
		d.logger.Close()
	}
}

func contains(list []string, item string) bool {
	for _, s := range list {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func removeFromList(list []string, item string) []string {
	var res []string
	for _, s := range list {
		if !strings.EqualFold(s, item) {
			res = append(res, s)
		}
	}
	return res
}

// EventBus returns the in-memory pub-sub bus for security events.
func (d *Daemon) EventBus() *EventBus {
	return d.bus
}

// BanList returns the in-memory/persistent ban list.
func (d *Daemon) BanList() *BanList {
	return d.banlist
}

// Config returns the current configuration.
func (d *Daemon) Config() *config.Config {
	return d.cfg
}

// Reload updates dynamic configuration for the running daemon, such as log levels and runtime settings.
func (d *Daemon) Reload(newCfg *config.Config) error {
	if newCfg == nil {
		return errors.New("configuration cannot be nil")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg = newCfg

	lvl := ParseLevel(newCfg.Global.LogLevel)
	if d.oplog != nil {
		d.oplog.SetLevel(lvl)
	}
	if d.logger != nil {
		d.logger.SetLevel(lvl)
	}
	return nil
}

