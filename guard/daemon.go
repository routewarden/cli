package guard

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/routewarden/cli/guard/crowdsec"
)

// Daemon manages one TCP listener per configured service, manages the
// HTTP API server, and coordinates metrics, logs, and hot reload.
type Daemon struct {
	mu         sync.RWMutex
	cfg        *Config
	configPath string

	banlist   *BanList
	failures  *FailureTracker
	limiter   *RateLimiter
	bus       *EventBus
	stats     *StatsRegistry
	logger    *LogWriter
	crowdsec  *crowdsec.Client
	apiServer *APIServer
	pipeline  *Pipeline
}

// NewDaemon creates a Daemon from a validated Config and optional configPath.
func NewDaemon(cfg *Config, configPath string) (*Daemon, error) {
	bl := NewBanList()
	ft := NewFailureTracker(bl)
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()

	// Register services in stats registry
	for _, s := range cfg.Services {
		if s.Enabled {
			stats.RegisterService(s.Name, s.Protocol, s.Listen, s.Upstream)
		}
	}

	// Initialize structured log writer if configured
	var logger *LogWriter
	if cfg.Global.LogFile != "" {
		lw, err := NewLogWriter(cfg.Global.LogFile)
		if err != nil {
			return nil, fmt.Errorf("opening log writer: %w", err)
		}
		logger = lw
		log.Printf("[guard] logging events to %s", cfg.Global.LogFile)
	}

	// Initialize CrowdSec LAPI bouncer if enabled
	var csClient *crowdsec.Client
	if cfg.CrowdSec.Enabled {
		csClient = crowdsec.NewClient(
			cfg.CrowdSec.LAPIURL,
			cfg.CrowdSec.APIKey,
			cfg.CrowdSec.UpdateIntervalSeconds,
		)
		log.Printf("[guard] CrowdSec LAPI bouncer enabled (url: %s)", cfg.CrowdSec.LAPIURL)
	}

	pipeline := NewPipeline(cfg, bl, ft, rl, bus, stats, logger, csClient)

	d := &Daemon{
		cfg:        cfg,
		configPath: configPath,
		banlist:    bl,
		failures:   ft,
		limiter:    rl,
		bus:        bus,
		stats:      stats,
		logger:     logger,
		crowdsec:   csClient,
		pipeline:   pipeline,
	}

	if cfg.API.Enabled {
		d.apiServer = NewAPIServer(cfg, bl, stats, bus, csClient)
	}

	return d, nil
}

// Bus returns the EventBus so external subscribers can tap in.
func (d *Daemon) Bus() *EventBus { return d.bus }

// BanList returns the live banlist for API exposure.
func (d *Daemon) BanList() *BanList { return d.banlist }

// Stats returns the stats registry.
func (d *Daemon) Stats() *StatsRegistry { return d.stats }

// Run starts all configured service listeners and the API server.
// Blocks until ctx is cancelled or a fatal listener error occurs.
func (d *Daemon) Run(ctx context.Context) error {
	defer func() {
		if d.logger != nil {
			_ = d.logger.Close()
		}
		if d.crowdsec != nil {
			d.crowdsec.Stop()
		}
	}()

	// Start CrowdSec background sync if client present
	if d.crowdsec != nil {
		d.crowdsec.Start(ctx)
	}

	// Start SIGHUP listener for config hot reload
	if d.configPath != "" {
		go d.listenSignals(ctx)
	}

	// Start API server if enabled
	if d.apiServer != nil {
		go func() {
			if err := d.apiServer.Start(ctx); err != nil {
				log.Printf("[guard:api] server error: %v", err)
			}
		}()
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(d.cfg.Services))

	d.mu.RLock()
	services := make([]ServiceConfig, len(d.cfg.Services))
	copy(services, d.cfg.Services)
	d.mu.RUnlock()

	for i := range services {
		svc := &services[i]
		if !svc.Enabled {
			continue
		}
		wg.Add(1)
		go func(s *ServiceConfig) {
			defer wg.Done()
			if err := d.runListener(ctx, s); err != nil {
				errCh <- fmt.Errorf("service %q: %w", s.Name, err)
			}
		}(svc)
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) runListener(ctx context.Context, svc *ServiceConfig) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", svc.Listen)
	if err != nil {
		return fmt.Errorf("bind %s: %w", svc.Listen, err)
	}
	defer ln.Close()

	log.Printf("[guard] %s: listening on %s → %s (%s)", svc.Name, svc.Listen, svc.Upstream, svc.Protocol)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[guard] %s: accept error: %v", svc.Name, err)
				continue
			}
		}
		go d.pipeline.Handle(ctx, conn, svc)
	}
}

func (d *Daemon) listenSignals(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sigCh:
			log.Printf("[guard] SIGHUP received, reloading configuration from %s...", d.configPath)
			if err := d.reloadConfig(); err != nil {
				log.Printf("[guard] configuration reload failed: %v", err)
			} else {
				log.Printf("[guard] configuration reloaded successfully")
			}
		}
	}
}

func (d *Daemon) reloadConfig() error {
	newCfg, err := LoadConfig(d.configPath)
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.cfg = newCfg
	// Update pipeline config reference
	d.pipeline.cfg = newCfg

	// Ensure any newly configured services are registered in stats
	for _, s := range newCfg.Services {
		if s.Enabled && d.stats.Get(s.Name) == nil {
			d.stats.RegisterService(s.Name, s.Protocol, s.Listen, s.Upstream)
		}
	}

	return nil
}
