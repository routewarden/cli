package guard

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
)

// Daemon manages one TCP listener per configured service and runs the
// connection pipeline for each accepted connection.
type Daemon struct {
	cfg      *Config
	banlist  *BanList
	failures *FailureTracker
	limiter  *RateLimiter
	bus      *EventBus
	pipeline *Pipeline
}

// NewDaemon creates a Daemon from a validated Config.
func NewDaemon(cfg *Config) *Daemon {
	bl := NewBanList()
	ft := NewFailureTracker(bl)
	rl := NewRateLimiter()
	bus := NewEventBus()
	return &Daemon{
		cfg:      cfg,
		banlist:  bl,
		failures: ft,
		limiter:  rl,
		bus:      bus,
		pipeline: NewPipeline(cfg, bl, ft, rl, bus),
	}
}

// Bus returns the EventBus so callers (e.g. the dashboard) can subscribe.
func (d *Daemon) Bus() *EventBus { return d.bus }

// BanList returns the live banlist for API exposure.
func (d *Daemon) BanList() *BanList { return d.banlist }

// Run starts all configured service listeners and blocks until ctx is
// cancelled or a listener fails to bind.
func (d *Daemon) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(d.cfg.Services))

	for i := range d.cfg.Services {
		svc := &d.cfg.Services[i]
		if !svc.Enabled {
			continue
		}
		wg.Add(1)
		go func(svc *ServiceConfig) {
			defer wg.Done()
			if err := d.runListener(ctx, svc); err != nil {
				errCh <- fmt.Errorf("service %q: %w", svc.Name, err)
			}
		}(svc)
	}

	// Close errCh when all listeners exit
	go func() {
		wg.Wait()
		close(errCh)
	}()

	// Return first fatal error, or nil on clean shutdown
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// runListener binds the TCP port for a single service and dispatches
// connections to the pipeline until ctx is cancelled.
func (d *Daemon) runListener(ctx context.Context, svc *ServiceConfig) error {
	proto := "tcp"
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, proto, svc.Listen)
	if err != nil {
		return fmt.Errorf("bind %s: %w", svc.Listen, err)
	}
	defer ln.Close()

	log.Printf("[guard] %s: listening on %s → %s", svc.Name, svc.Listen, svc.Upstream)

	// Stop accepting when ctx is cancelled
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil // clean shutdown
			default:
				log.Printf("[guard] %s: accept error: %v", svc.Name, err)
				continue
			}
		}
		go d.pipeline.Handle(ctx, conn, svc)
	}
}
