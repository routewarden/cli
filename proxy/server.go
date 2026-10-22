package proxy

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"sync"

	"github.com/routewarden/cli/proxy/config"
	"github.com/routewarden/cli/proxy/core"
)

//go:embed tcp-warden.yaml
var DefaultConfigFile []byte

// EventListener is invoked whenever a security event is published on the proxy event bus.
type EventListener func(event core.SecurityEvent)

// ServerOptions configures high-level proxy server behavior.
type ServerOptions struct {
	EventListener EventListener
	Verbose       bool
}

// Server coordinates the lifecycle of the Layer 4 security proxy.
type Server struct {
	cfg        *config.Config
	daemon     *core.Daemon
	opts       ServerOptions
	cancelSub  context.CancelFunc
	mu         sync.Mutex
	running    bool
}

// NewServer initializes a new Server from the provided configuration.
func NewServer(cfg *config.Config, opts ServerOptions) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	d, err := core.NewDaemon(cfg)
	if err != nil {
		return nil, fmt.Errorf("initialize daemon: %w", err)
	}

	return &Server{
		cfg:    cfg,
		daemon: d,
		opts:   opts,
	}, nil
}

// LoadConfig loads a configuration file from path or initializes a default if not found.
func LoadConfig(path string) (*config.Config, error) {
	if path == "" {
		path = "tcp-warden.yaml"
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, DefaultConfigFile, 0644); err != nil {
			return nil, fmt.Errorf("create default config %s: %w", path, err)
		}
	}
	return config.Load(path)
}

// Start begins listening and proxying traffic on all configured services.
// It blocks until ctx is canceled or an unrecoverable error occurs.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("proxy server is already running")
	}
	s.running = true

	// Wire event listener if provided
	if s.opts.EventListener != nil && s.daemon.EventBus() != nil {
		eventCh, unsub := s.daemon.EventBus().Subscribe(500)
		subCtx, cancel := context.WithCancel(ctx)
		s.cancelSub = cancel

		go func() {
			defer unsub()
			for {
				select {
				case <-subCtx.Done():
					return
				case ev, ok := <-eventCh:
					if !ok {
						return
					}
					s.opts.EventListener(ev)
				}
			}
		}()
	}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		if s.cancelSub != nil {
			s.cancelSub()
		}
		s.mu.Unlock()
	}()

	return s.daemon.Run(ctx)
}

// Stop terminates the running server, cancels background event subscriptions, and stops daemon listeners.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancelSub != nil {
		s.cancelSub()
		s.cancelSub = nil
	}
	if s.daemon != nil {
		s.daemon.Stop()
	}
	s.running = false
}

// Daemon returns the underlying core daemon.
func (s *Server) Daemon() *core.Daemon {
	return s.daemon
}

// Reload updates active server configuration.
func (s *Server) Reload(newCfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if newCfg == nil {
		return fmt.Errorf("configuration cannot be nil")
	}
	s.cfg = newCfg
	if s.daemon != nil {
		return s.daemon.Reload(newCfg)
	}
	return nil
}
