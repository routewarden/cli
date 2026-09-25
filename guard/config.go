package guard

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// Config is the top-level structure for netguard.json.
type Config struct {
	Enabled   bool            `json:"enabled"`
	Dashboard DashboardCfg    `json:"dashboard"`
	API       APIConfig       `json:"api"`
	CrowdSec  CrowdSecConfig  `json:"crowdsec"`
	Global    GlobalPolicy    `json:"global"`
	Services  []ServiceConfig `json:"services"`
}

// APIConfig controls the guard management and metrics HTTP API.
type APIConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"` // e.g. "127.0.0.1:9091"
	Token   string `json:"token"`  // optional Bearer / X-Guard-Token
}

// CrowdSecConfig controls the CrowdSec LAPI bouncer integration.
type CrowdSecConfig struct {
	Enabled               bool   `json:"enabled"`
	LAPIURL               string `json:"lapiUrl"`               // e.g. "http://127.0.0.1:8080"
	APIKey                string `json:"apiKey"`                // Bouncer API key
	UpdateIntervalSeconds int    `json:"updateIntervalSeconds"` // default 15s
}

// DashboardCfg controls the embedded dashboard integration.
type DashboardCfg struct {
	Port int    `json:"port"` // 0 = use rwarden dashboard separately
	Host string `json:"host"`
}

// GlobalPolicy applies to all services unless overridden per-service.
type GlobalPolicy struct {
	AllowedIPs          []string `json:"allowedIPs"`          // CIDR or single IPs
	BlockedIPs          []string `json:"blockedIPs"`
	BlockCountries      []string `json:"blockCountries"`      // ISO 3166-1 alpha-2
	MaxConnectionsPerIP int      `json:"maxConnectionsPerIP"` // concurrent; 0 = unlimited
	BanAfterFailures    int      `json:"banAfterFailures"`    // 0 = no auto-ban
	BanDurationSeconds  int      `json:"banDurationSeconds"`  // default 3600
	TarpitMs            int      `json:"tarpitMs"`            // default 0 (disabled)
	LogFile             string   `json:"logFile"`             // for CrowdSec consumption
}

// ServiceConfig defines a single proxied TCP service.
type ServiceConfig struct {
	Name     string `json:"name"`     // human label, e.g. "ssh"
	Enabled  bool   `json:"enabled"`
	Listen   string `json:"listen"`   // e.g. ":2222"
	Upstream string `json:"upstream"` // e.g. "127.0.0.1:22"
	Protocol string `json:"protocol"` // "ssh" | "smtp" | "pop3" | "imap" | "tcp"

	// Per-service policy overrides (merged with Global)
	AllowedIPs         []string    `json:"allowedIPs,omitempty"`
	BlockedIPs         []string    `json:"blockedIPs,omitempty"`
	BlockCountries     []string    `json:"blockCountries,omitempty"`
	MaxAuthFailures    int         `json:"maxAuthFailures,omitempty"`
	BanAfterFailures   int         `json:"banAfterFailures,omitempty"`
	BanDurationSeconds int         `json:"banDurationSeconds,omitempty"`
	RateLimit          RateLimitCfg `json:"rateLimit,omitempty"`
	Response           ResponseCfg  `json:"response,omitempty"`

	// SMTP-specific
	BlockedSenderDomains []string `json:"blockedSenderDomains,omitempty"`
	RequireSTARTTLS      bool     `json:"requireSTARTTLS,omitempty"`
}

// RateLimitCfg defines sliding-window rate limits for a service.
type RateLimitCfg struct {
	ConnectionsPerMinute  int `json:"connectionsPerMinute,omitempty"`
	AuthAttemptsPerMinute int `json:"authAttemptsPerMinute,omitempty"`
}

// ResponseCfg defines what the guard does with a rejected connection.
type ResponseCfg struct {
	Mode          string `json:"mode"`                    // "drop" | "reject" | "tarpit" | "silent"
	TarpitMs      int    `json:"tarpitMs,omitempty"`      // override global
	RejectMessage string `json:"rejectMessage,omitempty"` // SMTP/banner message
}

// LoadConfig reads and validates a netguard.json file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate performs semantic validation on the loaded config.
func (c *Config) Validate() error {
	for i, svc := range c.Services {
		if svc.Name == "" {
			return fmt.Errorf("service[%d]: name is required", i)
		}
		if svc.Listen == "" {
			return fmt.Errorf("service %q: listen address is required", svc.Name)
		}
		if svc.Upstream == "" {
			return fmt.Errorf("service %q: upstream address is required", svc.Name)
		}
		proto := strings.ToLower(svc.Protocol)
		switch proto {
		case "ssh", "smtp", "pop3", "imap", "tcp", "":
		default:
			return fmt.Errorf("service %q: unknown protocol %q (valid: ssh, smtp, pop3, imap, tcp)", svc.Name, svc.Protocol)
		}
		for _, cidr := range append(svc.AllowedIPs, svc.BlockedIPs...) {
			if strings.Contains(cidr, "/") {
				if _, _, err := net.ParseCIDR(cidr); err != nil {
					return fmt.Errorf("service %q: invalid CIDR %q: %w", svc.Name, cidr, err)
				}
			} else if net.ParseIP(cidr) == nil {
				return fmt.Errorf("service %q: invalid IP %q", svc.Name, cidr)
			}
		}
	}

	if c.CrowdSec.Enabled {
		if c.CrowdSec.LAPIURL == "" {
			return fmt.Errorf("crowdsec: lapiUrl is required when enabled")
		}
		if c.CrowdSec.APIKey == "" {
			return fmt.Errorf("crowdsec: apiKey is required when enabled")
		}
	}
	if c.API.Enabled && c.API.Listen == "" {
		c.API.Listen = "127.0.0.1:9091"
	}
	return nil
}

// EffectiveBanAfterFailures returns the service-level value, falling back to global.
func (s *ServiceConfig) EffectiveBanAfterFailures(g *GlobalPolicy) int {
	if s.BanAfterFailures > 0 {
		return s.BanAfterFailures
	}
	return g.BanAfterFailures
}

// EffectiveBanDuration returns the service-level ban duration, falling back to global.
func (s *ServiceConfig) EffectiveBanDurationSeconds(g *GlobalPolicy) int {
	if s.BanDurationSeconds > 0 {
		return s.BanDurationSeconds
	}
	if g.BanDurationSeconds > 0 {
		return g.BanDurationSeconds
	}
	return 3600
}
