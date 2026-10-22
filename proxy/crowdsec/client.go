package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DecisionItem represents a single decision rule from CrowdSec LAPI.
type DecisionItem struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"` // "Ip" or "Range"
	Type     string `json:"type"`  // "ban", "throttle", "bypass"
	Value    string `json:"value"` // IP or CIDR
	Duration string `json:"duration"`
}

// DecisionResult represents an active decision matching a queried IP.
type DecisionResult struct {
	Action   string `json:"action"`   // "ban", "throttle", "bypass"
	Scenario string `json:"scenario"` // rule name
	Origin   string `json:"origin"`   // "crowdsec", "CAPI", "cscli"
	Scope    string `json:"scope"`    // "Ip" or "Range"
	Value    string `json:"value"`    // IP or CIDR
}

// StreamResponse represents the response from /v1/decisions/stream.
type StreamResponse struct {
	New     []DecisionItem `json:"new"`
	Deleted []DecisionItem `json:"deleted"`
}

type rangeItem struct {
	net      *net.IPNet
	decision DecisionResult
}

// Client is a CrowdSec LAPI bouncer client that streams and caches decisions in memory.
type Client struct {
	mu             sync.RWMutex
	lapiURL        string
	apiKey         string
	updateInterval time.Duration
	httpClient     *http.Client
	warnf          func(format string, args ...any)

	ipDecisions    map[string]DecisionResult // ip -> decision
	rangeDecisions map[string]rangeItem      // cidr -> item

	lastSync time.Time
	lastErr  error
	started  bool
	cancel   context.CancelFunc
}

// Config holds client initialization parameters.
type Config struct {
	LAPIURL        string
	APIKey         string
	UpdateInterval time.Duration
	HTTPClient     *http.Client
	// WarnFunc is called for non-fatal warnings (e.g. sync failures).
	// Defaults to log.Printf when nil.
	WarnFunc func(format string, args ...any)
}

// NewClient creates a new CrowdSec bouncer client.
func NewClient(cfg Config) *Client {
	interval := cfg.UpdateInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	warnf := cfg.WarnFunc
	if warnf == nil {
		warnf = func(format string, args ...any) { log.Printf("⚠️ "+format, args...) }
	}
	return &Client{
		lapiURL:        strings.TrimRight(cfg.LAPIURL, "/"),
		apiKey:         cfg.APIKey,
		updateInterval: interval,
		httpClient:     httpClient,
		warnf:          warnf,
		ipDecisions:    make(map[string]DecisionResult),
		rangeDecisions: make(map[string]rangeItem),
	}
}

// Start begins periodic polling of /v1/decisions/stream.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.started = true
	c.mu.Unlock()

	// Initial startup fetch
	if err := c.sync(true); err != nil {
		c.warnf("CrowdSec initial sync warning (will retry in %s): %v", c.updateInterval, err)
	}

	go func() {
		ticker := time.NewTicker(c.updateInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.sync(false); err != nil {
					c.warnf("CrowdSec sync failed: %v", err)
				}
			}
		}
	}()

	return nil
}

// Stop terminates the periodic sync loop.
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	c.started = false
}

// Check queries the in-memory cache for an active decision on ipStr.
func (c *Client) Check(ipStr string) (DecisionResult, bool) {
	ipStr = strings.TrimSpace(ipStr)
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	ipStr = strings.Trim(ipStr, "[]")
	if idx := strings.IndexByte(ipStr, '%'); idx != -1 {
		ipStr = ipStr[:idx]
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP != nil {
		if v4 := parsedIP.To4(); v4 != nil {
			ipStr = v4.String()
		} else {
			ipStr = parsedIP.String()
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if dec, ok := c.ipDecisions[ipStr]; ok {
		return dec, true
	}

	if parsedIP == nil {
		return DecisionResult{}, false
	}

	for _, item := range c.rangeDecisions {
		if item.net.Contains(parsedIP) {
			return item.decision, true
		}
	}

	return DecisionResult{}, false
}

// DecisionCount returns the number of active cached decisions.
func (c *Client) DecisionCount() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.ipDecisions), len(c.rangeDecisions)
}

// LastSync returns the last successful sync time and error if any.
func (c *Client) LastSync() (time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSync, c.lastErr
}

func (c *Client) sync(startup bool) error {
	endpoint := fmt.Sprintf("%s/v1/decisions/stream", c.lapiURL)
	if startup {
		endpoint += "?startup=true"
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		c.setErr(err)
		return err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", "routewarden-tcp-warden/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.setErr(err)
		return fmt.Errorf("calling crowdsec LAPI stream: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("crowdsec LAPI returned status %d", resp.StatusCode)
		c.setErr(err)
		return err
	}

	var streamResp StreamResponse
	if err := json.NewDecoder(resp.Body).Decode(&streamResp); err != nil {
		c.setErr(err)
		return fmt.Errorf("decoding stream response: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if startup {
		c.ipDecisions = make(map[string]DecisionResult)
		c.rangeDecisions = make(map[string]rangeItem)
	}

	// Remove deleted decisions
	for _, del := range streamResp.Deleted {
		val := strings.TrimSpace(del.Value)
		val = strings.Trim(val, "[]")
		if parsed := net.ParseIP(val); parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				val = v4.String()
			} else {
				val = parsed.String()
			}
		}
		if strings.EqualFold(del.Scope, "Ip") || !strings.Contains(val, "/") {
			delete(c.ipDecisions, val)
		} else {
			delete(c.rangeDecisions, val)
		}
	}

	// Add new decisions
	for _, it := range streamResp.New {
		val := strings.TrimSpace(it.Value)
		val = strings.Trim(val, "[]")
		if parsed := net.ParseIP(val); parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				val = v4.String()
			} else {
				val = parsed.String()
			}
		}
		dec := DecisionResult{
			Action:   it.Type,
			Scenario: it.Scenario,
			Origin:   it.Origin,
			Scope:    it.Scope,
			Value:    val,
		}
		if strings.EqualFold(it.Scope, "Ip") || !strings.Contains(val, "/") {
			c.ipDecisions[val] = dec
		} else {
			_, ipNet, err := net.ParseCIDR(val)
			if err == nil {
				c.rangeDecisions[val] = rangeItem{
					net:      ipNet,
					decision: dec,
				}
			}
		}
	}

	c.lastSync = time.Now()
	c.lastErr = nil
	return nil
}

func (c *Client) setErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastErr = err
}
