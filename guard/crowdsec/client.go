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

	ipDecisions    map[string]DecisionResult // ip -> decision
	rangeDecisions map[string]rangeItem      // cidr -> item

	lastSync time.Time
	lastErr  error
	started  bool
	cancel   context.CancelFunc
}

// NewClient creates a new CrowdSec bouncer client.
func NewClient(lapiURL, apiKey string, intervalSeconds int) *Client {
	if intervalSeconds <= 0 {
		intervalSeconds = 15
	}
	lapiURL = strings.TrimRight(lapiURL, "/")

	return &Client{
		lapiURL:        lapiURL,
		apiKey:         apiKey,
		updateInterval: time.Duration(intervalSeconds) * time.Second,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		ipDecisions:    make(map[string]DecisionResult),
		rangeDecisions: make(map[string]rangeItem),
	}
}

// Start begins background synchronization with CrowdSec LAPI.
func (c *Client) Start(ctx context.Context) {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.started = true
	c.mu.Unlock()

	go c.runSyncLoop(ctx)
}

// Stop shuts down the sync loop.
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	c.started = false
}

// Check queries whether an IP matches any cached CrowdSec decision.
func (c *Client) Check(ipStr string) *DecisionResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 1. Direct IP match
	if dec, found := c.ipDecisions[ipStr]; found {
		return &dec
	}

	// 2. CIDR Range match
	parsed := net.ParseIP(ipStr)
	if parsed != nil {
		for _, r := range c.rangeDecisions {
			if r.net.Contains(parsed) {
				return &r.decision
			}
		}
	}

	return nil
}

// IsBanned checks whether an IP is banned in the CrowdSec local cache.
func (c *Client) IsBanned(ipStr string) (bool, string) {
	dec := c.Check(ipStr)
	if dec != nil && (dec.Action == "ban" || dec.Action == "") {
		return true, "crowdsec: " + dec.Scenario
	}
	return false, ""
}

// DecisionCount returns current count of cached IP and Range decisions.
func (c *Client) DecisionCount() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.ipDecisions), len(c.rangeDecisions)
}

// Status returns current sync status and last error if any.
func (c *Client) Status() (bool, time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.started, c.lastSync, c.lastErr
}

// Ping verifies connectivity to the CrowdSec LAPI and checks API key validity.
func (c *Client) Ping() error {
	url := fmt.Sprintf("%s/v1/decisions?ip=127.0.0.1", c.lapiURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", "RouteWarden-Guard-Bouncer/v1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentication failed: invalid API key (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP response from LAPI: %d", resp.StatusCode)
	}
	return nil
}

// QueryLive queries the CrowdSec LAPI directly for real-time decisions on an IP.
func (c *Client) QueryLive(ipStr string) (*DecisionResult, error) {
	url := fmt.Sprintf("%s/v1/decisions?ip=%s", c.lapiURL, ipStr)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", "RouteWarden-Guard-Bouncer/v1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("live query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LAPI returned HTTP %d", resp.StatusCode)
	}

	var decisions []DecisionItem
	if err := json.NewDecoder(resp.Body).Decode(&decisions); err != nil {
		return nil, fmt.Errorf("decoding LAPI response: %w", err)
	}

	if len(decisions) == 0 {
		return nil, nil
	}

	first := decisions[0]
	return &DecisionResult{
		Action:   first.Type,
		Scenario: first.Scenario,
		Origin:   first.Origin,
		Scope:    first.Scope,
		Value:    first.Value,
	}, nil
}

func (c *Client) runSyncLoop(ctx context.Context) {
	startup := true
	ticker := time.NewTicker(c.updateInterval)
	defer ticker.Stop()

	// Initial poll immediately
	if err := c.pollStream(startup); err != nil {
		log.Printf("[guard:crowdsec] initial sync failed (will retry): %v", err)
	} else {
		startup = false
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.pollStream(startup); err != nil {
				log.Printf("[guard:crowdsec] sync error: %v", err)
			} else {
				startup = false
			}
		}
	}
}

func (c *Client) pollStream(startup bool) error {
	url := fmt.Sprintf("%s/v1/decisions/stream?startup=%t", c.lapiURL, startup)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.recordErr(err)
		return err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", "RouteWarden-Guard-Bouncer/v1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("http request: %w", err)
		c.recordErr(err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status %d from LAPI", resp.StatusCode)
		c.recordErr(err)
		return err
	}

	var data StreamResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		err = fmt.Errorf("decoding json: %w", err)
		c.recordErr(err)
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastSync = time.Now()
	c.lastErr = nil

	if startup {
		c.ipDecisions = make(map[string]DecisionResult)
		c.rangeDecisions = make(map[string]rangeItem)
	}

	// Process deleted decisions
	for _, del := range data.Deleted {
		if strings.EqualFold(del.Scope, "Ip") {
			delete(c.ipDecisions, del.Value)
		} else if strings.EqualFold(del.Scope, "Range") {
			delete(c.rangeDecisions, del.Value)
		}
	}

	// Process new decisions
	for _, item := range data.New {
		act := strings.ToLower(item.Type)
		if act == "" {
			act = "ban"
		}
		res := DecisionResult{
			Action:   act,
			Scenario: item.Scenario,
			Origin:   item.Origin,
			Scope:    item.Scope,
			Value:    item.Value,
		}

		if strings.EqualFold(item.Scope, "Ip") {
			c.ipDecisions[item.Value] = res
		} else if strings.EqualFold(item.Scope, "Range") {
			_, ipNet, err := net.ParseCIDR(item.Value)
			if err == nil {
				c.rangeDecisions[item.Value] = rangeItem{
					net:      ipNet,
					decision: res,
				}
			}
		}
	}

	return nil
}

func (c *Client) recordErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastErr = err
}
