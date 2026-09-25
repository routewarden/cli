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

// DecisionItem represents a single ban rule from CrowdSec LAPI.
type DecisionItem struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"` // "Ip" or "Range"
	Type     string `json:"type"`  // "ban"
	Value    string `json:"value"` // IP or CIDR
	Duration string `json:"duration"`
}

// StreamResponse represents the response from /v1/decisions/stream.
type StreamResponse struct {
	New     []DecisionItem `json:"new"`
	Deleted []DecisionItem `json:"deleted"`
}

type rangeItem struct {
	net      *net.IPNet
	scenario string
}

// Client is a CrowdSec LAPI bouncer client that streams and caches decisions in memory.
type Client struct {
	mu             sync.RWMutex
	lapiURL        string
	apiKey         string
	updateInterval time.Duration
	httpClient     *http.Client

	ipBans    map[string]string    // ip -> scenario
	rangeBans map[string]rangeItem // cidr -> item

	started bool
	cancel  context.CancelFunc
}

// NewClient creates a new CrowdSec bouncer client.
func NewClient(lapiURL, apiKey string, intervalSeconds int) *Client {
	if intervalSeconds <= 0 {
		intervalSeconds = 15
	}
	// Normalize URL: remove trailing slash
	lapiURL = strings.TrimRight(lapiURL, "/")

	return &Client{
		lapiURL:        lapiURL,
		apiKey:         apiKey,
		updateInterval: time.Duration(intervalSeconds) * time.Second,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		ipBans:    make(map[string]string),
		rangeBans: make(map[string]rangeItem),
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

// IsBanned checks whether an IP is in the CrowdSec local cache.
func (c *Client) IsBanned(ipStr string) (bool, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 1. Direct IP check
	if scenario, found := c.ipBans[ipStr]; found {
		return true, "crowdsec: " + scenario
	}

	// 2. Range / CIDR check
	parsed := net.ParseIP(ipStr)
	if parsed != nil {
		for _, r := range c.rangeBans {
			if r.net.Contains(parsed) {
				return true, "crowdsec: " + r.scenario
			}
		}
	}

	return false, ""
}

// DecisionCount returns current count of cached IP and Range decisions.
func (c *Client) DecisionCount() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.ipBans), len(c.rangeBans)
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
		return err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", "RouteWarden-Guard-Bouncer/v1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from LAPI", resp.StatusCode)
	}

	var data StreamResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decoding json: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if startup {
		// Replace all
		c.ipBans = make(map[string]string)
		c.rangeBans = make(map[string]rangeItem)
	}

	// Process deleted decisions
	for _, del := range data.Deleted {
		if strings.EqualFold(del.Scope, "Ip") {
			delete(c.ipBans, del.Value)
		} else if strings.EqualFold(del.Scope, "Range") {
			delete(c.rangeBans, del.Value)
		}
	}

	// Process new decisions
	for _, item := range data.New {
		if strings.EqualFold(item.Type, "ban") {
			if strings.EqualFold(item.Scope, "Ip") {
				c.ipBans[item.Value] = item.Scenario
			} else if strings.EqualFold(item.Scope, "Range") {
				_, ipNet, err := net.ParseCIDR(item.Value)
				if err == nil {
					c.rangeBans[item.Value] = rangeItem{
						net:      ipNet,
						scenario: item.Scenario,
					}
				}
			}
		}
	}

	return nil
}
