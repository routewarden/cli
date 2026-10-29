package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestCrowdSecClientSync(t *testing.T) {
	mockResponse := StreamResponse{
		New: []DecisionItem{
			{
				ID:       1,
				Origin:   "cscli",
				Scenario: "manual_ban",
				Scope:    "Ip",
				Type:     "ban",
				Value:    "192.0.2.100",
			},
			{
				ID:       2,
				Origin:   "crowdsec",
				Scenario: "routewarden/tcp-ssh-bf",
				Scope:    "Range",
				Type:     "ban",
				Value:    "198.51.100.0/24",
			},
		},
		Deleted: nil,
	}

	bodyBytes, _ := json.Marshal(mockResponse)

	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			if req.Header.Get("X-Api-Key") != "test-api-key" {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}
		}),
	}

	client := NewClient(Config{
		LAPIURL:        "http://mock-crowdsec",
		APIKey:         "test-api-key",
		UpdateInterval: 100 * time.Millisecond,
		HTTPClient:     httpClient,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := client.Start(ctx); err != nil {
		t.Fatalf("failed to start crowdsec client: %v", err)
	}

	// 1. Direct IP check
	dec, ok := client.Check("192.0.2.100")
	if !ok {
		t.Fatalf("expected decision for 192.0.2.100")
	}
	if dec.Action != "ban" || dec.Scenario != "manual_ban" {
		t.Errorf("unexpected decision: %+v", dec)
	}

	// 1b. IPv4-mapped IPv6 check against single IP ban
	decMapped, okMapped := client.Check("::ffff:192.0.2.100")
	if !okMapped {
		t.Fatalf("expected decision for ::ffff:192.0.2.100 against single IP ban")
	}
	if decMapped.Action != "ban" {
		t.Errorf("expected ban action for IPv4-mapped IPv6, got %q", decMapped.Action)
	}

	// 2. CIDR Range check
	decRange, okRange := client.Check("198.51.100.42")
	if !okRange {
		t.Fatalf("expected decision for 198.51.100.42 within range")
	}
	if decRange.Action != "ban" {
		t.Errorf("expected ban action, got %q", decRange.Action)
	}

	// 2b. IPv4-mapped IPv6 within CIDR Range check
	decRangeMapped, okRangeMapped := client.Check("::ffff:198.51.100.42")
	if !okRangeMapped {
		t.Fatalf("expected decision for ::ffff:198.51.100.42 within CIDR range")
	}
	if decRangeMapped.Action != "ban" {
		t.Errorf("expected ban action for mapped IP in range, got %q", decRangeMapped.Action)
	}

	// 3. Unbanned IP check
	_, okClean := client.Check("203.0.113.1")
	if okClean {
		t.Errorf("did not expect decision for clean IP 203.0.113.1")
	}

	ipCount, rangeCount := client.DecisionCount()
	if ipCount != 1 || rangeCount != 1 {
		t.Errorf("expected 1 ip and 1 range decision, got %d and %d", ipCount, rangeCount)
	}
}

func TestCrowdSecClient_IPv6ZoneStripping(t *testing.T) {
	mockResponse := StreamResponse{
		New: []DecisionItem{
			{
				ID:       10,
				Origin:   "crowdsec",
				Scenario: "routewarden/ipv6-scan",
				Scope:    "Ip",
				Type:     "ban",
				Value:    "fe80::dead:beef",
			},
		},
	}
	bodyBytes, _ := json.Marshal(mockResponse)
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}
		}),
	}
	client := NewClient(Config{
		LAPIURL:    "http://mock-crowdsec",
		HTTPClient: httpClient,
	})
	if err := client.sync(true); err != nil {
		t.Fatalf("sync error: %v", err)
	}

	// Query with zone identifier
	dec, ok := client.Check("fe80::dead:beef%eth0")
	if !ok {
		t.Fatalf("expected decision for fe80::dead:beef%%eth0")
	}
	if dec.Action != "ban" || dec.Scenario != "routewarden/ipv6-scan" {
		t.Errorf("unexpected decision: %+v", dec)
	}

	// Query bracketed with port and zone
	decPort, okPort := client.Check("[fe80::dead:beef%eth0]:12345")
	if !okPort {
		t.Fatalf("expected decision for [fe80::dead:beef%%eth0]:12345")
	}
	if decPort.Action != "ban" {
		t.Errorf("unexpected decision: %+v", decPort)
	}
}

func TestCrowdSecClient_BracketedIPv6CIDR_AndDeletion(t *testing.T) {
	mockNew := StreamResponse{
		New: []DecisionItem{
			{
				ID:       1,
				Origin:   "cscli",
				Scenario: "manual_ban",
				Scope:    "Range",
				Type:     "ban",
				Value:    "[2001:db8::]/64",
			},
		},
	}
	bodyBytes, _ := json.Marshal(mockNew)
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}
		}),
	}
	client := NewClient(Config{
		LAPIURL:    "http://mock-crowdsec",
		HTTPClient: httpClient,
	})
	if err := client.sync(true); err != nil {
		t.Fatalf("sync error: %v", err)
	}

	// 1. Should match IPv6 in bracketed CIDR
	dec, ok := client.Check("2001:db8::1234")
	if !ok {
		t.Fatalf("expected decision for 2001:db8::1234 in [2001:db8::]/64")
	}
	if dec.Action != "ban" {
		t.Errorf("expected ban action, got %q", dec.Action)
	}

	// 2. Test deletion with canonicalized CIDR
	mockDel := StreamResponse{
		Deleted: []DecisionItem{
			{
				Scope: "Range",
				Value: "2001:0db8::/64", // expanded zeros
			},
		},
	}
	delBytes, _ := json.Marshal(mockDel)
	httpClient.Transport = roundTripFunc(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(delBytes)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}
	})
	if err := client.sync(false); err != nil {
		t.Fatalf("sync error on deletion: %v", err)
	}

	_, okAfterDel := client.Check("2001:db8::1234")
	if okAfterDel {
		t.Errorf("expected 2001:db8::1234 to be unbanned after deletion")
	}
}
