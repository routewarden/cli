package crowdsec

import (
	"net"
	"testing"
)

func TestCrowdSecDecisionCache(t *testing.T) {
	client := NewClient("http://127.0.0.1:8080", "testkey", 10)

	// Inject test IP decision
	client.ipBans["198.51.100.42"] = "crowdsecurity/ssh-bf"

	// Inject test CIDR decision
	_, ipNet, _ := net.ParseCIDR("203.0.113.0/24")
	client.rangeBans["203.0.113.0/24"] = rangeItem{
		net:      ipNet,
		scenario: "crowdsecurity/smtp-spam",
	}

	// Test direct IP ban
	banned, reason := client.IsBanned("198.51.100.42")
	if !banned || reason != "crowdsec: crowdsecurity/ssh-bf" {
		t.Fatalf("expected 198.51.100.42 banned, got %v (%s)", banned, reason)
	}

	// Test unbanned IP
	banned, _ = client.IsBanned("1.1.1.1")
	if banned {
		t.Fatalf("expected 1.1.1.1 not banned")
	}

	// Test range match
	banned, reason = client.IsBanned("203.0.113.55")
	if !banned || reason != "crowdsec: crowdsecurity/smtp-spam" {
		t.Fatalf("expected 203.0.113.55 banned by range, got %v (%s)", banned, reason)
	}

	// Test IP outside range
	banned, _ = client.IsBanned("203.0.114.1")
	if banned {
		t.Fatalf("expected 203.0.114.1 not banned")
	}

	ipCount, rangeCount := client.DecisionCount()
	if ipCount != 1 || rangeCount != 1 {
		t.Fatalf("expected (1, 1), got (%d, %d)", ipCount, rangeCount)
	}
}
