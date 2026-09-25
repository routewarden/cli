package dashboard

import (
	"net"
	"testing"
)

func TestCountryCodeToFlag(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"US", "🇺🇸"},
		{"DE", "🇩🇪"},
		{"IN", "🇮🇳"},
		{"GB", "🇬🇧"},
		{"FR", "🇫🇷"},
		{"JP", "🇯🇵"},
		{"LAN", "🏠"},
		{"local", "🏠"},
		{"", "🌐"},
		{"XYZ", "🌐"},
	}

	for _, tt := range tests {
		got := CountryCodeToFlag(tt.code)
		if got != tt.expected {
			t.Errorf("CountryCodeToFlag(%q) = %q, want %q", tt.code, got, tt.expected)
		}
	}
}

func TestLookupPrivateIP(t *testing.T) {
	privateIPs := []string{
		"127.0.0.1",
		"127.0.0.1:8080",
		"192.168.1.100",
		"10.0.0.1",
		"172.16.0.5",
		"::1",
		"fe80::1",
	}

	for _, ip := range privateIPs {
		res := LookupIP(ip)
		if res.CountryCode != "LAN" {
			t.Errorf("LookupIP(%q) CountryCode = %q, want %q", ip, res.CountryCode, "LAN")
		}
		if res.FlagEmoji != "🏠" {
			t.Errorf("LookupIP(%q) FlagEmoji = %q, want %q", ip, res.FlagEmoji, "🏠")
		}
	}
}

func TestLookupTailscaleAndNetBirdIP(t *testing.T) {
	vpnIPs := []struct {
		ip       string
		expected string
	}{
		{"100.100.100.100", "Tailscale / NetBird Mesh"},
		{"100.64.0.5", "NetBird / Tailscale Mesh"},
		{"100.85.12.34", "Tailscale / NetBird Mesh"},
		{"fd7a:115c:a1e0::1", "Tailscale Mesh IPv6"},
		{"fd00:64::1", "NetBird Mesh IPv6"},
	}

	for _, tc := range vpnIPs {
		res := LookupIP(tc.ip)
		if res.CountryCode != "VPN" {
			t.Errorf("LookupIP(%q) CountryCode = %q, want VPN", tc.ip, res.CountryCode)
		}
		if res.FlagEmoji != "🔒" {
			t.Errorf("LookupIP(%q) FlagEmoji = %q, want 🔒", tc.ip, res.FlagEmoji)
		}
		if res.CountryName != tc.expected {
			t.Errorf("LookupIP(%q) CountryName = %q, want %q", tc.ip, res.CountryName, tc.expected)
		}
		if !res.IsPrivate {
			t.Errorf("LookupIP(%q) IsPrivate = false, want true", tc.ip)
		}
	}
}

func TestLookupPublicKnownIP(t *testing.T) {
	res := LookupIP("8.8.8.8")
	if res.CountryCode != "US" || res.FlagEmoji != "🇺🇸" {
		t.Errorf("LookupIP(8.8.8.8) = %+v, want US/🇺🇸", res)
	}

	resCloudflare := LookupIP("1.1.1.1")
	if resCloudflare.CountryCode != "AU" || resCloudflare.FlagEmoji != "🇦🇺" {
		t.Errorf("LookupIP(1.1.1.1) = %+v, want AU/🇦🇺", resCloudflare)
	}
}

func TestEnrichGeoIP(t *testing.T) {
	e := SecurityEvent{
		ClientIP: "192.168.1.50",
	}
	enriched := EnrichGeoIP(e)
	if enriched.CountryCode != "LAN" || enriched.FlagEmoji != "🏠" {
		t.Errorf("EnrichGeoIP failed: got %+v", enriched)
	}
}

func TestIsPrivateOrLocal(t *testing.T) {
	if !isPrivateOrLocal(net.ParseIP("127.0.0.1")) {
		t.Errorf("expected 127.0.0.1 to be private")
	}
	if isPrivateOrLocal(net.ParseIP("8.8.8.8")) {
		t.Errorf("expected 8.8.8.8 not to be private")
	}
}
