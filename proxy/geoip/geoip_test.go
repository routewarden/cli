package geoip

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestCountryCodeToFlag(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"US", "🇺🇸"},
		{"DE", "🇩🇪"},
		{"FR", "🇫🇷"},
		{"LAN", "🏠"},
		{"VPN", "🔒"},
		{"XX", "🌐"},
		{"INVALID", "🌐"},
	}

	for _, tt := range tests {
		got := CountryCodeToFlag(tt.code)
		if got != tt.expected {
			t.Errorf("CountryCodeToFlag(%q) = %q; expected %q", tt.code, got, tt.expected)
		}
	}
}

func TestIsPrivateOrLocal(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.1.20", true},
		{"192.168.1.1", true},
		{"172.16.0.5", true},
		{"100.64.0.1", true}, // CGNAT
		{"198.51.100.5", true}, // RFC 5737 Test Net
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		parsed := net.ParseIP(tt.ip)
		if parsed == nil {
			t.Fatalf("failed to parse IP %q", tt.ip)
		}
		got := IsPrivateOrLocal(parsed)
		if got != tt.expected {
			t.Errorf("IsPrivateOrLocal(%q) = %v; expected %v", tt.ip, got, tt.expected)
		}
	}
}

func TestLookupIP(t *testing.T) {
	res := LookupIP("127.0.0.1")
	if res.CountryCode != "LAN" {
		t.Errorf("Expected country LAN for 127.0.0.1, got %q", res.CountryCode)
	}
	if !res.IsPrivate {
		t.Errorf("Expected IsPrivate=true for 127.0.0.1")
	}

	resPublic := LookupIP("8.8.8.8")
	if resPublic.IsPrivate {
		t.Errorf("Expected IsPrivate=false for 8.8.8.8")
	}
}

func TestMMDBReader_ResolveDataBoundary(t *testing.T) {
	// Verify resolveData does not panic when offset is near the end of the buffer (between 128 and 256 bytes from end)
	buf := make([]byte, 300)
	reader := &mmdbReader{
		buffer:      buf,
		dataSection: 100,
	}
	// offset 50 -> dataStart = 150. len(buf) = 300. dataStart+256 = 406 > 300.
	// Previously this paniced with slice bounds out of range.
	code, name, ok := reader.resolveData(50)
	if ok {
		t.Errorf("expected ok=false for empty chunk, got %q, %q", code, name)
	}

	// Also test offset completely past buffer length
	code, name, ok = reader.resolveData(300)
	if ok {
		t.Errorf("expected ok=false for past buffer chunk, got %q, %q", code, name)
	}
}

func TestLookupIP_CacheBounding(t *testing.T) {
	res1 := LookupIP("192.168.1.100")
	if res1.CountryCode != "LAN" {
		t.Errorf("expected LAN, got %s", res1.CountryCode)
	}
	res2 := LookupIP("192.168.1.100")
	if res2.CountryCode != "LAN" {
		t.Errorf("expected LAN on cached read, got %s", res2.CountryCode)
	}
}

func TestLookupIP_CacheEvictionThreshold(t *testing.T) {
	ResetCache()
	t.Cleanup(func() {
		ResetCache()
	})

	// Artificially advance the counter to maxGeoCacheEntries
	geoCacheCount.Store(maxGeoCacheEntries)

	// Trigger next insert for a fresh IP which should trigger eviction of the entire cache and re-insert the newest entry
	testIP := fmt.Sprintf("192.168.200.%d", time.Now().UnixNano()%250+1)
	cacheStore(testIP, GeoResult{
		IP:          testIP,
		CountryCode: "LAN",
		CountryName: "Local Network",
		FlagEmoji:   "🏠",
		IsPrivate:   true,
	})

	// Verify counter was reset and current count is 1
	currentCount := geoCacheCount.Load()
	if currentCount != 1 {
		t.Errorf("expected geoCacheCount to reset to 1 after eviction, got %d", currentCount)
	}

	// Verify the new entry exists in cache
	if val, ok := geoCache.Load(testIP); !ok {
		t.Error("expected newly stored key to exist after eviction")
	} else {
		res := val.(GeoResult)
		if res.CountryCode != "LAN" {
			t.Errorf("expected LAN, got %s", res.CountryCode)
		}
	}
}

func TestIsPrivateOrLocal_Comprehensive(t *testing.T) {
	testCases := []struct {
		ip       string
		expected bool
		desc     string
	}{
		// Standard RFC 1918 Private IPv4
		{"10.0.0.1", true, "RFC1918 10/8"},
		{"10.255.255.254", true, "RFC1918 10/8 high"},
		{"172.16.0.1", true, "RFC1918 172.16/12 low"},
		{"172.31.255.254", true, "RFC1918 172.16/12 high"},
		{"192.168.0.1", true, "RFC1918 192.168/16 low"},
		{"192.168.255.254", true, "RFC1918 192.168/16 high"},

		// Loopback
		{"127.0.0.1", true, "IPv4 loopback"},
		{"127.100.200.1", true, "IPv4 loopback range"},
		{"::1", true, "IPv6 loopback"},

		// Carrier-Grade NAT (CGNAT) 100.64.0.0/10 (Used by Tailscale, Starlink, cellular)
		{"100.64.0.1", true, "CGNAT low"},
		{"100.100.100.100", true, "Tailscale CGNAT magic DNS"},
		{"100.127.255.254", true, "CGNAT high"},
		{"100.128.0.1", false, "Outside CGNAT boundary"},

		// Benchmark 198.18.0.0/15
		{"198.18.0.1", true, "Benchmark low"},
		{"198.19.255.254", true, "Benchmark high"},
		{"198.20.0.1", false, "Outside benchmark"},

		// RFC 5737 Documentation Nets
		{"192.0.2.1", true, "TEST-NET-1"},
		{"198.51.100.1", true, "TEST-NET-2"},
		{"203.0.113.1", true, "TEST-NET-3"},

		// IPv6 Link-Local and ULA
		{"fe80::1", true, "IPv6 Link-Local Unicast"},
		{"ff02::1", true, "IPv6 Link-Local Multicast"},
		{"::", true, "IPv6 Unspecified"},
		{"fd7a:115c:a1e0::1", true, "Tailscale IPv6 ULA prefix"},
		{"fd7a:115c:a1e0:dead:beef::1", true, "Tailscale IPv6 ULA device"},

		// Public routable IPs
		{"8.8.8.8", false, "Google DNS"},
		{"1.1.1.1", false, "Cloudflare DNS"},
		{"93.184.216.34", false, "Example.com"},
		{"2606:4700:4700::1111", false, "Cloudflare IPv6 DNS"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			parsed := net.ParseIP(tc.ip)
			if parsed == nil {
				t.Fatalf("failed to parse IP %q", tc.ip)
			}
			got := IsPrivateOrLocal(parsed)
			if got != tc.expected {
				t.Errorf("IsPrivateOrLocal(%q) = %v; want %v (%s)", tc.ip, got, tc.expected, tc.desc)
			}
		})
	}
}

func TestLookupIP_AddressWithPortAndMalformed(t *testing.T) {
	// IPv4 with port
	res1 := LookupIP("127.0.0.1:8080")
	if res1.CountryCode != "LAN" || !res1.IsPrivate {
		t.Errorf("expected LAN/private for 127.0.0.1:8080, got %+v", res1)
	}

	// IPv6 bracketed with port
	res2 := LookupIP("[::1]:9090")
	if res2.CountryCode != "LAN" || !res2.IsPrivate {
		t.Errorf("expected LAN/private for [::1]:9090, got %+v", res2)
	}

	// Trim whitespace
	res3 := LookupIP("   192.168.1.50   ")
	if res3.CountryCode != "LAN" || !res3.IsPrivate {
		t.Errorf("expected LAN for trimmed IP, got %+v", res3)
	}

	// Empty string
	resEmpty := LookupIP("")
	if resEmpty.CountryCode != "XX" {
		t.Errorf("expected XX for empty IP, got %s", resEmpty.CountryCode)
	}

	// Malformed string
	resBad := LookupIP("not-an-ip-address")
	if resBad.CountryCode != "XX" {
		t.Errorf("expected XX for invalid IP, got %s", resBad.CountryCode)
	}
}

func TestLookupIP_IPv6ZoneStripping(t *testing.T) {
	// IPv6 link-local with zone index
	res1 := LookupIP("fe80::1%eth0")
	if res1.CountryCode != "LAN" || !res1.IsPrivate {
		t.Errorf("expected LAN/private for fe80::1%%eth0, got %+v", res1)
	}

	// IPv6 bracketed link-local with zone index and port
	res2 := LookupIP("[fe80::1%eth0]:54321")
	if res2.CountryCode != "LAN" || !res2.IsPrivate {
		t.Errorf("expected LAN/private for [fe80::1%%eth0]:54321, got %+v", res2)
	}
}



