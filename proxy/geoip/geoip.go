package geoip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// GeoResult holds resolved country info and location details for an IP.
type GeoResult struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	FlagEmoji   string `json:"flag_emoji"`
	IsPrivate   bool   `json:"is_private"`
}

const maxGeoCacheEntries = 50000

var (
	geoCache      sync.Map // map[string]GeoResult
	geoCacheCount atomic.Int64
	geoOnce       sync.Once
	mmdb          *mmdbReader
)

func cacheStore(clean string, res GeoResult) {
	if _, loaded := geoCache.LoadOrStore(clean, res); !loaded {
		if geoCacheCount.Add(1) > maxGeoCacheEntries {
			// Clear cache to prevent unbounded memory growth under spoofed/random IP scans
			geoCache.Range(func(k, _ any) bool {
				geoCache.Delete(k)
				return true
			})
			geoCacheCount.Store(0)
			geoCache.Store(clean, res)
			geoCacheCount.Store(1)
		}
	}
}

// ResetCache clears the internal GeoIP in-memory cache and resets the counter.
func ResetCache() {
	geoCache.Range(func(k, _ any) bool {
		geoCache.Delete(k)
		return true
	})
	geoCacheCount.Store(0)
}

// InitGeoIP attempts to locate and load a local MaxMind GeoLite2-Country.mmdb database.
func InitGeoIP(dbPath ...string) {
	geoOnce.Do(func() {
		candidates := []string{
			os.Getenv("GEOIP_DB"),
			"GeoLite2-Country.mmdb",
			"geolite2-country.mmdb",
			"/usr/share/GeoIP/GeoLite2-Country.mmdb",
			"/var/lib/GeoIP/GeoLite2-Country.mmdb",
			"/etc/routewarden/GeoLite2-Country.mmdb",
		}
		if len(dbPath) > 0 && dbPath[0] != "" {
			candidates = append([]string{dbPath[0]}, candidates...)
		}

		for _, p := range candidates {
			if p == "" {
				continue
			}
			data, err := os.ReadFile(p)
			if err == nil && len(data) > 0 {
				reader, err := newMMDBReader(data)
				if err == nil {
					mmdb = reader
					break
				}
			}
		}
	})
}

// CountryCodeToFlag converts an ISO 3166-1 alpha-2 country code to a Unicode flag emoji.
func CountryCodeToFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "LAN" || code == "LOC" || code == "LOCAL" || code == "PRIVATE" {
		return "🏠"
	}
	if code == "VPN" || code == "MESH" {
		return "🔒"
	}
	if len(code) != 2 || code == "XX" {
		return "🌐"
	}
	r1 := rune(code[0]) - 'A' + 0x1F1E6
	r2 := rune(code[1]) - 'A' + 0x1F1E6
	if r1 < 0x1F1E6 || r1 > 0x1F1FF || r2 < 0x1F1E6 || r2 > 0x1F1FF {
		return "🌐"
	}
	return string([]rune{r1, r2})
}

// IsPrivateOrLocal checks whether an IP belongs to private, loopback, or non-routable ranges.
func IsPrivateOrLocal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// CGNAT 100.64.0.0/10 (Used by Tailscale and NetBird)
		if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
			return true
		}
		// Benchmark 198.18.0.0/15
		if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
			return true
		}
		// RFC 5737 Documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return true
		}
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return true
		}
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return true
		}
	} else {
		// Tailscale IPv6 ULA prefix fd7a:115c:a1e0::/48
		lower := strings.ToLower(ip.String())
		if strings.HasPrefix(lower, "fd7a:115c:a1e0:") {
			return true
		}
	}
	return false
}

func cleanIPString(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	if idx := strings.IndexByte(ipStr, '%'); idx != -1 {
		ipStr = ipStr[:idx]
	}
	return ipStr
}

// LookupIP resolves an IP address to its GeoResult.
func LookupIP(ipStr string) GeoResult {
	clean := cleanIPString(ipStr)
	if clean == "" {
		return GeoResult{IP: ipStr, CountryCode: "XX", CountryName: "Unknown", FlagEmoji: "🌐"}
	}

	if val, ok := geoCache.Load(clean); ok {
		return val.(GeoResult)
	}

	parsedIP := net.ParseIP(clean)
	if parsedIP == nil {
		res := GeoResult{IP: clean, CountryCode: "XX", CountryName: "Unknown", FlagEmoji: "🌐"}
		cacheStore(clean, res)
		return res
	}

	// 1. Private / LAN check
	if IsPrivateOrLocal(parsedIP) {
		res := GeoResult{
			IP:          clean,
			CountryCode: "LAN",
			CountryName: "Local Network",
			FlagEmoji:   "🏠",
			IsPrivate:   true,
		}
		cacheStore(clean, res)
		return res
	}

	// 2. MaxMind GeoLite2 lookup if database loaded
	if mmdb != nil {
		if code, name, ok := mmdb.Lookup(parsedIP); ok {
			res := GeoResult{
				IP:          clean,
				CountryCode: code,
				CountryName: name,
				FlagEmoji:   CountryCodeToFlag(code),
			}
			cacheStore(clean, res)
			return res
		}
	}

	// Default fallback
	res := GeoResult{
		IP:          clean,
		CountryCode: "XX",
		CountryName: "Unknown",
		FlagEmoji:   "🌐",
	}
	cacheStore(clean, res)
	return res
}

// Minimal MMDB parser for MaxMind GeoLite2-Country
type mmdbReader struct {
	buffer        []byte
	nodeCount     uint32
	recordSize    uint16
	ipVersion     uint16
	nodeOffsetMult uint32
	dataSection   uint32
}

func newMMDBReader(data []byte) (*mmdbReader, error) {
	marker := []byte("\xab\xcd\xefMaxMind.com")
	idx := bytes.LastIndex(data, marker)
	if idx == -1 {
		return nil, fmt.Errorf("invalid mmdb: metadata marker not found")
	}

	metaBytes := data[idx+len(marker):]
	r := &mmdbReader{buffer: data}

	// Scan metadata section for node_count, record_size, ip_version
	r.recordSize = 28 // GeoLite2 default fallback
	r.ipVersion = 6
	r.nodeCount = 0

	for i := 0; i < len(metaBytes)-4; i++ {
		if bytes.HasPrefix(metaBytes[i:], []byte("node_count")) {
			if i+14 < len(metaBytes) {
				r.nodeCount = binary.BigEndian.Uint32(metaBytes[i+11 : i+15])
			}
		}
		if bytes.HasPrefix(metaBytes[i:], []byte("record_size")) {
			if i+13 < len(metaBytes) {
				r.recordSize = binary.BigEndian.Uint16(metaBytes[i+12 : i+14])
			}
		}
	}

	if r.nodeCount == 0 {
		return nil, fmt.Errorf("invalid mmdb: could not parse node count")
	}

	r.nodeOffsetMult = uint32(r.recordSize) / 4
	r.dataSection = (r.nodeCount * uint32(r.recordSize) * 2) / 8 + 16

	return r, nil
}

func (r *mmdbReader) Lookup(ip net.IP) (string, string, bool) {
	if r == nil || len(r.buffer) == 0 {
		return "", "", false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return "", "", false
	}

	node := uint32(0)
	for bitIdx := range 128 {
		byteVal := ip16[bitIdx/8]
		bit := (byteVal >> (7 - (bitIdx % 8))) & 1
		next, err := r.readNode(node, bit)
		if err != nil || next == r.nodeCount {
			return "", "", false
		}
		if next > r.nodeCount {
			return r.resolveData(next - r.nodeCount - 16)
		}
		node = next
	}
	return "", "", false
}

func (r *mmdbReader) readNode(node uint32, bit byte) (uint32, error) {
	offset := node * r.nodeOffsetMult
	if int(offset)+7 >= len(r.buffer) {
		return 0, fmt.Errorf("node offset out of bounds")
	}

	switch r.recordSize {
	case 24:
		if bit == 0 {
			return uint32(r.buffer[offset])<<16 | uint32(r.buffer[offset+1])<<8 | uint32(r.buffer[offset+2]), nil
		}
		return uint32(r.buffer[offset+3])<<16 | uint32(r.buffer[offset+4])<<8 | uint32(r.buffer[offset+5]), nil
	case 28:
		middle := r.buffer[offset+3]
		if bit == 0 {
			return uint32(middle>>4)<<24 | uint32(r.buffer[offset])<<16 | uint32(r.buffer[offset+1])<<8 | uint32(r.buffer[offset+2]), nil
		}
		return uint32(middle&0x0F)<<24 | uint32(r.buffer[offset+4])<<16 | uint32(r.buffer[offset+5])<<8 | uint32(r.buffer[offset+6]), nil
	case 32:
		if bit == 0 {
			return binary.BigEndian.Uint32(r.buffer[offset : offset+4]), nil
		}
		return binary.BigEndian.Uint32(r.buffer[offset+4 : offset+8]), nil
	default:
		return 0, fmt.Errorf("unsupported record size: %d", r.recordSize)
	}
}

func (r *mmdbReader) resolveData(offset uint32) (string, string, bool) {
	dataStart := r.dataSection + offset
	if int(dataStart) >= len(r.buffer) {
		return "", "", false
	}
	end := min(int(dataStart) + 256, len(r.buffer))
	chunk := r.buffer[dataStart:end]
	idx := bytes.Index(chunk, []byte("iso_code"))
	if idx != -1 && idx+11 < len(chunk) {
		code := string(chunk[idx+9 : idx+11])
		if len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' {
			return code, code, true
		}
	}
	return "", "", false
}
