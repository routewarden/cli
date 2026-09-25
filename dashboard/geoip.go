package dashboard

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// GeoResult holds the resolved country information, network, and location details for an IP.
type GeoResult struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	FlagEmoji   string  `json:"flag_emoji"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Zip         string  `json:"zip,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
	AS          string  `json:"as,omitempty"`
	IsPrivate   bool    `json:"is_private"`
}

var (
	geoCache sync.Map // map[string]GeoResult
	geoOnce  sync.Once
	mmdb     *mmdbReader
)

// InitGeoIP attempts to locate and load a local MaxMind GeoLite2-Country.mmdb database.
// Searches current directory, common system locations, or explicit GEOIP_DB env var.
func InitGeoIP(dbPath ...string) {
	geoOnce.Do(func() {
		candidates := []string{
			os.Getenv("GEOIP_DB"),
			"GeoLite2-Country.mmdb",
			"geolite2-country.mmdb",
			"/usr/share/GeoIP/GeoLite2-Country.mmdb",
			"/var/lib/GeoIP/GeoLite2-Country.mmdb",
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

// CountryCodeToFlag converts an ISO 3166-1 alpha-2 country code (e.g. "US", "DE")
// into its corresponding Unicode regional indicator flag emoji (e.g. "🇺🇸", "🇩🇪").
// Special/Private codes like "LAN" or "LOC" return "🏠", while "VPN" returns "🔒".
func CountryCodeToFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "LAN" || code == "LOC" || code == "LOCAL" || code == "PRIVATE" {
		return "🏠"
	}
	if code == "VPN" || code == "MESH" {
		return "🔒"
	}
	if len(code) != 2 {
		return "🌐"
	}
	r1 := rune(code[0]) - 'A' + 0x1F1E6
	r2 := rune(code[1]) - 'A' + 0x1F1E6
	if r1 < 0x1F1E6 || r1 > 0x1F1FF || r2 < 0x1F1E6 || r2 > 0x1F1FF {
		return "🌐"
	}
	return string([]rune{r1, r2})
}

// isPrivateOrLocal checks whether an IP belongs to private, loopback, or non-routable ranges.
func isPrivateOrLocal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// CGNAT 100.64.0.0/10 (Used by Tailscale and NetBird for mesh VPNs)
		if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
			return true
		}
		// Benchmark/Documentation 198.18.0.0/15
		if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
			return true
		}
		// RFC 5737 Documentation / Test Networks: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
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

// cleanIPString strips any trailing port or whitespace.
func cleanIPString(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		return host
	}
	return ipStr
}

// LookupIP resolves an IP address to its GeoResult.
// 1. Checks memory cache (0ms).
// 2. Checks if private/loopback/LAN/test/VPN -> returns "LAN"/"VPN" / "🏠"/"🔒".
// 3. Checks MaxMind GeoLite2 MMDB if loaded.
// 4. Falls back to free ip-api.com live endpoint with 2s timeout.
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
		geoCache.Store(clean, res)
		return res
	}

	// 1. Private/LAN/Documentation/VPN range
	if isPrivateOrLocal(parsedIP) {
		countryCode := "LAN"
		countryName := "Local Network"
		flagEmoji := "🏠"
		region := "Private Subnet"
		city := "Internal Host"
		isp := "Local Area Network (RFC 1918 / Loopback)"

		if ip4 := parsedIP.To4(); ip4 != nil {
			if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
				// Tailscale & NetBird Carrier Grade NAT 100.64.0.0/10
				countryCode = "VPN"
				flagEmoji = "🔒"
				if ip4[1] == 64 {
					// NetBird default IPv4 subnet is 100.64.0.0/16
					countryName = "NetBird / Tailscale Mesh"
					region = "NetBird Overlay Network (100.64.0.0/16)"
					city = "NetBird Peer"
					isp = "NetBird WireGuard Mesh Overlay"
				} else {
					countryName = "Tailscale / NetBird Mesh"
					region = "Tailscale Overlay Network (100.64.0.0/10)"
					city = "Tailscale Peer"
					isp = "Tailscale Encrypted WireGuard Overlay"
				}
			} else if (ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) ||
				(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) ||
				(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) {
				region = "RFC 5737 Test Network (TEST-NET-3)"
				city = "Documentation Subnet"
				isp = "IANA Special-Purpose / Reserved"
				countryName = "Reserved Test Network"
			}
		} else {
			lower := strings.ToLower(parsedIP.String())
			if strings.HasPrefix(lower, "fd7a:115c:a1e0:") {
				countryCode = "VPN"
				countryName = "Tailscale Mesh IPv6"
				flagEmoji = "🔒"
				region = "Tailscale IPv6 Overlay (fd7a:115c:a1e0::/48)"
				city = "Tailscale Peer"
				isp = "Tailscale Encrypted WireGuard Mesh"
			} else if strings.HasPrefix(lower, "fd") || strings.HasPrefix(lower, "fc") {
				countryCode = "VPN"
				countryName = "NetBird Mesh IPv6"
				flagEmoji = "🔒"
				region = "NetBird IPv6 Overlay (fd00::/8 ULA)"
				city = "NetBird Peer"
				isp = "NetBird WireGuard Overlay"
			}
		}

		res := GeoResult{
			IP:          clean,
			CountryCode: countryCode,
			CountryName: countryName,
			FlagEmoji:   flagEmoji,
			Region:      region,
			City:        city,
			ISP:         isp,
			Org:         "Private Overlay / Local Subnet",
			IsPrivate:   true,
		}
		geoCache.Store(clean, res)
		return res
	}

	// 2. Embedded / Local MaxMind MMDB lookup
	InitGeoIP()
	if mmdb != nil {
		if code, name, ok := mmdb.lookup(parsedIP); ok && code != "" {
			res := GeoResult{
				IP:          clean,
				CountryCode: code,
				CountryName: name,
				FlagEmoji:   CountryCodeToFlag(code),
				IsPrivate:   false,
			}
			geoCache.Store(clean, res)
			return res
		}
	}

	// 3. Quick well-known public resolver IPs
	if ip4 := parsedIP.To4(); ip4 != nil {
		switch {
		case ip4[0] == 8 && ip4[1] == 8: // Google DNS (8.8.8.8, 8.8.4.4)
			res := GeoResult{
				IP:          clean,
				CountryCode: "US",
				CountryName: "United States",
				FlagEmoji:   "🇺🇸",
				City:        "Mountain View",
				Region:      "California",
				ISP:         "Google LLC",
				Org:         "Google Public DNS",
				AS:          "AS15169 Google LLC",
				IsPrivate:   false,
			}
			geoCache.Store(clean, res)
			return res
		case ip4[0] == 1 && ip4[1] == 1 && ip4[2] == 1: // Cloudflare (1.1.1.1)
			res := GeoResult{
				IP:          clean,
				CountryCode: "AU",
				CountryName: "Australia",
				FlagEmoji:   "🇦🇺",
				City:        "South Brisbane",
				Region:      "Queensland",
				ISP:         "Cloudflare, Inc.",
				Org:         "APNIC and Cloudflare DNS Resolver Project",
				AS:          "AS13335 CLOUDFLARENET",
				IsPrivate:   false,
			}
			geoCache.Store(clean, res)
			return res
		case ip4[0] == 9 && ip4[1] == 9 && ip4[2] == 9: // Quad9 (9.9.9.9)
			res := GeoResult{
				IP:          clean,
				CountryCode: "US",
				CountryName: "United States",
				FlagEmoji:   "🇺🇸",
				City:        "Berkeley",
				Region:      "California",
				ISP:         "Quad9",
				Org:         "Quad9 Recursive Resolver",
				AS:          "AS19281 QUAD9-AS-1",
				IsPrivate:   false,
			}
			geoCache.Store(clean, res)
			return res
		}
	}

	// 4. Free ip-api.com live fallback
	res := queryIPAPI(clean)
	geoCache.Store(clean, res)
	return res
}

// EnrichGeoIP populates CountryCode, CountryName, and FlagEmoji on a SecurityEvent.
func EnrichGeoIP(e SecurityEvent) SecurityEvent {
	if e.ClientIP == "" {
		return e
	}
	if e.CountryCode != "" && e.FlagEmoji != "" {
		return e
	}
	geo := LookupIP(e.ClientIP)
	e.CountryCode = geo.CountryCode
	e.CountryName = geo.CountryName
	e.FlagEmoji = geo.FlagEmoji
	return e
}

// queryIPAPI calls the free ip-api.com endpoint with extended network & location fields.
func queryIPAPI(ipStr string) GeoResult {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	endpoint := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as", url.PathEscape(ipStr))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return GeoResult{IP: ipStr, CountryCode: "XX", CountryName: "Public IP", FlagEmoji: "🌐"}
	}
	req.Header.Set("User-Agent", "RouteWarden-Dashboard/1.2")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return GeoResult{IP: ipStr, CountryCode: "XX", CountryName: "Public IP", FlagEmoji: "🌐"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return GeoResult{IP: ipStr, CountryCode: "XX", CountryName: "Public IP", FlagEmoji: "🌐"}
	}

	var data struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Zip         string  `json:"zip"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Timezone    string  `json:"timezone"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&data); err != nil {
		return GeoResult{IP: ipStr, CountryCode: "XX", CountryName: "Public IP", FlagEmoji: "🌐"}
	}

	if data.Status == "success" && data.CountryCode != "" {
		return GeoResult{
			IP:          ipStr,
			CountryCode: strings.ToUpper(data.CountryCode),
			CountryName: data.Country,
			FlagEmoji:   CountryCodeToFlag(data.CountryCode),
			Region:      data.RegionName,
			City:        data.City,
			Zip:         data.Zip,
			Lat:         data.Lat,
			Lon:         data.Lon,
			Timezone:    data.Timezone,
			ISP:         data.ISP,
			Org:         data.Org,
			AS:          data.AS,
			IsPrivate:   false,
		}
	}

	return GeoResult{IP: ipStr, CountryCode: "XX", CountryName: "Public IP", FlagEmoji: "🌐"}
}

// ── Lightweight pure Go MaxMind DB (MMDB) Country Reader ──────────────────────────

type mmdbReader struct {
	data        []byte
	nodeCount   uint
	recordSize  uint
	ipVersion   uint
	treeSize    uint
	dataSection []byte
}

func newMMDBReader(data []byte) (*mmdbReader, error) {
	marker := []byte("\xab\xcd\xefMaxMind.com")
	idx := bytes.LastIndex(data, marker)
	if idx < 0 {
		return nil, fmt.Errorf("mmdb marker not found")
	}

	metaBytes := data[idx+len(marker):]
	r := &mmdbReader{data: data}

	meta, _, err := r.decodeData(metaBytes, 0)
	if err != nil {
		return nil, fmt.Errorf("mmdb metadata decode: %w", err)
	}

	metaMap, ok := meta.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("mmdb metadata not a map")
	}

	if nc, ok := toUint(metaMap["node_count"]); ok {
		r.nodeCount = nc
	}
	if rs, ok := toUint(metaMap["record_size"]); ok {
		r.recordSize = rs
	}
	if iv, ok := toUint(metaMap["ip_version"]); ok {
		r.ipVersion = iv
	}

	if r.nodeCount == 0 || r.recordSize == 0 {
		return nil, fmt.Errorf("invalid mmdb metadata parameters")
	}

	r.treeSize = (r.nodeCount * (r.recordSize * 2)) / 8
	if int(r.treeSize+16) > len(data) {
		return nil, fmt.Errorf("mmdb data section out of bounds")
	}
	r.dataSection = data[r.treeSize+16:]

	return r, nil
}

func (r *mmdbReader) readRecord(nodeIndex uint, index uint) uint {
	recSize := r.recordSize
	switch recSize {
	case 24:
		offset := nodeIndex * 6
		if index == 0 {
			return uint(r.data[offset])<<16 | uint(r.data[offset+1])<<8 | uint(r.data[offset+2])
		}
		return uint(r.data[offset+3])<<16 | uint(r.data[offset+4])<<8 | uint(r.data[offset+5])
	case 28:
		offset := nodeIndex * 7
		if index == 0 {
			return (uint(r.data[offset+3]&0xF0) << 20) | (uint(r.data[offset]) << 16) | (uint(r.data[offset+1]) << 8) | uint(r.data[offset+2])
		}
		return (uint(r.data[offset+3]&0x0F) << 24) | (uint(r.data[offset+4]) << 16) | (uint(r.data[offset+5]) << 8) | uint(r.data[offset+6])
	case 32:
		offset := nodeIndex * 8
		if index == 0 {
			return uint(binary.BigEndian.Uint32(r.data[offset : offset+4]))
		}
		return uint(binary.BigEndian.Uint32(r.data[offset+4 : offset+8]))
	default:
		return 0
	}
}

func (r *mmdbReader) lookup(ip net.IP) (isoCode string, countryName string, found bool) {
	var ipBytes []byte
	if ip4 := ip.To4(); ip4 != nil {
		if r.ipVersion == 6 {
			// IPv4-mapped IPv6
			ipBytes = append(make([]byte, 12), ip4...)
		} else {
			ipBytes = ip4
		}
	} else {
		ipBytes = ip.To16()
	}

	node := uint(0)
	for _, b := range ipBytes {
		for i := 7; i >= 0; i-- {
			bit := uint((b >> i) & 1)
			node = r.readRecord(node, bit)
			if node >= r.nodeCount {
				break
			}
		}
		if node >= r.nodeCount {
			break
		}
	}

	if node == r.nodeCount || node == 0 {
		return "", "", false
	}

	dataOffset := node - r.nodeCount - 16
	if int(dataOffset) >= len(r.dataSection) {
		return "", "", false
	}

	val, _, err := r.decodeData(r.dataSection, dataOffset)
	if err != nil {
		return "", "", false
	}

	dataMap, ok := val.(map[string]any)
	if !ok {
		return "", "", false
	}

	// Try country.iso_code, or registered_country.iso_code
	if country, ok := dataMap["country"].(map[string]any); ok {
		if code, ok := country["iso_code"].(string); ok {
			isoCode = code
		}
		if names, ok := country["names"].(map[string]any); ok {
			if name, ok := names["en"].(string); ok {
				countryName = name
			}
		}
	}
	if isoCode == "" {
		if country, ok := dataMap["registered_country"].(map[string]any); ok {
			if code, ok := country["iso_code"].(string); ok {
				isoCode = code
			}
			if names, ok := country["names"].(map[string]any); ok {
				if name, ok := names["en"].(string); ok {
					countryName = name
				}
			}
		}
	}

	if isoCode != "" {
		return isoCode, countryName, true
	}
	return "", "", false
}

func (r *mmdbReader) decodeData(buf []byte, offset uint) (any, uint, error) {
	if int(offset) >= len(buf) {
		return nil, offset, io.EOF
	}

	ctrl := buf[offset]
	offset++
	typeNum := ctrl >> 5

	var size uint
	var err error
	size, offset, err = r.decodeSize(ctrl, buf, offset)
	if err != nil {
		return nil, offset, err
	}

	// Pointer
	if typeNum == 1 {
		ptrSize := ((ctrl >> 3) & 0x03)
		var ptr uint
		switch ptrSize {
		case 0:
			if int(offset) >= len(buf) {
				return nil, offset, io.EOF
			}
			ptr = (uint(ctrl&0x07) << 8) | uint(buf[offset])
			offset++
		case 1:
			if int(offset+1) >= len(buf) {
				return nil, offset, io.EOF
			}
			ptr = 2048 + ((uint(ctrl&0x07) << 16) | (uint(buf[offset]) << 8) | uint(buf[offset+1]))
			offset += 2
		case 2:
			if int(offset+2) >= len(buf) {
				return nil, offset, io.EOF
			}
			ptr = 526336 + ((uint(ctrl&0x07) << 24) | (uint(buf[offset]) << 16) | (uint(buf[offset+1]) << 8) | uint(buf[offset+2]))
			offset += 3
		case 3:
			if int(offset+3) >= len(buf) {
				return nil, offset, io.EOF
			}
			ptr = uint(binary.BigEndian.Uint32(buf[offset : offset+4]))
			offset += 4
		}
		val, _, _ := r.decodeData(r.dataSection, ptr)
		return val, offset, nil
	}

	// Extended type
	if typeNum == 0 {
		if int(offset) >= len(buf) {
			return nil, offset, io.EOF
		}
		typeNum = buf[offset] + 7
		offset++
	}

	switch typeNum {
	case 2: // UTF-8 string
		end := offset + size
		if int(end) > len(buf) {
			return "", offset, nil
		}
		return string(buf[offset:end]), end, nil
	case 5, 6, 9: // uint16, uint32, uint64
		var val uint64
		for i := uint(0); i < size && int(offset+i) < len(buf); i++ {
			val = (val << 8) | uint64(buf[offset+i])
		}
		return val, offset + size, nil
	case 7: // Map
		m := make(map[string]any, size)
		for i := uint(0); i < size; i++ {
			kVal, nextOff, err := r.decodeData(buf, offset)
			if err != nil {
				return m, offset, err
			}
			offset = nextOff
			vVal, nextOff2, err := r.decodeData(buf, offset)
			if err != nil {
				return m, offset, err
			}
			offset = nextOff2
			if ks, ok := kVal.(string); ok {
				m[ks] = vVal
			}
		}
		return m, offset, nil
	case 11: // Array
		arr := make([]any, size)
		for i := uint(0); i < size; i++ {
			vVal, nextOff, err := r.decodeData(buf, offset)
			if err != nil {
				return arr, offset, err
			}
			offset = nextOff
			arr[i] = vVal
		}
		return arr, offset, nil
	case 14: // Boolean
		return size != 0, offset, nil
	default:
		return nil, offset + size, nil
	}
}

func (r *mmdbReader) decodeSize(ctrl byte, buf []byte, offset uint) (uint, uint, error) {
	size := uint(ctrl & 0x1F)
	if (ctrl >> 5) == 1 {
		return 0, offset, nil
	}
	if size < 29 {
		return size, offset, nil
	}
	switch size {
	case 29:
		if int(offset) >= len(buf) {
			return 0, offset, io.EOF
		}
		return 29 + uint(buf[offset]), offset + 1, nil
	case 30:
		if int(offset+1) >= len(buf) {
			return 0, offset, io.EOF
		}
		return 285 + (uint(buf[offset])<<8 | uint(buf[offset+1])), offset + 2, nil
	case 31:
		if int(offset+2) >= len(buf) {
			return 0, offset, io.EOF
		}
		return 65821 + (uint(buf[offset])<<16 | uint(buf[offset+1])<<8 | uint(buf[offset+2])), offset + 3, nil
	}
	return size, offset, nil
}

func toUint(v any) (uint, bool) {
	switch n := v.(type) {
	case uint:
		return n, true
	case uint64:
		return uint(n), true
	case int:
		return uint(n), true
	case float64:
		return uint(n), true
	}
	return 0, false
}
