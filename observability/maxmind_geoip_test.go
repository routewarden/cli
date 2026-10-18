package observability_test

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/routewarden/cli/observability"
)

func TestCountryCodeToName(t *testing.T) {
	cases := map[string]string{
		"US": "United States",
		"DE": "Germany",
		"FR": "France",
		"GB": "United Kingdom",
		"IN": "India",
		"JP": "Japan",
		"CN": "China",
		"CA": "Canada",
		"BR": "Brazil",
		"AU": "Australia",
		"SG": "Singapore",
		"NL": "Netherlands",
		"UNKNOWN": "UNKNOWN",
	}

	for code, want := range cases {
		got := observability.CountryCodeToName(code)
		if got != want {
			t.Errorf("CountryCodeToName(%q) = %q, want %q", code, got, want)
		}
	}
}

func TestInitMaxMind_NonExistent(t *testing.T) {
	observability.ResetMaxMind()
	err := observability.InitMaxMind("/path/to/nonexistent/GeoLite2-Country.mmdb")
	if err == nil {
		t.Errorf("expected error for nonexistent mmdb file")
	}
	if observability.IsMaxMindLoaded() {
		t.Errorf("expected IsMaxMindLoaded=false")
	}
}

// buildSyntheticMMDB generates a valid binary MMDB byte slice mapping all IPs to a target country code
func buildSyntheticMMDB(isoCode string) []byte {
	// Node count: 1. Record size: 28 bits (7 bytes per node).
	// Node 0: left (0) and right (1) both point to data section at offset 0
	nodeCount := uint32(1)
	recordSize := uint16(28)

	// Binary node: 7 bytes.
	// Leaf index = nodeCount + 16 (resolves to offset 0) = 17 (0x00000011)
	// Left pointer: 17 -> 28 bits: 0x0000011
	// Right pointer: 17 -> 28 bits: 0x0000011
	// In 28-bit encoding:
	// middle byte = (left_high_4 << 4) | (right_high_4) = (0 << 4) | 0 = 0x00
	// left bytes [0:3] = 0x00, 0x00, 0x11
	// middle byte [3] = 0x00
	// right bytes [4:7] = 0x00, 0x00, 0x11
	treeBytes := []byte{
		0x00, 0x00, 0x11, // left low 24 bits
		0x00,             // middle: left high 4 | right high 4
		0x00, 0x00, 0x11, // right low 24 bits
	}

	// Data section: 16-byte padding + map with "iso_code" and 2-letter ISO code
	dataPadding := make([]byte, 16)
	dataPayload := []byte("\x00\x00iso_code" + isoCode + "\x00\x00")
	dataSection := append(dataPadding, dataPayload...)

	// Metadata section
	marker := []byte("\xab\xcd\xefMaxMind.com")
	meta := []byte("type:GeoLite2-Country;")
	meta = append(meta, []byte("node_count")...)
	ncBytes := make([]byte, 5)
	binary.BigEndian.PutUint32(ncBytes[1:], nodeCount)
	meta = append(meta, ncBytes...)

	meta = append(meta, []byte("record_size")...)
	rsBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(rsBytes[2:], recordSize)
	meta = append(meta, rsBytes...)

	meta = append(meta, []byte("ip_version")...)
	ipVerBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(ipVerBytes[2:], 6)
	meta = append(meta, ipVerBytes...)

	buf := append(treeBytes, dataSection...)
	buf = append(buf, marker...)
	buf = append(buf, meta...)
	return buf
}

func TestLoadMaxMindData_AndLookup(t *testing.T) {
	observability.ResetMaxMind()
	defer observability.ResetMaxMind()

	mmdbData := buildSyntheticMMDB("DE")
	err := observability.LoadMaxMindData(mmdbData, "synthetic-de.mmdb")
	if err != nil {
		t.Fatalf("LoadMaxMindData failed: %v", err)
	}

	if !observability.IsMaxMindLoaded() {
		t.Fatalf("expected IsMaxMindLoaded=true")
	}
	if observability.MaxMindDBPath() != "synthetic-de.mmdb" {
		t.Errorf("unexpected MaxMindDBPath: %s", observability.MaxMindDBPath())
	}

	// Lookup public IP (8.8.8.8)
	cName, cCode, ok := observability.LookupMaxMind(net.ParseIP("8.8.8.8"))
	if !ok {
		t.Fatalf("expected LookupMaxMind to succeed")
	}
	if cCode != "DE" {
		t.Errorf("expected country code DE, got %s", cCode)
	}
	if cName != "Germany" {
		t.Errorf("expected country name Germany, got %s", cName)
	}

	// Test AutoDetectCountry integration
	detName, detCode := observability.AutoDetectCountry("8.8.8.8")
	if detCode != "DE" || detName != "Germany" {
		t.Errorf("expected AutoDetectCountry to use MaxMind (DE, Germany), got (%s, %s)", detName, detCode)
	}

	// Test LookupIP integration
	ipInfo := observability.LookupIP("8.8.8.8")
	if ipInfo.CountryCode != "DE" || ipInfo.Country != "Germany" {
		t.Errorf("expected LookupIP to return MaxMind DE, got %+v", ipInfo)
	}
	if ipInfo.ISP != "MaxMind GeoIP" {
		t.Errorf("expected ISP 'MaxMind GeoIP', got %s", ipInfo.ISP)
	}
}

func TestInitMaxMind_FileLoading(t *testing.T) {
	observability.ResetMaxMind()
	defer observability.ResetMaxMind()

	tmpDir := t.TempDir()
	dbFile := filepath.Join(tmpDir, "GeoLite2-Country.mmdb")
	synthetic := buildSyntheticMMDB("FR")
	if err := os.WriteFile(dbFile, synthetic, 0644); err != nil {
		t.Fatalf("failed to write test mmdb: %v", err)
	}

	err := observability.InitMaxMind(dbFile)
	if err != nil {
		t.Fatalf("InitMaxMind failed: %v", err)
	}

	if !observability.IsMaxMindLoaded() {
		t.Fatalf("expected IsMaxMindLoaded=true")
	}

	cName, cCode, ok := observability.LookupMaxMind(net.ParseIP("1.1.1.1"))
	if !ok || cCode != "FR" || cName != "France" {
		t.Errorf("expected France / FR from file, got (%s, %s, %v)", cName, cCode, ok)
	}
}
