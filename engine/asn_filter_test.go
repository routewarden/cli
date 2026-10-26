package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func asnTestDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "asn.json")
	if err := os.WriteFile(path, []byte(`{"AS64500":["8.0.0.0/8","2001:db8::/32"],"64501":["8.8.8.0/24","2001:db8:1::/48"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestASNLongestPrefix(t *testing.T) {
	f, err := NewASNFilter([]string{"as64500"}, asnTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"8.1.2.3", true}, {"8.1.2.3:443", true}, {"::ffff:8.1.2.3", true},
		{"8.8.8.8", false}, {"2001:db8:2::1", true}, {"2001:db8:1::1", false},
		{"9.1.2.3", false}, {"127.0.0.1", false}, {"bad", false}, {"", false},
	} {
		if got := f.IsAllowed(tc.ip); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.ip, got, tc.want)
		}
	}
}
func TestASNValidation(t *testing.T) {
	path := asnTestDB(t)
	for _, allowed := range [][]string{{"0"}, {"4294967296"}, {"AS"}, {"-1"}, {"+64500"}, {"1.2"}, {"64502"}} {
		if _, err := NewASNFilter(allowed, path); err == nil {
			t.Errorf("accepted %v", allowed)
		}
	}
	if _, err := NewASNFilter([]string{"64500"}, ""); err == nil {
		t.Error("accepted missing DB path")
	}
	if _, err := NewASNFilter([]string{"64500"}, path+"missing"); err == nil {
		t.Error("accepted unreadable DB")
	}
	for _, content := range []string{`bad`, `null`, `{}`, `{"64500":["invalid"]}`, `{"64500":["8.0.0.0/8"],"64501":["8.1.0.0/8"]}`} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewASNFilter([]string{"64500"}, path); err == nil {
			t.Errorf("accepted bad database %s", content)
		}
	}
	f, err := NewASNFilter(nil, "nonexistent")
	if err != nil || f.IsAllowed("8.1.2.3") {
		t.Error("disabled feature changed behavior")
	}
}

func TestASNEngineConfigAndGenerators(t *testing.T) {
	path := asnTestDB(t)
	for _, snake := range []bool{false, true} {
		cfg := CreateConfig()
		asnsKey, dbKey := "allowedASNs", "asnDB"
		if snake {
			asnsKey, dbKey = "allowed_asns", "asn_db"
		}
		data, err := json.Marshal(map[string]interface{}{asnsKey: []string{"AS64500"}, dbKey: path})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			t.Fatal(err)
		}
		e, err := NewEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got := e.EvaluateWithClientIP("GET", "/.env", "", nil, "8.1.2.3")
		if !got.Allowed || got.Reason != "asn_whitelisted" {
			t.Fatalf("ASN bypass failed: %+v", got)
		}
		if got := e.EvaluateWithClientIP("GET", "/.env", "", map[string]string{"X-Forwarded-For": "8.1.2.3"}, "9.1.2.3"); !got.Blocked {
			t.Fatalf("forged header bypassed: %+v", got)
		}
		for _, output := range []string{cfg.GenerateTraefikYAML(), cfg.GenerateTraefikTOML(), cfg.GenerateTraefikLabels(), cfg.GenerateCaddyfile(), cfg.GenerateNginxLua(), cfg.GenerateTCPWardenYAML()} {
			if !strings.Contains(output, "AS64500") || !strings.Contains(output, path) {
				t.Errorf("ASN config lost: %s", output)
			}
		}
		base := CreateConfig()
		diff := DiffConfigs(base, cfg, "base", "candidate")
		if !diff.HasDifferences || diff.Impact != DiffImpactRelaxed || len(diff.AllowedASNs.Added) != 1 {
			t.Errorf("ASN bypass omitted from policy diff: %+v", diff)
		}
	}
}

func TestASNGeneratorPreservesOverrides(t *testing.T) {
	cfg := CreateConfig()
	cfg.ConfigFile = "/base.json"
	cfg.AllowedASNs = []string{}
	for _, output := range []string{cfg.GenerateTraefikYAML(), cfg.GenerateTraefikTOML(), cfg.GenerateTraefikLabels(), cfg.GenerateCaddyfile(), cfg.GenerateNginxLua()} {
		if !strings.Contains(output, "allowedASNs") && !strings.Contains(output, "allowed_asns") {
			t.Errorf("lost empty ASN override: %s", output)
		}
	}
	cfg.AllowedASNs = nil
	cfg.ASNDB = "/alternate.json"
	for _, output := range []string{cfg.GenerateTraefikYAML(), cfg.GenerateTraefikTOML(), cfg.GenerateTraefikLabels(), cfg.GenerateCaddyfile(), cfg.GenerateNginxLua(), cfg.GenerateTCPWardenYAML()} {
		if !strings.Contains(output, cfg.ASNDB) {
			t.Errorf("lost database-only override: %s", output)
		}
		if strings.Contains(output, "allowedASNs") || strings.Contains(output, "allowed_asns") {
			t.Errorf("database-only override added allowlist: %s", output)
		}
	}
}
