package observability_test

import (
	"slices"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/routewarden/cli/observability"
)

func TestExportObservabilityAssets(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "routewarden-observability-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := observability.Export(tempDir); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	requiredFiles := []string{
		"docker-compose.yml",
		"config.alloy",
		"loki-config.yaml",
		"grafana/provisioning/datasources/datasources.yaml",
		"grafana/provisioning/dashboards/dashboards.yaml",
		"grafana/provisioning/alerting/alerting.yaml",
		"grafana/dashboards/routewarden-overview.json",
	}

	for _, rel := range requiredFiles {
		full := filepath.Join(tempDir, rel)
		info, err := os.Stat(full)
		if err != nil {
			t.Errorf("expected exported file %s does not exist: %v", rel, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("exported file %s is empty", rel)
		}
	}
}

func TestDashboardGeoIPIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "routewarden-dashboard-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := observability.Export(tempDir); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	dashboardPath := filepath.Join(tempDir, "grafana/dashboards/routewarden-overview.json")
	data, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("failed to read exported dashboard: %v", err)
	}

	var model struct {
		Title  string `json:"title"`
		Panels []struct {
			ID      int    `json:"id"`
			Type    string `json:"type"`
			Title   string `json:"title"`
			GridPos struct {
				H int `json:"h"`
				W int `json:"w"`
				X int `json:"x"`
				Y int `json:"y"`
			} `json:"gridPos"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
		Templating struct {
			List []struct {
				Name string `json:"name"`
			} `json:"list"`
		} `json:"templating"`
		Tags []string `json:"tags"`
	}

	if err := json.Unmarshal(data, &model); err != nil {
		t.Fatalf("failed to parse dashboard JSON: %v", err)
	}

	// Verify template variables exist
	expectedVars := []string{"gateway", "verdict", "country_code", "protocol", "transport"}
	varSet := make(map[string]bool)
	for _, v := range model.Templating.List {
		varSet[v.Name] = true
	}
	for _, v := range expectedVars {
		if !varSet[v] {
			t.Errorf("expected %q template variable in dashboard", v)
		}
	}

	// Verify tags exist
	expectedTags := []string{"routewarden", "waf", "security", "loki", "geoip", "layer4", "scanners", "alerting"}
	for _, tag := range expectedTags {
		if !slices.Contains(model.Tags, tag) {
			t.Errorf("expected %q tag in dashboard tags", tag)
		}
	}

	// Verify required panels exist
	panelTitles := make(map[string]string) // title -> type
	for _, p := range model.Panels {
		panelTitles[p.Title] = p.Type
		if p.GridPos.W > 24 {
			t.Errorf("panel %s exceeds max grid width 24: %d", p.Title, p.GridPos.W)
		}
	}

	expectedPanels := map[string]string{
		"🌍 Threat Geography & GeoIP Intelligence":                           "row",
		"Global Attack Origins Map":                                         "geomap",
		"Top Attacking Countries":                                           "bargauge",
		"Country Threat Share":                                              "piechart",
		"🔀 Layer 4 & Layer 7 Multi-Protocol Convergence":                    "row",
		"L4 vs L7 Threat Convergence Over Time":                             "timeseries",
		"Protocol Breakdown":                                                "piechart",
		"Transport Split (TCP vs UDP)":                                      "bargauge",
		"🎯 Threat Analysis & Attack Vector Profiling":                       "row",
		"Top Attacked Endpoints":                                            "bargauge",
		"Top Offender IP Addresses & GeoIP":                                 "bargauge",
		"Top Triggered Rules / Signatures":                                  "bargauge",
		"🤖 Malicious User-Agents & Attack Scanners":                         "bargauge",
		"Attacked HTTP Methods & Verbs":                                     "piechart",
		"📜 Live Security Event Feed & Incident Triage":                       "row",
		"🚨 Interactive Threat Incident Triage Table (Click IP to Investigate)": "table",
		"Real-Time Attack Log Stream":                                       "logs",
	}

	for expectedTitle, expectedType := range expectedPanels {
		actualType, ok := panelTitles[expectedTitle]
		if !ok {
			t.Errorf("missing expected panel %q", expectedTitle)
		} else if actualType != expectedType {
			t.Errorf("panel %q has type %q, expected %q", expectedTitle, actualType, expectedType)
		}
	}

	// Verify synchronization with github/dashboards/routewarden-overview.json
	githubDashboardPath := filepath.Join("..", "..", "github", "dashboards", "routewarden-overview.json")
	if githubData, err := os.ReadFile(githubDashboardPath); err == nil {
		if string(data) != string(githubData) {
			t.Errorf("observability dashboard does not match github/dashboards/routewarden-overview.json")
		}
	}
}

func TestAlertingProvisioning(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "routewarden-alerting-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := observability.Export(tempDir); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	alertingPath := filepath.Join(tempDir, "grafana/provisioning/alerting/alerting.yaml")
	data, err := os.ReadFile(alertingPath)
	if err != nil {
		t.Fatalf("failed to read exported alerting.yaml: %v", err)
	}
	content := string(data)

	// Verify contact points
	expectedContactPoints := []string{"routewarden-webhook", "routewarden-slack", "routewarden-discord", "routewarden-pagerduty"}
	for _, cp := range expectedContactPoints {
		if !slices.Contains([]string{cp}, cp) || !containsSubstring(content, cp) {
			t.Errorf("alerting.yaml missing contact point receiver %q", cp)
		}
	}

	// Verify alert rule identifiers
	expectedRules := []string{"rw-ddos-attack-spike", "rw-sensitive-path-probe", "rw-l4-brute-force", "rw-scanner-nuclei-sqlmap"}
	for _, rule := range expectedRules {
		if !containsSubstring(content, rule) {
			t.Errorf("alerting.yaml missing alert rule %q", rule)
		}
	}

	// Verify sync with github/dashboards/alerting.yaml
	githubAlertingPath := filepath.Join("..", "..", "github", "dashboards", "alerting.yaml")
	if githubData, err := os.ReadFile(githubAlertingPath); err == nil {
		if content != string(githubData) {
			t.Errorf("alerting.yaml does not match github/dashboards/alerting.yaml")
		}
	}
}

func TestPublicDashboardAndThreatIntelligenceDrilldowns(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "routewarden-public-dash-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := observability.Export(tempDir); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// 1. Verify docker-compose.yml publicDashboards and embedding configuration
	composePath := filepath.Join(tempDir, "docker-compose.yml")
	composeData, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("failed to read docker-compose.yml: %v", err)
	}
	composeContent := string(composeData)
	if !containsSubstring(composeContent, "publicDashboards") {
		t.Errorf("docker-compose.yml missing publicDashboards feature toggle")
	}
	if !containsSubstring(composeContent, "GF_SECURITY_ALLOW_EMBEDDING") {
		t.Errorf("docker-compose.yml missing GF_SECURITY_ALLOW_EMBEDDING setting")
	}

	// 2. Verify dashboard links and dataLinks in routewarden-overview.json
	dashboardPath := filepath.Join(tempDir, "grafana/dashboards/routewarden-overview.json")
	dashData, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("failed to read dashboard json: %v", err)
	}
	dashContent := string(dashData)

	// Threat intel links
	if !containsSubstring(dashContent, "abuseipdb.com") {
		t.Errorf("dashboard missing AbuseIPDB threat intelligence links")
	}
	if !containsSubstring(dashContent, "virustotal.com") {
		t.Errorf("dashboard missing VirusTotal threat intelligence links")
	}
	if !containsSubstring(dashContent, "shodan.io") {
		t.Errorf("dashboard missing Shodan host intelligence links")
	}
	if !containsSubstring(dashContent, "explore?left=") {
		t.Errorf("dashboard missing Loki forensic threat hunter drilldown link")
	}
}

func containsSubstring(s, sub string) bool {
	return filepath.Clean(s) != "" && len(sub) > 0 && (len(s) >= len(sub) && (s == sub || searchSubstring(s, sub)))
}

func searchSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

