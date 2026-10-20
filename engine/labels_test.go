package engine_test

import (
	"strings"
	"testing"

	"github.com/routewarden/cli/engine"
)

func TestDetectConfigFormat(t *testing.T) {
	tests := []struct {
		name       string
		pathOrName string
		content    string
		wantFormat engine.ConfigFormat
		wantTarget string
	}{
		{
			name:       "traefik toml",
			pathOrName: "dynamic_conf.toml",
			content:    "[http.routers.app]\nrule = \"Host(`localhost`)\"",
			wantFormat: engine.FormatTraefikTOML,
			wantTarget: "traefik",
		},
		{
			name:       "traefik yaml",
			pathOrName: "dynamic_conf.yml",
			content:    "http:\n  middlewares:\n    shield:\n",
			wantFormat: engine.FormatTraefikYAML,
			wantTarget: "traefik",
		},
		{
			name:       "docker-compose yaml",
			pathOrName: "docker-compose.yaml",
			content:    "services:\n  app:\n    labels:\n      - \"traefik.enable=true\"",
			wantFormat: engine.FormatTraefikLabels,
			wantTarget: "traefik",
		},
		{
			name:       "caddyfile",
			pathOrName: "Caddyfile",
			content:    ":8080 {\n  routewarden {\n  }\n}",
			wantFormat: engine.FormatCaddyfile,
			wantTarget: "caddy",
		},
		{
			name:       "nginx conf",
			pathOrName: "nginx.conf",
			content:    "events {}\nhttp {\n  init_by_lua_block { require(\"resty.routewarden\") }\n}",
			wantFormat: engine.FormatNginx,
			wantTarget: "nginx",
		},
		{
			name:       "json config",
			pathOrName: "routewarden.json",
			content:    `{"enabled": true}`,
			wantFormat: engine.FormatJSON,
			wantTarget: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotFmt := engine.DetectConfigFormat(tc.pathOrName, []byte(tc.content))
			if gotFmt != tc.wantFormat {
				t.Errorf("expected format %s, got %s", tc.wantFormat, gotFmt)
			}
			gotTarget := engine.InferredTargetFromFormat(gotFmt)
			if gotTarget != tc.wantTarget {
				t.Errorf("expected target %s, got %s", tc.wantTarget, gotTarget)
			}
		})
	}
}

func TestLabels_ParseAndConvert(t *testing.T) {
	composeContent := `services:
  app:
    image: my-app
    labels:
      - "traefik.enable=true"
      - "traefik.http.middlewares.my-shield.plugin.routewarden.enabled=true"
      - "traefik.http.middlewares.my-shield.plugin.routewarden.enableDefaultPatterns=true"
      - "traefik.http.middlewares.my-shield.plugin.routewarden.blockPatterns=(?i)^/api/auth/login.*$,(?i)^/admin.*$"
      - "traefik.http.middlewares.my-shield.plugin.routewarden.allowedIps=10.0.0.0/8,192.168.1.0/24"
      - "traefik.http.middlewares.my-shield.plugin.routewarden.response.mode=json"
      - "traefik.http.middlewares.my-shield.plugin.routewarden.response.statusCode=404"
      - 'traefik.http.middlewares.my-shield.plugin.routewarden.response.body={"error":"Not Found"}'
`

	labels := engine.ExtractLabelsFromCompose(composeContent)
	if len(labels) == 0 {
		t.Fatalf("expected extracted labels, got none")
	}

	yamlOut, err := engine.ConvertLabelsToTraefikDynamicYAML(labels)
	if err != nil {
		t.Fatalf("failed to convert labels: %v", err)
	}

	if !strings.Contains(yamlOut, "my-shield:") {
		t.Errorf("missing middleware name 'my-shield' in yaml output:\n%s", yamlOut)
	}
	if !strings.Contains(yamlOut, "- '(?i)^/api/auth/login.*$'") {
		t.Errorf("missing pathPattern in yaml output:\n%s", yamlOut)
	}
	if !strings.Contains(yamlOut, "statusCode: 404") {
		t.Errorf("missing statusCode: 404 in yaml output:\n%s", yamlOut)
	}
	if !strings.Contains(yamlOut, "10.0.0.0/8") {
		t.Errorf("missing allowed IP in yaml output:\n%s", yamlOut)
	}
}

func TestLabels_UnquotedBooleanDictionary(t *testing.T) {
	composeContent := `services:
  app:
    image: traefik/whoami:latest
    labels:
      traefik.http.middlewares.compose-shield.plugin.routewarden.enableDefaultAllowPatterns: true
      traefik.http.middlewares.compose-shield.plugin.routewarden.enableDefaultPatterns: true
      traefik.http.middlewares.compose-shield.plugin.routewarden.enabled: true
      traefik.http.middlewares.compose-shield.plugin.routewarden.debug: true
      traefik.http.middlewares.compose-shield.plugin.routewarden.securityLog: true
`

	labels := engine.ExtractLabelsFromCompose(composeContent)
	if len(labels) != 5 {
		t.Fatalf("expected 5 extracted labels, got %d: %+v", len(labels), labels)
	}

	yamlOut, err := engine.ConvertLabelsToTraefikDynamicYAML(labels)
	if err != nil {
		t.Fatalf("failed to convert labels: %v", err)
	}

	expectedClauses := []string{
		"compose-shield:",
		"enabled: true",
		"enableDefaultPatterns: true",
		"enableDefaultAllowPatterns: true",
		"debug: true",
		"securityLog: true",
	}

	for _, clause := range expectedClauses {
		if !strings.Contains(yamlOut, clause) {
			t.Errorf("missing %q in converted dynamic YAML:\n%s", clause, yamlOut)
		}
	}
}

func TestLabels_TrustedProxies(t *testing.T) {
	labelContent := `
traefik.http.middlewares.proxy-shield.plugin.routewarden.enabled=true
traefik.http.middlewares.proxy-shield.plugin.routewarden.trustedProxies=10.0.0.0/8,172.16.0.0/12
`
	labels := engine.ParseTraefikLabels(labelContent)
	yamlOut, err := engine.ConvertLabelsToTraefikDynamicYAML(labels)
	if err != nil {
		t.Fatalf("failed to convert labels: %v", err)
	}

	if !strings.Contains(yamlOut, "trustedProxies:") ||
		!strings.Contains(yamlOut, "- '10.0.0.0/8'") ||
		!strings.Contains(yamlOut, "- '172.16.0.0/12'") {
		t.Errorf("expected trustedProxies in converted dynamic YAML:\n%s", yamlOut)
	}
}

func TestLabels_IndexedArrayLabels(t *testing.T) {
	labelContent := `
traefik.http.middlewares.indexed-shield.plugin.routewarden.enabled=true
traefik.http.middlewares.indexed-shield.plugin.routewarden.blockPatterns[0]=(?i)^/admin
traefik.http.middlewares.indexed-shield.plugin.routewarden.blockPatterns[1]=(?i)^/metrics
traefik.http.middlewares.indexed-shield.plugin.routewarden.allowedIps[0]=10.0.0.0/8
traefik.http.middlewares.indexed-shield.plugin.routewarden.allowedIps[1]=192.168.1.100
`
	labels := engine.ParseTraefikLabels(labelContent)
	yamlOut, err := engine.ConvertLabelsToTraefikDynamicYAML(labels)
	if err != nil {
		t.Fatalf("failed to convert labels: %v", err)
	}

	if !strings.Contains(yamlOut, "indexed-shield:") {
		t.Errorf("expected 'indexed-shield:' in YAML:\n%s", yamlOut)
	}
	if !strings.Contains(yamlOut, "- '(?i)^/admin'") || !strings.Contains(yamlOut, "- '(?i)^/metrics'") {
		t.Errorf("expected indexed blockPatterns in YAML:\n%s", yamlOut)
	}
	if !strings.Contains(yamlOut, "- '10.0.0.0/8'") || !strings.Contains(yamlOut, "- '192.168.1.100'") {
		t.Errorf("expected indexed allowedIps in YAML:\n%s", yamlOut)
	}
}

func TestLabels_ParseLabelLine_EdgeCases(t *testing.T) {
	// Raw lines with quotes, comments, invalid keys
	content := `
# Full-line comment should be ignored
  # Indented comment should be ignored
  
- "traefik.http.middlewares.q1.plugin.routewarden.enabled=true"
- 'traefik.http.middlewares.q2.plugin.routewarden.enabled: false'
- "not-traefik.label.key=value"
- invalid-line-without-separator
traefik.http.middlewares.colon.plugin.routewarden.enabled: true
traefik.http.middlewares.quotes.plugin.routewarden.response.body="{\"status\":\"blocked\"}"
`
	labels := engine.ParseTraefikLabels(content)
	if len(labels) != 4 {
		t.Fatalf("expected 4 valid traefik labels, got %d: %+v", len(labels), labels)
	}

	keys := map[string]string{}
	for _, l := range labels {
		keys[l.Key] = l.Value
	}

	if keys["traefik.http.middlewares.q1.plugin.routewarden.enabled"] != "true" {
		t.Errorf("expected q1 enabled true, got %v", keys["traefik.http.middlewares.q1.plugin.routewarden.enabled"])
	}
	if keys["traefik.http.middlewares.q2.plugin.routewarden.enabled"] != "false" {
		t.Errorf("expected q2 enabled false, got %v", keys["traefik.http.middlewares.q2.plugin.routewarden.enabled"])
	}
	if keys["traefik.http.middlewares.colon.plugin.routewarden.enabled"] != "true" {
		t.Errorf("expected colon enabled true, got %v", keys["traefik.http.middlewares.colon.plugin.routewarden.enabled"])
	}
}

func TestLabels_ConvertLabelsToTraefikDynamicYAML_AllResponseFields(t *testing.T) {
	labelContent := `
traefik.http.middlewares.full-shield.plugin.routewarden.enabled=1
traefik.http.middlewares.full-shield.plugin.routewarden.enable_default_patterns=yes
traefik.http.middlewares.full-shield.plugin.routewarden.enable-default-allow-patterns=on
traefik.http.middlewares.full-shield.plugin.routewarden.check-query=true
traefik.http.middlewares.full-shield.plugin.routewarden.check_body=true
traefik.http.middlewares.full-shield.plugin.routewarden.check-body-max-bytes=131072
traefik.http.middlewares.full-shield.plugin.routewarden.check_body_patterns=(?i)malicious_payload,(?i)union_select
traefik.http.middlewares.full-shield.plugin.routewarden.check_headers=X-Custom-Auth,X-Forwarded-Host
traefik.http.middlewares.full-shield.plugin.routewarden.methods=GET,POST,PUT,DELETE
traefik.http.middlewares.full-shield.plugin.routewarden.response.mode=tarpit
traefik.http.middlewares.full-shield.plugin.routewarden.response.status_code=429
traefik.http.middlewares.full-shield.plugin.routewarden.response.content_type=text/plain; charset=utf-8
traefik.http.middlewares.full-shield.plugin.routewarden.response.body=Rate limited, please slow down
traefik.http.middlewares.full-shield.plugin.routewarden.response.redirect_url=https://example.com/blocked
traefik.http.middlewares.full-shield.plugin.routewarden.response.proxy_url=http://127.0.0.1:9999/honeypot
traefik.http.middlewares.full-shield.plugin.routewarden.response.gzip_bomb_mb=25
traefik.http.middlewares.full-shield.plugin.routewarden.response.retry_after_seconds=120
traefik.http.middlewares.full-shield.plugin.routewarden.response.tarpit_delay_ms=2500
traefik.http.middlewares.full-shield.plugin.routewarden.response.tarpit_max_duration_seconds=15
traefik.http.middlewares.full-shield.plugin.routewarden.response.stream_size_mb=10
`
	labels := engine.ParseTraefikLabels(labelContent)
	yamlOut, err := engine.ConvertLabelsToTraefikDynamicYAML(labels)
	if err != nil {
		t.Fatalf("failed to convert labels: %v", err)
	}

	expectedSnippets := []string{
		"full-shield:",
		"enabled: true",
		"enableDefaultPatterns: true",
		"enableDefaultAllowPatterns: true",
		"checkQuery: true",
		"checkBody: true",
		"checkBodyMaxBytes: 131072",
		"- '(?i)malicious_payload'",
		"- '(?i)union_select'",
		"- 'X-Custom-Auth'",
		"- 'X-Forwarded-Host'",
		"- 'GET'",
		"- 'POST'",
		"response:",
		"mode: tarpit",
		"statusCode: 429",
		"contentType: \"text/plain; charset=utf-8\"",
		"body: \"Rate limited, please slow down\"",
		"redirectUrl: \"https://example.com/blocked\"",
		"proxyUrl: \"http://127.0.0.1:9999/honeypot\"",
		"gzipBombMB: 25",
		"retryAfterSeconds: 120",
		"tarpitDelayMs: 2500",
		"tarpitMaxDurationSeconds: 15",
		"streamSizeMB: 10",
	}

	for _, s := range expectedSnippets {
		if !strings.Contains(yamlOut, s) {
			t.Errorf("missing expected snippet %q in YAML:\n%s", s, yamlOut)
		}
	}
}

func TestLabels_ConvertLabelsToTraefikDynamicYAML_NoLabelsError(t *testing.T) {
	labelContent := `
traefik.http.routers.my-router.rule=Host('example.com')
traefik.http.services.my-service.loadbalancer.server.port=8080
`
	labels := engine.ParseTraefikLabels(labelContent)
	_, err := engine.ConvertLabelsToTraefikDynamicYAML(labels)
	if err == nil {
		t.Fatalf("expected error when no RouteWarden labels exist, got nil")
	}
	if !strings.Contains(err.Error(), "no RouteWarden middleware labels found") {
		t.Errorf("expected 'no RouteWarden middleware labels found' error, got: %v", err)
	}
}

func TestLabels_ExtractLabelsFromCompose_DeployLabels(t *testing.T) {
	composeContent := `
services:
  swarm-app:
    image: nginx:alpine
    deploy:
      labels:
        traefik.http.middlewares.swarm-shield.plugin.routewarden.enabled: true
        traefik.http.middlewares.swarm-shield.plugin.routewarden.mode: reject
        traefik.http.middlewares.swarm-shield.plugin.routewarden.statusCode: "403"
`
	labels := engine.ExtractLabelsFromCompose(composeContent)
	if len(labels) < 3 {
		t.Fatalf("expected at least 3 labels extracted from deploy.labels, got %d", len(labels))
	}

	yamlOut, err := engine.ConvertLabelsToTraefikDynamicYAML(labels)
	if err != nil {
		t.Fatalf("failed to convert labels: %v", err)
	}

	if !strings.Contains(yamlOut, "swarm-shield:") {
		t.Errorf("expected swarm-shield in YAML output:\n%s", yamlOut)
	}
	if !strings.Contains(yamlOut, "mode: reject") || !strings.Contains(yamlOut, "statusCode: 403") {
		t.Errorf("expected response mode and statusCode in YAML:\n%s", yamlOut)
	}
}

func TestLabels_ListProp_SingleQuoteEscaping(t *testing.T) {
	// Values containing single quotes should have them doubled in YAML list
	labelContent := `
traefik.http.middlewares.escape-shield.plugin.routewarden.enabled=true
traefik.http.middlewares.escape-shield.plugin.routewarden.blockPatterns=(?i)O'Reilly,(?i)user's_token
`
	labels := engine.ParseTraefikLabels(labelContent)
	yamlOut, err := engine.ConvertLabelsToTraefikDynamicYAML(labels)
	if err != nil {
		t.Fatalf("failed to convert labels: %v", err)
	}

	if !strings.Contains(yamlOut, "O''Reilly") || !strings.Contains(yamlOut, "user''s_token") {
		t.Errorf("expected single quotes escaped as double single-quotes in YAML:\n%s", yamlOut)
	}
}

func TestLabels_ConfigFile(t *testing.T) {
	// 1. camelCase configFile
	content1 := `
traefik.http.middlewares.cfg-shield.plugin.routewarden.configFile=/etc/routewarden/base.json
`
	labels1 := engine.ParseTraefikLabels(content1)
	yamlOut1, err := engine.ConvertLabelsToTraefikDynamicYAML(labels1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(yamlOut1, "configFile: /etc/routewarden/base.json") {
		t.Errorf("expected configFile in YAML, got:\n%s", yamlOut1)
	}

	// 2. snake_case config_file
	content2 := `
traefik.http.middlewares.cfg-shield.plugin.routewarden.config_file=/etc/routewarden/base.json
`
	labels2 := engine.ParseTraefikLabels(content2)
	yamlOut2, err := engine.ConvertLabelsToTraefikDynamicYAML(labels2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(yamlOut2, "configFile: /etc/routewarden/base.json") {
		t.Errorf("expected configFile in YAML for snake_case label, got:\n%s", yamlOut2)
	}
}

func TestLabels_GzipBombMB_FloatingValues(t *testing.T) {
	content := `
traefik.http.middlewares.bomb-shield.plugin.routewarden.response.mode=gzipBomb
traefik.http.middlewares.bomb-shield.plugin.routewarden.response.gzip_bomb_mb=0.5
`
	labels := engine.ParseTraefikLabels(content)
	yamlOut, err := engine.ConvertLabelsToTraefikDynamicYAML(labels)
	if err != nil {
		t.Fatalf("failed to convert labels: %v", err)
	}

	if !strings.Contains(yamlOut, "gzipBombMB: 0.5") {
		t.Errorf("expected 'gzipBombMB: 0.5' in YAML, got:\n%s", yamlOut)
	}
}

