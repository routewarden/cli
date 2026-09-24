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
      - "traefik.http.middlewares.my-shield.plugin.routewarden.pathPatterns=(?i)^/api/auth/login.*$,(?i)^/admin.*$"
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

