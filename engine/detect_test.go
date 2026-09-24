package engine_test

import (
	"testing"

	"github.com/routewarden/cli/engine"
)

func TestDetectConfigFormat_Detailed(t *testing.T) {
	tests := []struct {
		name       string
		pathOrName string
		content    string
		wantFormat engine.ConfigFormat
		wantTarget string
	}{
		{
			name:       "traefik.toml extension",
			pathOrName: "/etc/traefik/traefik.toml",
			content:    "",
			wantFormat: engine.FormatTraefikTOML,
			wantTarget: "traefik",
		},
		{
			name:       "traefik toml content with [http.middlewares.xyz]",
			pathOrName: "some_config.unknown",
			content:    "[http.middlewares.my-mw.plugin.routewarden]\nenabled = true\n",
			wantFormat: engine.FormatTraefikTOML,
			wantTarget: "traefik",
		},
		{
			name:       "traefik toml content with [http.routers.xyz]",
			pathOrName: "routes.ini",
			content:    "[http.routers.my-router]\nrule = \"Host(`example.com`)\"\n",
			wantFormat: engine.FormatTraefikTOML,
			wantTarget: "traefik",
		},
		{
			name:       "traefik .yml extension",
			pathOrName: "/var/config/dynamic.yml",
			content:    "foo: bar",
			wantFormat: engine.FormatTraefikYAML,
			wantTarget: "traefik",
		},
		{
			name:       "traefik .yaml extension",
			pathOrName: "traefik.yaml",
			content:    "",
			wantFormat: engine.FormatTraefikYAML,
			wantTarget: "traefik",
		},
		{
			name:       "traefik yaml content with middlewares:",
			pathOrName: "custom.txt",
			content:    "middlewares:\n  warden:\n    plugin: routewarden",
			wantFormat: engine.FormatTraefikYAML,
			wantTarget: "traefik",
		},
		{
			name:       "traefik yaml content with http:",
			pathOrName: "custom.txt",
			content:    "http:\n  services:\n    app: {}\n",
			wantFormat: engine.FormatTraefikYAML,
			wantTarget: "traefik",
		},
		{
			name:       "docker-compose.yaml filename",
			pathOrName: "docker-compose.yaml",
			content:    "",
			wantFormat: engine.FormatTraefikLabels,
			wantTarget: "traefik",
		},
		{
			name:       "docker-compose.yml filename",
			pathOrName: "/deploy/docker-compose.prod.yml",
			content:    "",
			wantFormat: engine.FormatTraefikLabels,
			wantTarget: "traefik",
		},
		{
			name:       "compose.yaml filename",
			pathOrName: "compose.override.yaml",
			content:    "",
			wantFormat: engine.FormatTraefikLabels,
			wantTarget: "traefik",
		},
		{
			name:       "content containing traefik.http.middlewares.",
			pathOrName: "labels.env",
			content:    "traefik.http.middlewares.warden.plugin.routewarden.enabled=true",
			wantFormat: engine.FormatTraefikLabels,
			wantTarget: "traefik",
		},
		{
			name:       "content containing traefik.enable=",
			pathOrName: "service.properties",
			content:    "traefik.enable=true\nfoo=bar",
			wantFormat: engine.FormatTraefikLabels,
			wantTarget: "traefik",
		},
		{
			name:       "Caddyfile name",
			pathOrName: "/etc/caddy/Caddyfile",
			content:    "",
			wantFormat: engine.FormatCaddyfile,
			wantTarget: "caddy",
		},
		{
			name:       ".caddy extension",
			pathOrName: "site.caddy",
			content:    "",
			wantFormat: engine.FormatCaddyfile,
			wantTarget: "caddy",
		},
		{
			name:       ".caddyfile extension",
			pathOrName: "config.caddyfile",
			content:    "",
			wantFormat: engine.FormatCaddyfile,
			wantTarget: "caddy",
		},
		{
			name:       "content containing routewarden {",
			pathOrName: "directive.conf",
			content:    ":80 {\n  routewarden {\n    methods GET\n  }\n}",
			wantFormat: engine.FormatCaddyfile,
			wantTarget: "caddy",
		},
		{
			name:       "content containing route_warden {",
			pathOrName: "directive.conf",
			content:    ":80 {\n  route_warden {\n  }\n}",
			wantFormat: engine.FormatCaddyfile,
			wantTarget: "caddy",
		},
		{
			name:       "nginx.conf name",
			pathOrName: "/etc/nginx/nginx.conf",
			content:    "",
			wantFormat: engine.FormatNginx,
			wantTarget: "nginx",
		},
		{
			name:       ".conf extension",
			pathOrName: "default.conf",
			content:    "",
			wantFormat: engine.FormatNginx,
			wantTarget: "nginx",
		},
		{
			name:       "content containing resty.routewarden",
			pathOrName: "openresty_snippet.lua",
			content:    "local rw = require(\"resty.routewarden\")",
			wantFormat: engine.FormatNginx,
			wantTarget: "nginx",
		},
		{
			name:       ".json extension",
			pathOrName: "routewarden.json",
			content:    "{}",
			wantFormat: engine.FormatJSON,
			wantTarget: "",
		},
		{
			name:       "JSON content starting with { and ending with }",
			pathOrName: "-",
			content:    `  { "enabled": true }  `,
			wantFormat: engine.FormatJSON,
			wantTarget: "",
		},
		{
			name:       "unknown format and target",
			pathOrName: "arbitrary.bin",
			content:    "some random binary or plain text without keywords",
			wantFormat: engine.FormatUnknown,
			wantTarget: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotFmt := engine.DetectConfigFormat(tc.pathOrName, []byte(tc.content))
			if gotFmt != tc.wantFormat {
				t.Errorf("DetectConfigFormat(%q) = %q, want %q", tc.pathOrName, gotFmt, tc.wantFormat)
			}
			gotTarget := engine.InferredTargetFromFormat(gotFmt)
			if gotTarget != tc.wantTarget {
				t.Errorf("InferredTargetFromFormat(%q) = %q, want %q", gotFmt, gotTarget, tc.wantTarget)
			}
		})
	}
}
