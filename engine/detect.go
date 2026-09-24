package engine

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// ConfigFormat represents the detected format of an input configuration.
type ConfigFormat string

const (
	FormatUnknown       ConfigFormat = "unknown"
	FormatJSON          ConfigFormat = "json"
	FormatTraefikYAML   ConfigFormat = "traefik-yaml"
	FormatTraefikTOML   ConfigFormat = "traefik-toml"
	FormatTraefikLabels ConfigFormat = "traefik-labels"
	FormatCaddyfile     ConfigFormat = "caddy"
	FormatNginx         ConfigFormat = "nginx"
)

// DetectConfigFormat inspects a filename, path, and optional content to determine the gateway configuration format.
func DetectConfigFormat(pathOrName string, content []byte) ConfigFormat {
	name := strings.ToLower(filepath.Base(pathOrName))
	ext := strings.ToLower(filepath.Ext(pathOrName))
	strContent := string(content)

	// 1. Docker Compose / Labels
	if strings.HasPrefix(name, "docker-compose") || strings.HasPrefix(name, "compose.") || strings.HasPrefix(name, "compose-") ||
		(strings.Contains(name, "compose") && (ext == ".yaml" || ext == ".yml")) {
		return FormatTraefikLabels
	}
	if strings.Contains(strContent, "traefik.http.middlewares.") || strings.Contains(strContent, "traefik.enable=") ||
		(strings.Contains(strContent, "services:") && strings.Contains(strContent, "labels:")) {
		return FormatTraefikLabels
	}

	// 2. Traefik TOML
	if ext == ".toml" || strings.Contains(strContent, "[http.middlewares.") || strings.Contains(strContent, "[http.routers.") {
		return FormatTraefikTOML
	}

	// 3. Caddyfile
	if name == "caddyfile" || ext == ".caddy" || ext == ".caddyfile" || strings.HasPrefix(name, "caddyfile") ||
		strings.Contains(strContent, "route_warden") || strings.Contains(strContent, "routewarden {") ||
		strings.Contains(strContent, "order routewarden") || strings.Contains(strContent, "reverse_proxy") {
		return FormatCaddyfile
	}

	// 4. NGINX
	if name == "nginx.conf" || name == "nginx" || ext == ".conf" || strings.Contains(strContent, "resty.routewarden") ||
		strings.Contains(strContent, "access_by_lua") || (strings.Contains(strContent, "events {") && strings.Contains(strContent, "http {")) {
		return FormatNginx
	}

	// 5. JSON
	trimmed := strings.TrimSpace(strContent)
	if ext == ".json" || (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") && json.Valid([]byte(trimmed))) {
		return FormatJSON
	}

	// 6. YAML (Traefik Dynamic YAML)
	if ext == ".yaml" || ext == ".yml" || strings.Contains(strContent, "http:") || strings.Contains(strContent, "middlewares:") {
		return FormatTraefikYAML
	}

	return FormatUnknown
}

// InferredTargetFromFormat maps a ConfigFormat to default target gateway ("traefik", "caddy", "nginx").
func InferredTargetFromFormat(fmt ConfigFormat) string {
	switch fmt {
	case FormatTraefikTOML, FormatTraefikYAML, FormatTraefikLabels:
		return "traefik"
	case FormatCaddyfile:
		return "caddy"
	case FormatNginx:
		return "nginx"
	default:
		return ""
	}
}
