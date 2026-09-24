package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// TraefikLabel represents a single key-value label pair.
type TraefikLabel struct {
	Key   string
	Value string
}

// parseLabelLine parses a single label line formatted as key=val, key: val, or list item.
// Handles both quoted strings and unquoted boolean literals (e.g. true, false).
func parseLabelLine(rawLine string) (TraefikLabel, bool) {
	line := strings.TrimSpace(rawLine)
	line = strings.TrimPrefix(line, "-")
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return TraefikLabel{}, false
	}

	// Unquote entire line if quoted as "- 'key=value'" or "- \"key: value\""
	if (strings.HasPrefix(line, `"`) && strings.HasSuffix(line, `"`)) ||
		(strings.HasPrefix(line, `'`) && strings.HasSuffix(line, `'`)) {
		line = strings.Trim(line, `"'`)
	}

	var k, v string
	if strings.Contains(line, "=") {
		parts := strings.SplitN(line, "=", 2)
		k = strings.TrimSpace(parts[0])
		v = strings.TrimSpace(parts[1])
	} else if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		k = strings.TrimSpace(parts[0])
		v = strings.TrimSpace(parts[1])
	} else {
		return TraefikLabel{}, false
	}

	k = strings.Trim(k, `"'`)
	v = strings.Trim(v, `"'`)

	if strings.HasPrefix(k, "traefik.") {
		return TraefikLabel{Key: k, Value: v}, true
	}
	return TraefikLabel{}, false
}

// ParseTraefikLabels parses lines or comma-separated lists of Docker labels.
// Supports lines like:
//   - "traefik.http.middlewares.my-shield.plugin.routewarden.enabled=true"
//     traefik.http.middlewares.my-shield.plugin.routewarden.enabled: true
//     traefik.http.middlewares.my-shield.plugin.routewarden.response.mode=json
func ParseTraefikLabels(content string) []TraefikLabel {
	lines := strings.Split(content, "\n")
	var items []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		// If line contains multiple comma-separated traefik labels (e.g. CLI flag format)
		if strings.Contains(l, ",traefik.") {
			parts := strings.Split(l, ",")
			for _, p := range parts {
				items = append(items, strings.TrimSpace(p))
			}
		} else {
			items = append(items, l)
		}
	}

	var labels []TraefikLabel
	for _, rawLine := range items {
		if lbl, ok := parseLabelLine(rawLine); ok {
			labels = append(labels, lbl)
		}
	}
	return labels
}

// ExtractLabelsFromCompose extracts Traefik labels from docker-compose.yaml content,
// supporting both list-of-strings format (- "traefik.xxx=yyy") and YAML dictionary format
// (traefik.xxx: true).
func ExtractLabelsFromCompose(composeContent string) []TraefikLabel {
	var labels []TraefikLabel
	lines := strings.Split(composeContent, "\n")
	inLabels := false
	labelsIndent := -1

	for _, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "labels:") {
			inLabels = true
			labelsIndent = len(rawLine) - len(strings.TrimLeft(rawLine, " \t"))
			continue
		}

		if inLabels {
			currentIndent := len(rawLine) - len(strings.TrimLeft(rawLine, " \t"))
			// Exit labels block if indentation is back to labelsIndent or less
			if currentIndent <= labelsIndent {
				inLabels = false
				continue
			}

			if lbl, ok := parseLabelLine(trimmed); ok {
				labels = append(labels, lbl)
				continue
			}

			// If it's another YAML property at the same service level (e.g. image:, ports:, environment:)
			if !strings.HasPrefix(trimmed, "-") && strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, "traefik.") {
				if currentIndent <= labelsIndent+2 {
					inLabels = false
				}
			}
		}
	}

	// Fallback: if inLabels didn't catch or labels are formatted differently, scan all lines
	if len(labels) == 0 {
		return ParseTraefikLabels(composeContent)
	}
	return labels
}

// normalizePropKey normalizes property casing and naming variations.
func normalizePropKey(prop string) string {
	lower := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(prop, "_", ""), "-", ""))
	switch lower {
	case "enabled":
		return "enabled"
	case "enabledefaultpatterns":
		return "enableDefaultPatterns"
	case "enabledefaultallowpatterns":
		return "enableDefaultAllowPatterns"
	case "pathpatterns":
		return "pathPatterns"
	case "blockpatterns":
		return "blockPatterns"
	case "allowpatterns":
		return "allowPatterns"
	case "allowedips":
		return "allowedIps"
	case "methods":
		return "methods"
	case "checkquery":
		return "checkQuery"
	case "checkheaders":
		return "checkHeaders"
	case "statuscode", "status":
		return "statusCode"
	case "customresponsetext":
		return "customResponseText"
	case "debug":
		return "debug"
	case "securitylog":
		return "securityLog"
	case "action":
		return "action"
	case "mode":
		return "mode"
	default:
		if after, ok :=strings.CutPrefix(lower, "response."); ok  {
			sub := after
			switch sub {
			case "statuscode", "status":
				return "response.statusCode"
			case "mode":
				return "response.mode"
			case "body":
				return "response.body"
			case "redirecturl":
				return "response.redirectUrl"
			case "proxyurl":
				return "response.proxyUrl"
			default:
				return prop
			}
		}
		return prop
	}
}

// normalizeBool parses boolean strings, handling unquoted YAML booleans (true, false, yes, no, 1, 0).
func normalizeBool(val string, defaultVal bool) bool {
	v := strings.ToLower(strings.TrimSpace(val))
	switch v {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return defaultVal
	}
}

// ConvertLabelsToTraefikDynamicYAML converts a collection of Traefik labels into a standalone dynamic YAML configuration.
func ConvertLabelsToTraefikDynamicYAML(labels []TraefikLabel) (string, error) {
	middlewareProps := make(map[string]map[string]string)
	middlewareListPattern := regexp.MustCompile(`^traefik\.http\.middlewares\.([a-zA-Z0-9_-]+)\.plugin\.(?:routewarden|traefik-warden|traefik_warden|warden)\.(.+)$`)

	for _, l := range labels {
		m := middlewareListPattern.FindStringSubmatch(l.Key)
		if len(m) == 3 {
			name := m[1]
			prop := normalizePropKey(m[2])
			if _, exists := middlewareProps[name]; !exists {
				middlewareProps[name] = make(map[string]string)
			}
			middlewareProps[name][prop] = l.Value
		}
	}

	if len(middlewareProps) == 0 {
		return "", fmt.Errorf("no RouteWarden middleware labels found (pattern: traefik.http.middlewares.<name>.plugin.routewarden.<property>=...)")
	}

	var b strings.Builder
	b.WriteString("# Traefik dynamic configuration translated from Docker labels by RouteWarden\n")
	b.WriteString("http:\n")
	b.WriteString("  routers:\n")

	// Collect and sort middleware names deterministically
	var mwNames []string
	for name := range middlewareProps {
		mwNames = append(mwNames, name)
	}
	sort.Strings(mwNames)

	b.WriteString("    sandbox-router:\n")
	b.WriteString("      rule: \"PathPrefix(`/`)\"\n")
	b.WriteString("      entryPoints:\n")
	b.WriteString("        - web\n")
	b.WriteString("      middlewares:\n")
	for _, mw := range mwNames {
		fmt.Fprintf(&b, "        - %s\n", mw)
	}
	b.WriteString("      service: ping@internal\n\n")

	b.WriteString("  middlewares:\n")
	for _, name := range mwNames {
		props := middlewareProps[name]
		fmt.Fprintf(&b, "    %s:\n", name)
		b.WriteString("      plugin:\n")
		b.WriteString("        routewarden:\n")

		// Write common boolean properties as unquoted YAML booleans (%t)
		enabled := true
		if val, ok := props["enabled"]; ok {
			enabled = normalizeBool(val, true)
		}
		fmt.Fprintf(&b, "          enabled: %t\n", enabled)

		if val, ok := props["enableDefaultPatterns"]; ok {
			fmt.Fprintf(&b, "          enableDefaultPatterns: %t\n", normalizeBool(val, true))
		}
		if val, ok := props["enableDefaultAllowPatterns"]; ok {
			fmt.Fprintf(&b, "          enableDefaultAllowPatterns: %t\n", normalizeBool(val, true))
		}
		if val, ok := props["checkQuery"]; ok {
			fmt.Fprintf(&b, "          checkQuery: %t\n", normalizeBool(val, false))
		}
		if val, ok := props["debug"]; ok {
			fmt.Fprintf(&b, "          debug: %t\n", normalizeBool(val, false))
		}
		if val, ok := props["securityLog"]; ok {
			fmt.Fprintf(&b, "          securityLog: %t\n", normalizeBool(val, false))
		}

		writeListProp(&b, "pathPatterns", props["pathPatterns"])
		writeListProp(&b, "blockPatterns", props["blockPatterns"])
		writeListProp(&b, "allowPatterns", props["allowPatterns"])
		writeListProp(&b, "allowedIps", props["allowedIps"])
		writeListProp(&b, "methods", props["methods"])
		writeListProp(&b, "checkHeaders", props["checkHeaders"])

		// Response sub-tree
		hasResponse := false
		for k := range props {
			if strings.HasPrefix(k, "response.") {
				hasResponse = true
				break
			}
		}
		if !hasResponse && (props["statusCode"] != "" || props["mode"] != "" || props["action"] != "" || props["customResponseText"] != "") {
			hasResponse = true
		}
		if hasResponse {
			b.WriteString("          response:\n")
			mode := props["response.mode"]
			if mode == "" {
				mode = props["mode"]
			}
			if mode == "" {
				mode = props["action"]
			}
			if mode != "" {
				fmt.Fprintf(&b, "            mode: %s\n", mode)
			}
			status := props["response.statusCode"]
			if status == "" {
				status = props["statusCode"]
			}
			if status != "" {
				fmt.Fprintf(&b, "            statusCode: %s\n", status)
			}
			body := props["response.body"]
			if body == "" {
				body = props["customResponseText"]
			}
			if body != "" {
				fmt.Fprintf(&b, "            body: %q\n", body)
			}
		}
	}

	return b.String(), nil
}

func writeListProp(b *strings.Builder, key, val string) {
	if val == "" {
		return
	}
	items := strings.Split(val, ",")
	fmt.Fprintf(b, "          %s:\n", key)
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			fmt.Fprintf(b, "            - '%s'\n", strings.ReplaceAll(item, "'", "''"))
		}
	}
}
