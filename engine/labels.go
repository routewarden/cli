package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
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
			parts := strings.SplitSeq(l, ",")
			for p := range parts {
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
// (traefik.xxx: true). Uses standard yaml.Unmarshal for robust structured parsing.
func ExtractLabelsFromCompose(composeContent string) []TraefikLabel {
	var composeData struct {
		Services map[string]struct {
			Labels any `yaml:"labels"`
			Deploy struct {
				Labels any `yaml:"labels"`
			} `yaml:"deploy"`
		} `yaml:"services"`
	}

	var labels []TraefikLabel
	if err := yaml.Unmarshal([]byte(composeContent), &composeData); err == nil && len(composeData.Services) > 0 {
		extract := func(raw any) {
			if raw == nil {
				return
			}
			switch v := raw.(type) {
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok {
						if lbl, ok := parseLabelLine(s); ok {
							labels = append(labels, lbl)
						}
					}
				}
			case map[string]any:
				for k, val := range v {
					s := fmt.Sprintf("%s=%v", k, val)
					if lbl, ok := parseLabelLine(s); ok {
						labels = append(labels, lbl)
					}
				}
			}
		}

		for _, svc := range composeData.Services {
			extract(svc.Labels)
			extract(svc.Deploy.Labels)
		}
		if len(labels) > 0 {
			return labels
		}
	}

	// Fallback to text scanning if not valid Compose YAML
	return ParseTraefikLabels(composeContent)
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
	case "blockpatterns":
		return "blockPatterns"
	case "allowpatterns":
		return "allowPatterns"
	case "allowedips":
		return "allowedIps"
	case "trustedproxies":
		return "trustedProxies"
	case "methods":
		return "methods"
	case "checkquery":
		return "checkQuery"
	case "checkheaders":
		return "checkHeaders"
	case "checkbody":
		return "checkBody"
	case "checkbodymaxbytes":
		return "checkBodyMaxBytes"
	case "checkbodypatterns":
		return "checkBodyPatterns"
	case "statuscode":
		return "statusCode"
	case "debug":
		return "debug"
	case "securitylog":
		return "securityLog"
	case "mode":
		return "mode"
	default:
		if after, ok := strings.CutPrefix(lower, "response."); ok {
			sub := after
			switch sub {
			case "statuscode":
				return "response.statusCode"
			case "mode":
				return "response.mode"
			case "body":
				return "response.body"
			case "contenttype":
				return "response.contentType"
			case "redirecturl":
				return "response.redirectUrl"
			case "proxyurl":
				return "response.proxyUrl"
			case "gzipbombmb":
				return "response.gzipBombMB"
			case "retryafterseconds":
				return "response.retryAfterSeconds"
			case "tarpitdelayms":
				return "response.tarpitDelayMs"
			case "tarpitmaxdurationseconds":
				return "response.tarpitMaxDurationSeconds"
			case "streamsizemb":
				return "response.streamSizeMB"
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
	middlewareIndexedProps := make(map[string]map[string]map[int]string)
	middlewareListPattern := regexp.MustCompile(`^traefik\.http\.middlewares\.([a-zA-Z0-9_-]+)\.plugin\.(?:routewarden|traefik-warden|traefik_warden|warden)\.(.+)$`)
	indexPattern := regexp.MustCompile(`^(.+)\[(\d+)\]$`)

	for _, l := range labels {
		m := middlewareListPattern.FindStringSubmatch(l.Key)
		if len(m) == 3 {
			name := m[1]
			rawProp := m[2]
			if _, exists := middlewareProps[name]; !exists {
				middlewareProps[name] = make(map[string]string)
			}
			if im := indexPattern.FindStringSubmatch(rawProp); len(im) == 3 {
				base := normalizePropKey(im[1])
				idx, _ := strconv.Atoi(im[2])
				if _, exists := middlewareIndexedProps[name]; !exists {
					middlewareIndexedProps[name] = make(map[string]map[int]string)
				}
				if _, exists := middlewareIndexedProps[name][base]; !exists {
					middlewareIndexedProps[name][base] = make(map[int]string)
				}
				middlewareIndexedProps[name][base][idx] = l.Value
			} else {
				prop := normalizePropKey(rawProp)
				middlewareProps[name][prop] = l.Value
			}
		}
	}

	for name, baseMap := range middlewareIndexedProps {
		for base, idxMap := range baseMap {
			var indices []int
			for idx := range idxMap {
				indices = append(indices, idx)
			}
			sort.Ints(indices)
			var vals []string
			for _, idx := range indices {
				vals = append(vals, idxMap[idx])
			}
			joined := strings.Join(vals, ",")
			if existing, ok := middlewareProps[name][base]; ok && existing != "" {
				middlewareProps[name][base] = existing + "," + joined
			} else {
				middlewareProps[name][base] = joined
			}
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

		writeListProp(&b, "blockPatterns", props["blockPatterns"])
		writeListProp(&b, "allowPatterns", props["allowPatterns"])
		writeListProp(&b, "allowedIps", props["allowedIps"])
		writeListProp(&b, "trustedProxies", props["trustedProxies"])
		writeListProp(&b, "methods", props["methods"])
		writeListProp(&b, "checkHeaders", props["checkHeaders"])
		if val, ok := props["checkBody"]; ok {
			fmt.Fprintf(&b, "          checkBody: %t\n", normalizeBool(val, false))
		}
		if val, ok := props["checkBodyMaxBytes"]; ok {
			if num, err := strconv.ParseInt(val, 10, 64); err == nil && num > 0 {
				fmt.Fprintf(&b, "          checkBodyMaxBytes: %d\n", num)
			}
		}
		writeListProp(&b, "checkBodyPatterns", props["checkBodyPatterns"])

		// Response sub-tree
		hasResponse := false
		for k := range props {
			if strings.HasPrefix(k, "response.") {
				hasResponse = true
				break
			}
		}
		if !hasResponse && (props["statusCode"] != "" || props["mode"] != "") {
			hasResponse = true
		}
		if hasResponse {
			b.WriteString("          response:\n")
			mode := props["response.mode"]
			if mode == "" {
				mode = props["mode"]
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
			if body != "" {
				fmt.Fprintf(&b, "            body: %q\n", body)
			}
			if ct := props["response.contentType"]; ct != "" {
				fmt.Fprintf(&b, "            contentType: %q\n", ct)
			}
			if ru := props["response.redirectUrl"]; ru != "" {
				fmt.Fprintf(&b, "            redirectUrl: %q\n", ru)
			}
			if pu := props["response.proxyUrl"]; pu != "" {
				fmt.Fprintf(&b, "            proxyUrl: %q\n", pu)
			}
			if gz := props["response.gzipBombMB"]; gz != "" {
				if n, err := strconv.Atoi(gz); err == nil {
					fmt.Fprintf(&b, "            gzipBombMB: %d\n", n)
				}
			}
			if ra := props["response.retryAfterSeconds"]; ra != "" {
				if n, err := strconv.Atoi(ra); err == nil {
					fmt.Fprintf(&b, "            retryAfterSeconds: %d\n", n)
				}
			}
			if td := props["response.tarpitDelayMs"]; td != "" {
				if n, err := strconv.Atoi(td); err == nil {
					fmt.Fprintf(&b, "            tarpitDelayMs: %d\n", n)
				}
			}
			if tm := props["response.tarpitMaxDurationSeconds"]; tm != "" {
				if n, err := strconv.Atoi(tm); err == nil {
					fmt.Fprintf(&b, "            tarpitMaxDurationSeconds: %d\n", n)
				}
			}
			if ss := props["response.streamSizeMB"]; ss != "" {
				if n, err := strconv.Atoi(ss); err == nil {
					fmt.Fprintf(&b, "            streamSizeMB: %d\n", n)
				}
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
