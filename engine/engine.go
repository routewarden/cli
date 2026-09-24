package engine

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// DefaultBlockPatterns contains well-known sensitive endpoints and file extensions.
var DefaultBlockPatterns = []string{
	// Sensitive extensions & environment files (e.g. .env, .env.local, .txt, .log, .bak, .backup, .sql, .conf, .config, .ini, .yaml, .yml)
	`(?i)(^|/)(\.env.*|.*\.(txt|log|bak|backup|sql|conf|config|ini|yaml|yml))$`,
	// Version control & sensitive hidden directories
	`(?i)(^|/)\.(git|svn|hg|bzr|cvs)(/.*|$)`,
	// Cloud & infra credentials
	`(?i)(^|/)\.(aws|ssh|kube|docker)(/.*|$)`,
	// Database & server dump files / archives
	`(?i).*\.(tar|tar\.gz|tgz|zip|rar|7z|gz|bz2|iso|dump|sqlite|sqlite3|db)$`,
	// Common sensitive admin & debug endpoints
	`(?i)(^|/)(phpinfo\.php|info\.php|server-status|server-info|actuator(/.*)?|metrics|heapdump|trace|env)$`,
	// Package manager files & lockfiles
	`(?i)(^|/)(composer\.(json|lock)|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Pipfile|Pipfile\.lock|requirements\.txt)$`,
	// TLS & cryptographic private keys, certificates, keystores
	`(?i).*\.(pem|key|crt|pfx|p12|jks|kdb)$`,
	// Container & orchestration manifests and configs
	`(?i)(^|/)(dockerfile.*|docker-compose.*\.ya?ml)$`,
	// System & macOS metadata files
	`(?i)(^|/)\.ds_store$`,
	// Web framework and CMS sensitive configuration files
	`(?i)(^|/)(wp-config\.php.*|configuration\.php.*|settings\.py|local_settings\.py)$`,
}

// DefaultAllowPatterns contains typical legitimate endpoints that might otherwise match broad patterns.
var DefaultAllowPatterns = []string{
	`(?i)^/robots\.txt$`,
	`(?i)^/sitemap.*\.xml$`,
	`(?i)^/ads\.txt$`,
	`(?i)^/security\.txt$`,
	`(?i)^/\.well-known(/.*)?$`,
}

// CaptchaConfig holds captcha configuration options.
type CaptchaConfig struct {
	Provider string `json:"provider,omitempty"`
	SiteKey  string `json:"siteKey,omitempty"`
	Title    string `json:"title,omitempty"`
	Template string `json:"template,omitempty"`
}

// ResponseConfig defines how blocked requests should be answered.
type ResponseConfig struct {
	Mode                     string            `json:"mode,omitempty"`
	StatusCode               int               `json:"statusCode,omitempty"`
	ContentType              string            `json:"contentType,omitempty"`
	Body                     string            `json:"body,omitempty"`
	Headers                  map[string]string `json:"headers,omitempty"`
	RedirectURL              string            `json:"redirectUrl,omitempty"`
	ProxyURL                 string            `json:"proxyUrl,omitempty"`
	Captcha                  *CaptchaConfig    `json:"captcha,omitempty"`
	GzipBombMB               int               `json:"gzipBombMB,omitempty"`
	RetryAfterSeconds        int               `json:"retryAfterSeconds,omitempty"`
	TarpitDelayMs            int               `json:"tarpitDelayMs,omitempty"`
	TarpitMaxDurationSeconds int               `json:"tarpitMaxDurationSeconds,omitempty"`
	StreamSizeMB             int               `json:"streamSizeMB,omitempty"`
}

// Config holds the RouteWarden configuration.
type Config struct {
	Enabled                    bool            `json:"enabled,omitempty"`
	EnableDefaultPatterns      bool            `json:"enableDefaultPatterns,omitempty"`
	EnableDefaultAllowPatterns bool            `json:"enableDefaultAllowPatterns,omitempty"`
	PathPatterns               []string        `json:"pathPatterns,omitempty"`
	BlockPatterns              []string        `json:"blockPatterns,omitempty"`
	AllowPatterns              []string        `json:"allowPatterns,omitempty"`
	AllowedIPs                 []string        `json:"allowedIps,omitempty"`
	Methods                    []string        `json:"methods,omitempty"`
	StatusCode                 int             `json:"statusCode,omitempty"`
	CustomResponseText         string          `json:"customResponseText,omitempty"`
	SilentDrop                 bool            `json:"silentDrop,omitempty"`
	Action                     string          `json:"action,omitempty"`
	Mode                       string          `json:"mode,omitempty"`
	CheckQuery                 bool            `json:"checkQuery,omitempty"`
	CheckHeaders               []string        `json:"checkHeaders,omitempty"`
	Debug                      bool            `json:"debug,omitempty"`
	SecurityLog                bool            `json:"securityLog,omitempty"`
	Response                   *ResponseConfig `json:"response,omitempty"`
}

// CreateConfig creates default RouteWarden configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                    true,
		EnableDefaultPatterns:      true,
		EnableDefaultAllowPatterns: true,
		PathPatterns:               []string{},
		BlockPatterns:              []string{},
		AllowPatterns:              []string{},
		AllowedIPs:                 []string{},
		Methods:                    []string{"GET"},
		StatusCode:                 403,
		CustomResponseText:         "403 Forbidden: Access to sensitive endpoint is blocked",
		SilentDrop:                 false,
		CheckQuery:                 false,
		CheckHeaders:               []string{},
		Debug:                      false,
		SecurityLog:                true,
		Response: &ResponseConfig{
			Mode: "text",
		},
	}
}

// ExtractCandidatePaths normalizes and extracts all representations of a request URI path.
func ExtractCandidatePaths(rawPath, pathStr, requestURI string) []string {
	pathsToCheck := []string{path.Clean(pathStr)}

	rawURIPath := requestURI
	if idx := strings.IndexByte(rawURIPath, '?'); idx != -1 {
		rawURIPath = rawURIPath[:idx]
	}
	if rawURIPath != "" {
		pathsToCheck = append(pathsToCheck, path.Clean(rawURIPath))
	}

	if rawPath != "" && rawPath != pathStr {
		pathsToCheck = append(pathsToCheck, path.Clean(rawPath))
	}

	curPath := pathStr
	for i := 0; i < 3; i++ {
		unescaped, err := url.PathUnescape(curPath)
		if err != nil || unescaped == curPath {
			break
		}
		pathsToCheck = append(pathsToCheck, path.Clean(unescaped))
		curPath = unescaped
	}

	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.ContainsRune(p, '\\') {
			slashConverted := strings.ReplaceAll(p, "\\", "/")
			pathsToCheck = append(pathsToCheck, path.Clean(slashConverted))
		}
	}

	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.ContainsRune(p, ';') {
			parts := strings.Split(p, "/")
			cleanedSegments := make([]string, len(parts))
			paramSegments := make([]string, 0)
			for i, seg := range parts {
				if semiIdx := strings.IndexByte(seg, ';'); semiIdx != -1 {
					cleanedSegments[i] = seg[:semiIdx]
					paramSegments = append(paramSegments, seg[semiIdx+1:])
				} else {
					cleanedSegments[i] = seg
				}
			}
			matrixStripped := strings.Join(cleanedSegments, "/")
			pathsToCheck = append(pathsToCheck, path.Clean(matrixStripped))

			for _, param := range paramSegments {
				if param != "" {
					pathsToCheck = append(pathsToCheck, "/"+param, path.Clean("/"+param))
				}
			}

			semiAsSlash := strings.ReplaceAll(p, ";", "/")
			pathsToCheck = append(pathsToCheck, path.Clean(semiAsSlash))
		}
	}

	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.ContainsRune(p, '\x00') {
			pathsToCheck = append(pathsToCheck, path.Clean(strings.ReplaceAll(p, "\x00", "")))
		}
	}

	candidatePaths := make([]string, 0, len(pathsToCheck))
	seen := make(map[string]struct{}, len(pathsToCheck))
	for _, p := range pathsToCheck {
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = path.Clean(p)
		if _, exists := seen[p]; !exists {
			seen[p] = struct{}{}
			candidatePaths = append(candidatePaths, p)
		}
	}

	return candidatePaths
}

// Engine represents a compiled inspection engine.
type Engine struct {
	Config       *Config
	Methods      map[string]struct{}
	BlockRegexes []*regexp.Regexp
	AllowRegexes []*regexp.Regexp
	AllowedIPs   []net.IP
	AllowedNets  []*net.IPNet
}

// NewEngine validates and compiles a RouteWarden configuration.
func NewEngine(cfg *Config) (*Engine, error) {
	if cfg == nil {
		cfg = CreateConfig()
	}

	methodsMap := make(map[string]struct{})
	if len(cfg.Methods) == 0 {
		methodsMap["GET"] = struct{}{}
	} else {
		for _, m := range cfg.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != "" {
				methodsMap[m] = struct{}{}
			}
		}
		if len(methodsMap) == 0 {
			methodsMap["GET"] = struct{}{}
		}
	}

	var blockPatterns []string
	if cfg.EnableDefaultPatterns {
		blockPatterns = append(blockPatterns, DefaultBlockPatterns...)
	}
	blockPatterns = append(blockPatterns, cfg.PathPatterns...)
	blockPatterns = append(blockPatterns, cfg.BlockPatterns...)

	compiledBlock := make([]*regexp.Regexp, 0, len(blockPatterns))
	for _, p := range blockPatterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid block regex %q: %w", p, err)
		}
		compiledBlock = append(compiledBlock, re)
	}

	var allowPatterns []string
	if cfg.EnableDefaultAllowPatterns {
		allowPatterns = append(allowPatterns, DefaultAllowPatterns...)
	}
	allowPatterns = append(allowPatterns, cfg.AllowPatterns...)

	compiledAllow := make([]*regexp.Regexp, 0, len(allowPatterns))
	for _, p := range allowPatterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid allow regex %q: %w", p, err)
		}
		compiledAllow = append(compiledAllow, re)
	}

	var ips []net.IP
	var nets []*net.IPNet
	for _, ipStr := range cfg.AllowedIPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", ipStr, err)
			}
			nets = append(nets, ipNet)
		} else {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address %q", ipStr)
			}
			ips = append(ips, ip)
		}
	}

	// Validate status code range if configured
	if cfg.StatusCode != 0 && (cfg.StatusCode < 100 || cfg.StatusCode > 599) {
		return nil, fmt.Errorf("invalid statusCode %d: must be between 100 and 599", cfg.StatusCode)
	}

	// Resolve top-level Mode or Action aliases into cfg.Response.Mode
	if cfg.Response == nil {
		cfg.Response = &ResponseConfig{Mode: "text"}
	}
	if strings.TrimSpace(cfg.Response.Mode) == "" || cfg.Response.Mode == "text" {
		if strings.TrimSpace(cfg.Mode) != "" {
			cfg.Response.Mode = strings.TrimSpace(cfg.Mode)
		} else if strings.TrimSpace(cfg.Action) != "" {
			cfg.Response.Mode = strings.TrimSpace(cfg.Action)
		} else if cfg.SilentDrop {
			cfg.Response.Mode = "silentDrop"
		} else if cfg.Response.Mode == "" {
			cfg.Response.Mode = "text"
		}
	}

	// Validate response configuration
	if cfg.Response != nil {
		if cfg.Response.StatusCode != 0 && (cfg.Response.StatusCode < 100 || cfg.Response.StatusCode > 599) {
			return nil, fmt.Errorf("invalid response.statusCode %d: must be between 100 and 599", cfg.Response.StatusCode)
		}

		if cfg.Response.Mode != "" {
			validModes := map[string]struct{}{
				"text": {}, "json": {}, "html": {}, "captcha": {},
				"redirect": {}, "silentdrop": {}, "drop": {}, "gzipbomb": {},
				"tarpit": {}, "fakesuccess": {}, "ratelimit": {}, "ratelimitchallenge": {},
				"proxy": {}, "infinitestream": {}, "garbagestream": {}, "xml": {},
			}
			if _, ok := validModes[strings.ToLower(cfg.Response.Mode)]; !ok {
				return nil, fmt.Errorf("unsupported response.mode %q", cfg.Response.Mode)
			}

			if strings.EqualFold(cfg.Response.Mode, "redirect") && strings.TrimSpace(cfg.Response.RedirectURL) == "" {
				return nil, fmt.Errorf("redirectUrl is required when response.mode is 'redirect'")
			}

			if strings.EqualFold(cfg.Response.Mode, "proxy") {
				if strings.TrimSpace(cfg.Response.ProxyURL) == "" {
					return nil, fmt.Errorf("proxyUrl is required when response.mode is 'proxy'")
				}
				if _, err := url.ParseRequestURI(cfg.Response.ProxyURL); err != nil {
					return nil, fmt.Errorf("invalid proxyUrl %q: %w", cfg.Response.ProxyURL, err)
				}
			}

			if strings.EqualFold(cfg.Response.Mode, "captcha") && cfg.Response.Captcha != nil {
				if cfg.Response.Captcha.Provider != "" {
					validProviders := map[string]struct{}{
						"turnstile": {}, "hcaptcha": {}, "recaptcha": {}, "custom": {},
					}
					if _, ok := validProviders[strings.ToLower(cfg.Response.Captcha.Provider)]; !ok {
						return nil, fmt.Errorf("unsupported captcha provider %q (must be turnstile, hcaptcha, recaptcha, or custom)", cfg.Response.Captcha.Provider)
					}
				}
			}
		}
	}

	return &Engine{
		Config:       cfg,
		Methods:      methodsMap,
		BlockRegexes: compiledBlock,
		AllowRegexes: compiledAllow,
		AllowedIPs:   ips,
		AllowedNets:  nets,
	}, nil
}

// EvaluationResult represents the inspection outcome of a request.
type EvaluationResult struct {
	Allowed        bool
	Bypassed       bool
	Blocked        bool
	CandidatePaths []string
	MatchedPattern string
	MatchedTarget  string
	Reason         string
}

// Evaluate inspects a simulated request against compiled rules without client IP.
func (e *Engine) Evaluate(method, requestPath, queryString string, headers map[string]string) *EvaluationResult {
	return e.EvaluateWithClientIP(method, requestPath, queryString, headers, "")
}

// EvaluateWithClientIP inspects a simulated request against compiled rules including client IP check.
func (e *Engine) EvaluateWithClientIP(method, requestPath, queryString string, headers map[string]string, clientIPStr string) *EvaluationResult {
	result := &EvaluationResult{
		Allowed:        false,
		Bypassed:       false,
		Blocked:        false,
		CandidatePaths: []string{},
	}

	if !e.Config.Enabled {
		result.Bypassed = true
		result.Reason = "middleware_disabled"
		return result
	}

	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	if _, ok := e.Methods[method]; !ok {
		result.Bypassed = true
		result.Reason = fmt.Sprintf("method_%s_not_inspected", method)
		return result
	}

	// Check client IP whitelist
	if clientIPStr != "" {
		if ip := net.ParseIP(strings.TrimSpace(clientIPStr)); ip != nil {
			for _, allowedIP := range e.AllowedIPs {
				if allowedIP.Equal(ip) {
					result.Allowed = true
					result.Reason = "ip_whitelisted"
					return result
				}
			}
			for _, allowedNet := range e.AllowedNets {
				if allowedNet.Contains(ip) {
					result.Allowed = true
					result.Reason = "ip_whitelisted"
					return result
				}
			}
		}
	}

	candidatePaths := ExtractCandidatePaths("", requestPath, requestPath)
	result.CandidatePaths = candidatePaths

	// Check allow patterns first
	for _, p := range candidatePaths {
		for _, re := range e.AllowRegexes {
			if re.MatchString(p) {
				result.Allowed = true
				result.MatchedPattern = re.String()
				result.MatchedTarget = p
				result.Reason = "path_allowed"
				return result
			}
		}
	}

	// Check block patterns
	for _, p := range candidatePaths {
		for _, re := range e.BlockRegexes {
			if re.MatchString(p) {
				result.Blocked = true
				result.MatchedPattern = re.String()
				result.MatchedTarget = p
				result.Reason = "path_blocked"
				return result
			}
		}
	}

	// Check query string
	if e.Config.CheckQuery && queryString != "" {
		unescapedQuery, err := url.QueryUnescape(queryString)
		if err != nil {
			unescapedQuery = queryString
		}

		queryCandidates := []string{queryString, unescapedQuery}
		if parsed, err := url.ParseQuery(queryString); err == nil {
			for _, vals := range parsed {
				for _, v := range vals {
					queryCandidates = append(queryCandidates, v)
					queryCandidates = append(queryCandidates, ExtractCandidatePaths("", v, v)...)
				}
			}
		}

		for _, q := range queryCandidates {
			for _, re := range e.BlockRegexes {
				if re.MatchString(q) {
					result.Blocked = true
					result.MatchedPattern = re.String()
					result.MatchedTarget = q
					result.Reason = "query_blocked"
					return result
				}
			}
		}
	}

	// Check headers
	if len(e.Config.CheckHeaders) > 0 && headers != nil {
		for _, hdrName := range e.Config.CheckHeaders {
			for k, v := range headers {
				if strings.EqualFold(k, hdrName) && strings.TrimSpace(v) != "" {
					hdrCandidates := ExtractCandidatePaths("", v, v)
					for _, hc := range hdrCandidates {
						for _, re := range e.BlockRegexes {
							if re.MatchString(hc) {
								result.Blocked = true
								result.MatchedPattern = re.String()
								result.MatchedTarget = hc
								result.Reason = "header_blocked"
								return result
							}
						}
					}
				}
			}
		}
	}

	result.Allowed = true
	result.Reason = "passed_inspection"
	return result
}

// Generate converts a Config into target gateway configuration (traefik-yaml, traefik-toml, traefik-labels, caddy, nginx).
func (cfg *Config) Generate(target string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "traefik", "traefik-yaml", "traefik.yaml", "traefik.yml", "traefik-yml", "treafik-yaml":
		return cfg.GenerateTraefikYAML(), nil
	case "traefik-toml", "traefik.toml", "treafik-toml":
		return cfg.GenerateTraefikTOML(), nil
	case "traefik-labels", "traefik_labels", "treafik-labels", "labels":
		return cfg.GenerateTraefikLabels(), nil
	case "caddy", "caddyfile":
		return cfg.GenerateCaddyfile(), nil
	case "nginx", "openresty", "nginx.conf":
		return cfg.GenerateNginxLua(), nil
	default:
		return "", fmt.Errorf("unsupported target: %s (must be 'traefik-yaml', 'traefik-toml', 'traefik-labels', 'caddy', or 'nginx')", target)
	}
}

// ResolveResponse returns a normalized ResponseConfig incorporating top-level mode/action aliases.
func (cfg *Config) ResolveResponse() (string, int, string) {
	mode := "text"
	status := 403
	body := ""

	if cfg.StatusCode != 0 {
		status = cfg.StatusCode
	}
	if cfg.CustomResponseText != "" {
		body = cfg.CustomResponseText
	}

	if cfg.Response != nil {
		if cfg.Response.Mode != "" {
			mode = cfg.Response.Mode
		}
		if cfg.Response.StatusCode != 0 {
			status = cfg.Response.StatusCode
		}
		if cfg.Response.Body != "" {
			body = cfg.Response.Body
		}
	}

	if mode == "text" {
		if strings.TrimSpace(cfg.Mode) != "" {
			mode = strings.TrimSpace(cfg.Mode)
		} else if strings.TrimSpace(cfg.Action) != "" {
			mode = strings.TrimSpace(cfg.Action)
		} else if cfg.SilentDrop {
			mode = "silentDrop"
		}
	}

	return mode, status, body
}

// GenerateTraefikYAML outputs Traefik dynamic YAML middleware configuration.
func (cfg *Config) GenerateTraefikYAML() string {
	var b strings.Builder
	b.WriteString("# Traefik dynamic configuration generated by RouteWarden CLI\n")
	b.WriteString("http:\n")
	b.WriteString("  middlewares:\n")
	b.WriteString("    routewarden:\n")
	b.WriteString("      plugin:\n")
	b.WriteString("        routewarden:\n")
	fmt.Fprintf(&b, "          enabled: %t\n", cfg.Enabled)
	fmt.Fprintf(&b, "          enableDefaultPatterns: %t\n", cfg.EnableDefaultPatterns)
	fmt.Fprintf(&b, "          enableDefaultAllowPatterns: %t\n", cfg.EnableDefaultAllowPatterns)

	allBlocks := append([]string{}, cfg.PathPatterns...)
	allBlocks = append(allBlocks, cfg.BlockPatterns...)
	if len(allBlocks) > 0 {
		b.WriteString("          pathPatterns:\n")
		for _, p := range allBlocks {
			fmt.Fprintf(&b, "            - '%s'\n", strings.ReplaceAll(p, "'", "''"))
		}
	}
	if len(cfg.AllowPatterns) > 0 {
		b.WriteString("          allowPatterns:\n")
		for _, a := range cfg.AllowPatterns {
			fmt.Fprintf(&b, "            - '%s'\n", strings.ReplaceAll(a, "'", "''"))
		}
	}
	if len(cfg.AllowedIPs) > 0 {
		b.WriteString("          allowedIps:\n")
		for _, ip := range cfg.AllowedIPs {
			fmt.Fprintf(&b, "            - '%s'\n", ip)
		}
	}
	if len(cfg.Methods) > 0 {
		b.WriteString("          methods:\n")
		for _, m := range cfg.Methods {
			fmt.Fprintf(&b, "            - '%s'\n", m)
		}
	}
	if cfg.CheckQuery {
		b.WriteString("          checkQuery: true\n")
	}
	if len(cfg.CheckHeaders) > 0 {
		b.WriteString("          checkHeaders:\n")
		for _, h := range cfg.CheckHeaders {
			fmt.Fprintf(&b, "            - '%s'\n", h)
		}
	}

	mode, status, body := cfg.ResolveResponse()
	b.WriteString("          response:\n")
	b.WriteString(fmt.Sprintf("            mode: %s\n", mode))
	b.WriteString(fmt.Sprintf("            statusCode: %d\n", status))
	if body != "" {
		b.WriteString(fmt.Sprintf("            body: %q\n", body))
	}

	return b.String()
}

// GenerateTraefikTOML outputs Traefik dynamic TOML middleware configuration.
func (cfg *Config) GenerateTraefikTOML() string {
	var b strings.Builder
	b.WriteString("# Traefik dynamic TOML configuration generated by RouteWarden CLI\n")
	b.WriteString("[http.middlewares.routewarden.plugin.routewarden]\n")
	fmt.Fprintf(&b, "  enabled = %t\n", cfg.Enabled)
	fmt.Fprintf(&b, "  enableDefaultPatterns = %t\n", cfg.EnableDefaultPatterns)
	fmt.Fprintf(&b, "  enableDefaultAllowPatterns = %t\n", cfg.EnableDefaultAllowPatterns)

	allBlocks := append([]string{}, cfg.PathPatterns...)
	allBlocks = append(allBlocks, cfg.BlockPatterns...)
	if len(allBlocks) > 0 {
		b.WriteString("  pathPatterns = [")
		for i, p := range allBlocks {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", p)
		}
		b.WriteString("]\n")
	}
	if len(cfg.AllowPatterns) > 0 {
		b.WriteString("  allowPatterns = [")
		for i, a := range cfg.AllowPatterns {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", a)
		}
		b.WriteString("]\n")
	}
	if len(cfg.AllowedIPs) > 0 {
		b.WriteString("  allowedIps = [")
		for i, ip := range cfg.AllowedIPs {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", ip)
		}
		b.WriteString("]\n")
	}
	if len(cfg.Methods) > 0 {
		b.WriteString("  methods = [")
		for i, m := range cfg.Methods {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", m)
		}
		b.WriteString("]\n")
	}
	if cfg.CheckQuery {
		b.WriteString("  checkQuery = true\n")
	}
	if len(cfg.CheckHeaders) > 0 {
		b.WriteString("  checkHeaders = [")
		for i, h := range cfg.CheckHeaders {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", h)
		}
		b.WriteString("]\n")
	}

	mode, status, body := cfg.ResolveResponse()
	b.WriteString("\n[http.middlewares.routewarden.plugin.routewarden.response]\n")
	fmt.Fprintf(&b, "  mode = %q\n", mode)
	fmt.Fprintf(&b, "  statusCode = %d\n", status)
	if body != "" {
		fmt.Fprintf(&b, "  body = %q\n", body)
	}

	return b.String()
}

// GenerateTraefikLabels outputs Docker Compose label strings for Traefik.
func (cfg *Config) GenerateTraefikLabels() string {
	var b strings.Builder
	b.WriteString("labels:\n")
	b.WriteString("  - \"traefik.enable=true\"\n")
	b.WriteString("  - \"traefik.http.middlewares.warden.plugin.routewarden.enabled="); fmt.Fprintf(&b, "%t", cfg.Enabled); b.WriteString("\"\n")
	b.WriteString("  - \"traefik.http.middlewares.warden.plugin.routewarden.enableDefaultPatterns="); fmt.Fprintf(&b, "%t", cfg.EnableDefaultPatterns); b.WriteString("\"\n")

	allBlocks := append([]string{}, cfg.PathPatterns...)
	allBlocks = append(allBlocks, cfg.BlockPatterns...)
	if len(allBlocks) > 0 {
		b.WriteString(fmt.Sprintf("  - \"traefik.http.middlewares.warden.plugin.routewarden.pathPatterns=%s\"\n", strings.Join(allBlocks, ",")))
	}
	if len(cfg.AllowPatterns) > 0 {
		b.WriteString(fmt.Sprintf("  - \"traefik.http.middlewares.warden.plugin.routewarden.allowPatterns=%s\"\n", strings.Join(cfg.AllowPatterns, ",")))
	}
	if len(cfg.AllowedIPs) > 0 {
		b.WriteString(fmt.Sprintf("  - \"traefik.http.middlewares.warden.plugin.routewarden.allowedIps=%s\"\n", strings.Join(cfg.AllowedIPs, ",")))
	}
	if len(cfg.Methods) > 0 {
		b.WriteString(fmt.Sprintf("  - \"traefik.http.middlewares.warden.plugin.routewarden.methods=%s\"\n", strings.Join(cfg.Methods, ",")))
	}
	if cfg.CheckQuery {
		b.WriteString("  - \"traefik.http.middlewares.warden.plugin.routewarden.checkQuery=true\"\n")
	}
	if len(cfg.CheckHeaders) > 0 {
		b.WriteString(fmt.Sprintf("  - \"traefik.http.middlewares.warden.plugin.routewarden.checkHeaders=%s\"\n", strings.Join(cfg.CheckHeaders, ",")))
	}

	mode, status, body := cfg.ResolveResponse()
	b.WriteString(fmt.Sprintf("  - \"traefik.http.middlewares.warden.plugin.routewarden.response.mode=%s\"\n", mode))
	b.WriteString(fmt.Sprintf("  - \"traefik.http.middlewares.warden.plugin.routewarden.response.statusCode=%d\"\n", status))
	if body != "" {
		escapedBody := strings.ReplaceAll(body, "\"", "\\\"")
		b.WriteString(fmt.Sprintf("  - \"traefik.http.middlewares.warden.plugin.routewarden.response.body=%s\"\n", escapedBody))
	}
	return b.String()
}

// GenerateCaddyfile outputs Caddyfile directive block.
func (cfg *Config) GenerateCaddyfile() string {
	var b strings.Builder
	b.WriteString("routewarden {\n")
	if !cfg.Enabled {
		b.WriteString("    disable\n")
	}
	if !cfg.EnableDefaultPatterns {
		b.WriteString("    disable_default_patterns\n")
	}
	if !cfg.EnableDefaultAllowPatterns {
		b.WriteString("    disable_default_allow_patterns\n")
	}
	if cfg.CheckQuery {
		b.WriteString("    check_query\n")
	}
	if len(cfg.CheckHeaders) > 0 {
		b.WriteString(fmt.Sprintf("    check_headers %s\n", strings.Join(cfg.CheckHeaders, " ")))
	}
	allBlocks := append([]string{}, cfg.PathPatterns...)
	allBlocks = append(allBlocks, cfg.BlockPatterns...)
	for _, p := range allBlocks {
		b.WriteString(fmt.Sprintf("    block_pattern %q\n", p))
	}
	for _, a := range cfg.AllowPatterns {
		b.WriteString(fmt.Sprintf("    allow_pattern %q\n", a))
	}
	for _, ip := range cfg.AllowedIPs {
		b.WriteString(fmt.Sprintf("    allowed_ip %s\n", ip))
	}
	if len(cfg.Methods) > 0 {
		b.WriteString(fmt.Sprintf("    methods %s\n", strings.Join(cfg.Methods, " ")))
	}
	mode, status, body := cfg.ResolveResponse()
	if mode != "" || status != 403 || body != "" {
		b.WriteString("    response {\n")
		if mode != "" {
			b.WriteString(fmt.Sprintf("        mode %s\n", mode))
		}
		if status != 0 {
			b.WriteString(fmt.Sprintf("        status %d\n", status))
		}
		if body != "" {
			b.WriteString(fmt.Sprintf("        body %q\n", body))
		}
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// GenerateNginxLua outputs OpenResty Lua configuration table.
func (cfg *Config) GenerateNginxLua() string {
	var b strings.Builder
	b.WriteString("-- RouteWarden OpenResty configuration table\n")
	b.WriteString("local routewarden_config = {\n")
	b.WriteString(fmt.Sprintf("    enabled = %t,\n", cfg.Enabled))
	b.WriteString(fmt.Sprintf("    enable_default_patterns = %t,\n", cfg.EnableDefaultPatterns))
	allBlocks := append([]string{}, cfg.PathPatterns...)
	allBlocks = append(allBlocks, cfg.BlockPatterns...)
	if len(allBlocks) > 0 {
		b.WriteString("    block_patterns = {\n")
		for _, p := range allBlocks {
			b.WriteString(fmt.Sprintf("        %q,\n", p))
		}
		b.WriteString("    },\n")
	}
	if len(cfg.AllowPatterns) > 0 {
		b.WriteString("    allow_patterns = {\n")
		for _, a := range cfg.AllowPatterns {
			b.WriteString(fmt.Sprintf("        %q,\n", a))
		}
		b.WriteString("    },\n")
	}
	if len(cfg.AllowedIPs) > 0 {
		b.WriteString("    allowed_ips = {\n")
		for _, ip := range cfg.AllowedIPs {
			b.WriteString(fmt.Sprintf("        %q,\n", ip))
		}
		b.WriteString("    },\n")
	}
	if len(cfg.Methods) > 0 {
		b.WriteString("    methods = {\n")
		for _, m := range cfg.Methods {
			b.WriteString(fmt.Sprintf("        %q,\n", m))
		}
		b.WriteString("    },\n")
	}
	if cfg.CheckQuery {
		b.WriteString("    check_query = true,\n")
	}
	if len(cfg.CheckHeaders) > 0 {
		b.WriteString("    check_headers = {\n")
		for _, h := range cfg.CheckHeaders {
			b.WriteString(fmt.Sprintf("        %q,\n", h))
		}
		b.WriteString("    },\n")
	}
	mode, status, body := cfg.ResolveResponse()
	b.WriteString("    response = {\n")
	if mode != "" {
		b.WriteString(fmt.Sprintf("        mode = %q,\n", mode))
	}
	if status != 0 {
		b.WriteString(fmt.Sprintf("        status_code = %d,\n", status))
	}
	if body != "" {
		b.WriteString(fmt.Sprintf("        body = %q,\n", body))
	}
	b.WriteString("    },\n")
	b.WriteString("}\n")
	return b.String()
}

