package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
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
	GzipBombMB               float64           `json:"gzipBombMB,omitempty"`
	RetryAfterSeconds        int               `json:"retryAfterSeconds,omitempty"`
	TarpitDelayMs            int               `json:"tarpitDelayMs,omitempty"`
	TarpitMaxDurationSeconds int               `json:"tarpitMaxDurationSeconds,omitempty"`
	StreamSizeMB             int               `json:"streamSizeMB,omitempty"`
}

// Config holds the RouteWarden configuration.
type Config struct {
	ConfigFile                 string          `json:"configFile,omitempty"`
	ConfigFileSnake            string          `json:"config_file,omitempty"`
	Enabled                    bool            `json:"enabled,omitempty"`
	EnableDefaultPatterns      bool            `json:"enableDefaultPatterns,omitempty"`
	EnableDefaultAllowPatterns bool            `json:"enableDefaultAllowPatterns,omitempty"`
	BlockPatterns              []string        `json:"blockPatterns,omitempty"`
	AllowPatterns              []string        `json:"allowPatterns,omitempty"`
	AllowedASNs                []string        `json:"allowedASNs,omitempty"`
	ASNDB                      string          `json:"asnDB,omitempty"`
	AllowedIPs                 []string        `json:"allowedIps,omitempty"`
	TrustedProxies             []string        `json:"trustedProxies,omitempty"`
	Methods                    []string        `json:"methods,omitempty"`
	StatusCode                 int             `json:"statusCode,omitempty"`
	CustomResponseText         string          `json:"customResponseText,omitempty"`
	Mode                       string          `json:"mode,omitempty"`
	CheckQuery                 bool            `json:"checkQuery,omitempty"`
	CheckHeaders               []string        `json:"checkHeaders,omitempty"`
	CheckBody                  bool            `json:"checkBody,omitempty"`
	CheckBodyMaxBytes          int64           `json:"checkBodyMaxBytes,omitempty"`
	CheckBodyPatterns          []string        `json:"checkBodyPatterns,omitempty"`
	Debug                      bool            `json:"debug,omitempty"`
	SecurityLog                bool            `json:"securityLog,omitempty"`
	Response                   *ResponseConfig `json:"response,omitempty"`
}

// UnmarshalJSON implements flexible unmarshaling supporting both camelCase and snake_case tags.
func (c *CaptchaConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Provider     string `json:"provider"`
		SiteKey      string `json:"siteKey"`
		SiteKeySnake string `json:"site_key"`
		Title        string `json:"title"`
		Template     string `json:"template"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Provider = raw.Provider
	if raw.SiteKey != "" {
		c.SiteKey = raw.SiteKey
	} else {
		c.SiteKey = raw.SiteKeySnake
	}
	c.Title = raw.Title
	c.Template = raw.Template
	return nil
}

func parseFlexibleFloat(val any) float64 {
	switch v := val.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f
		}
	case string:
		v = strings.TrimSpace(v)
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// UnmarshalJSON implements flexible unmarshaling supporting both camelCase and snake_case tags.
func (r *ResponseConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Mode                          string            `json:"mode"`
		StatusCode                    int               `json:"statusCode"`
		StatusCodeSnake               int               `json:"status_code"`
		ContentType                   string            `json:"contentType"`
		ContentTypeSnake              string            `json:"content_type"`
		Body                          string            `json:"body"`
		Headers                       map[string]string `json:"headers"`
		RedirectURL                   string            `json:"redirectUrl"`
		RedirectURLSnake              string            `json:"redirect_url"`
		ProxyURL                      string            `json:"proxyUrl"`
		ProxyURLSnake                 string            `json:"proxy_url"`
		Captcha                       *CaptchaConfig    `json:"captcha"`
		GzipBombMB                    any               `json:"gzipBombMB"`
		GzipBombMBSnake               any               `json:"gzip_bomb_mb"`
		GzipBombMb                    any               `json:"gzipBombMb"`
		RetryAfterSeconds             int               `json:"retryAfterSeconds"`
		RetryAfterSecondsSnake        int               `json:"retry_after_seconds"`
		TarpitDelayMs                 int               `json:"tarpitDelayMs"`
		TarpitDelayMsSnake            int               `json:"tarpit_delay_ms"`
		TarpitMaxDurationSeconds      int               `json:"tarpitMaxDurationSeconds"`
		TarpitMaxDurationSecondsSnake int               `json:"tarpit_max_duration_seconds"`
		StreamSizeMB                  int               `json:"streamSizeMB"`
		StreamSizeMBSnake             int               `json:"stream_size_mb"`
		StreamSizeMb                  int               `json:"streamSizeMb"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Mode = raw.Mode
	if raw.StatusCode != 0 {
		r.StatusCode = raw.StatusCode
	} else if raw.StatusCodeSnake != 0 {
		r.StatusCode = raw.StatusCodeSnake
	}
	if raw.ContentType != "" {
		r.ContentType = raw.ContentType
	} else {
		r.ContentType = raw.ContentTypeSnake
	}
	r.Body = raw.Body
	r.Headers = raw.Headers
	if raw.RedirectURL != "" {
		r.RedirectURL = raw.RedirectURL
	} else {
		r.RedirectURL = raw.RedirectURLSnake
	}
	if raw.ProxyURL != "" {
		r.ProxyURL = raw.ProxyURL
	} else {
		r.ProxyURL = raw.ProxyURLSnake
	}
	r.Captcha = raw.Captcha
	if val := parseFlexibleFloat(raw.GzipBombMB); val > 0 {
		r.GzipBombMB = val
	} else if val := parseFlexibleFloat(raw.GzipBombMBSnake); val > 0 {
		r.GzipBombMB = val
	} else if val := parseFlexibleFloat(raw.GzipBombMb); val > 0 {
		r.GzipBombMB = val
	}
	if raw.RetryAfterSeconds != 0 {
		r.RetryAfterSeconds = raw.RetryAfterSeconds
	} else if raw.RetryAfterSecondsSnake != 0 {
		r.RetryAfterSeconds = raw.RetryAfterSecondsSnake
	}
	if raw.TarpitDelayMs != 0 {
		r.TarpitDelayMs = raw.TarpitDelayMs
	} else if raw.TarpitDelayMsSnake != 0 {
		r.TarpitDelayMs = raw.TarpitDelayMsSnake
	}
	if raw.TarpitMaxDurationSeconds != 0 {
		r.TarpitMaxDurationSeconds = raw.TarpitMaxDurationSeconds
	} else if raw.TarpitMaxDurationSecondsSnake != 0 {
		r.TarpitMaxDurationSeconds = raw.TarpitMaxDurationSecondsSnake
	}
	if raw.StreamSizeMB != 0 {
		r.StreamSizeMB = raw.StreamSizeMB
	} else if raw.StreamSizeMBSnake != 0 {
		r.StreamSizeMB = raw.StreamSizeMBSnake
	} else if raw.StreamSizeMb != 0 {
		r.StreamSizeMB = raw.StreamSizeMb
	}
	return nil
}

// UnmarshalJSON implements custom JSON unmarshaling to support both camelCase and snake_case tags,
// and ensures proper specification defaults for boolean and scalar fields.
func (cfg *Config) UnmarshalJSON(data []byte) error {
	var raw struct {
		ConfigFile                      string          `json:"configFile"`
		ConfigFileSnake                 string          `json:"config_file"`
		Enabled                         *bool           `json:"enabled"`
		EnableDefaultPatterns           *bool           `json:"enableDefaultPatterns"`
		EnableDefaultPatternsSnake      *bool           `json:"enable_default_patterns"`
		EnableDefaultAllowPatterns      *bool           `json:"enableDefaultAllowPatterns"`
		EnableDefaultAllowPatternsSnake *bool           `json:"enable_default_allow_patterns"`
		BlockPatterns                   []string        `json:"blockPatterns"`
		BlockPatternsSnake              []string        `json:"block_patterns"`
		AllowPatterns                   []string        `json:"allowPatterns"`
		AllowPatternsSnake              []string        `json:"allow_patterns"`
		AllowedASNs                     []string        `json:"allowedASNs"`
		AllowedASNsSnake                []string        `json:"allowed_asns"`
		ASNDB                           string          `json:"asnDB"`
		ASNDBSnake                      string          `json:"asn_db"`
		AllowedIPs                      []string        `json:"allowedIps"`
		AllowedIPsSnake                 []string        `json:"allowed_ips"`
		TrustedProxies                  []string        `json:"trustedProxies"`
		TrustedProxiesSnake             []string        `json:"trusted_proxies"`
		Methods                         []string        `json:"methods"`
		StatusCode                      *int            `json:"statusCode"`
		StatusCodeSnake                 *int            `json:"status_code"`
		CustomResponseText              *string         `json:"customResponseText"`
		CustomResponseTextSnake         *string         `json:"custom_response_text"`
		Mode                            *string         `json:"mode"`
		CheckQuery                      *bool           `json:"checkQuery"`
		CheckQuerySnake                 *bool           `json:"check_query"`
		CheckHeaders                    []string        `json:"checkHeaders"`
		CheckHeadersSnake               []string        `json:"check_headers"`
		CheckBody                       *bool           `json:"checkBody"`
		CheckBodySnake                  *bool           `json:"check_body"`
		CheckBodyMaxBytes               *int64          `json:"checkBodyMaxBytes"`
		CheckBodyMaxBytesSnake          *int64          `json:"check_body_max_bytes"`
		CheckBodyPatterns               []string        `json:"checkBodyPatterns"`
		CheckBodyPatternsSnake          []string        `json:"check_body_patterns"`
		Debug                           *bool           `json:"debug"`
		SecurityLog                     *bool           `json:"securityLog"`
		SecurityLogSnake                *bool           `json:"security_log"`
		Response                        *ResponseConfig `json:"response"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// 1. Config file
	if raw.ConfigFile != "" {
		cfg.ConfigFile = raw.ConfigFile
	}
	if raw.ConfigFileSnake != "" {
		cfg.ConfigFileSnake = raw.ConfigFileSnake
		if cfg.ConfigFile == "" {
			cfg.ConfigFile = raw.ConfigFileSnake
		}
	}

	// 2. Booleans with specification default true
	if raw.Enabled != nil {
		cfg.Enabled = *raw.Enabled
	} else if !cfg.Enabled && raw.ConfigFile == "" && raw.ConfigFileSnake == "" {
		cfg.Enabled = true
	}

	if raw.EnableDefaultPatterns != nil {
		cfg.EnableDefaultPatterns = *raw.EnableDefaultPatterns
	} else if raw.EnableDefaultPatternsSnake != nil {
		cfg.EnableDefaultPatterns = *raw.EnableDefaultPatternsSnake
	} else if !cfg.EnableDefaultPatterns && raw.ConfigFile == "" && raw.ConfigFileSnake == "" {
		cfg.EnableDefaultPatterns = true
	}

	if raw.EnableDefaultAllowPatterns != nil {
		cfg.EnableDefaultAllowPatterns = *raw.EnableDefaultAllowPatterns
	} else if raw.EnableDefaultAllowPatternsSnake != nil {
		cfg.EnableDefaultAllowPatterns = *raw.EnableDefaultAllowPatternsSnake
	} else if !cfg.EnableDefaultAllowPatterns && raw.ConfigFile == "" && raw.ConfigFileSnake == "" {
		cfg.EnableDefaultAllowPatterns = true
	}

	if raw.SecurityLog != nil {
		cfg.SecurityLog = *raw.SecurityLog
	} else if raw.SecurityLogSnake != nil {
		cfg.SecurityLog = *raw.SecurityLogSnake
	} else if !cfg.SecurityLog && raw.ConfigFile == "" && raw.ConfigFileSnake == "" {
		cfg.SecurityLog = true
	}

	// 3. String slices
	if raw.BlockPatterns != nil {
		cfg.BlockPatterns = raw.BlockPatterns
	} else if raw.BlockPatternsSnake != nil {
		cfg.BlockPatterns = raw.BlockPatternsSnake
	} else if cfg.BlockPatterns == nil {
		cfg.BlockPatterns = []string{}
	}

	if raw.AllowPatterns != nil {
		cfg.AllowPatterns = raw.AllowPatterns
	} else if raw.AllowPatternsSnake != nil {
		cfg.AllowPatterns = raw.AllowPatternsSnake
	} else if cfg.AllowPatterns == nil {
		cfg.AllowPatterns = []string{}
	}

	cfg.AllowedASNs = raw.AllowedASNs
	if raw.AllowedASNsSnake != nil {
		cfg.AllowedASNs = raw.AllowedASNsSnake
	}
	cfg.ASNDB = raw.ASNDB
	if raw.ASNDBSnake != "" {
		cfg.ASNDB = raw.ASNDBSnake
	}
	if raw.AllowedIPs != nil {
		cfg.AllowedIPs = raw.AllowedIPs
	} else if raw.AllowedIPsSnake != nil {
		cfg.AllowedIPs = raw.AllowedIPsSnake
	} else if cfg.AllowedIPs == nil {
		cfg.AllowedIPs = []string{}
	}

	if raw.TrustedProxies != nil {
		cfg.TrustedProxies = raw.TrustedProxies
	} else if raw.TrustedProxiesSnake != nil {
		cfg.TrustedProxies = raw.TrustedProxiesSnake
	} else if cfg.TrustedProxies == nil {
		cfg.TrustedProxies = []string{}
	}

	if raw.Methods != nil {
		cfg.Methods = raw.Methods
	} else if len(cfg.Methods) == 0 {
		cfg.Methods = []string{"GET"}
	}

	if raw.CheckHeaders != nil {
		cfg.CheckHeaders = raw.CheckHeaders
	} else if raw.CheckHeadersSnake != nil {
		cfg.CheckHeaders = raw.CheckHeadersSnake
	} else if cfg.CheckHeaders == nil {
		cfg.CheckHeaders = []string{}
	}

	if raw.CheckBodyPatterns != nil {
		cfg.CheckBodyPatterns = raw.CheckBodyPatterns
	} else if raw.CheckBodyPatternsSnake != nil {
		cfg.CheckBodyPatterns = raw.CheckBodyPatternsSnake
	} else if cfg.CheckBodyPatterns == nil {
		cfg.CheckBodyPatterns = []string{}
	}

	// 4. Other scalars
	if raw.StatusCode != nil {
		cfg.StatusCode = *raw.StatusCode
	} else if raw.StatusCodeSnake != nil {
		cfg.StatusCode = *raw.StatusCodeSnake
	} else if cfg.StatusCode == 0 {
		cfg.StatusCode = 403
	}

	if raw.CustomResponseText != nil {
		cfg.CustomResponseText = *raw.CustomResponseText
	} else if raw.CustomResponseTextSnake != nil {
		cfg.CustomResponseText = *raw.CustomResponseTextSnake
	} else if cfg.CustomResponseText == "" {
		cfg.CustomResponseText = "403 Forbidden: Access to sensitive endpoint is blocked"
	}

	if raw.Mode != nil {
		cfg.Mode = *raw.Mode
	} else if cfg.Mode == "" {
		cfg.Mode = "text"
	}

	if raw.CheckQuery != nil {
		cfg.CheckQuery = *raw.CheckQuery
	} else if raw.CheckQuerySnake != nil {
		cfg.CheckQuery = *raw.CheckQuerySnake
	}

	if raw.CheckBody != nil {
		cfg.CheckBody = *raw.CheckBody
	} else if raw.CheckBodySnake != nil {
		cfg.CheckBody = *raw.CheckBodySnake
	}

	if raw.CheckBodyMaxBytes != nil {
		cfg.CheckBodyMaxBytes = *raw.CheckBodyMaxBytes
	} else if raw.CheckBodyMaxBytesSnake != nil {
		cfg.CheckBodyMaxBytes = *raw.CheckBodyMaxBytesSnake
	} else if cfg.CheckBodyMaxBytes == 0 {
		cfg.CheckBodyMaxBytes = 65536
	}

	if raw.Debug != nil {
		cfg.Debug = *raw.Debug
	}

	// 5. Nested response
	if raw.Response != nil {
		cfg.Response = raw.Response
	} else if cfg.Response == nil {
		cfg.Response = &ResponseConfig{Mode: "text"}
	}

	return nil
}

// GetConfigFile returns the configured base config file path (resolving camelCase and snake_case aliases).
func (cfg *Config) GetConfigFile() string {
	if cfg.ConfigFile != "" {
		return cfg.ConfigFile
	}
	return cfg.ConfigFileSnake
}

// CreateConfig creates default RouteWarden configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                    true,
		EnableDefaultPatterns:      true,
		EnableDefaultAllowPatterns: true,
		BlockPatterns:              []string{},
		AllowPatterns:              []string{},
		AllowedIPs:                 []string{},
		TrustedProxies:             []string{},
		Methods:                    []string{"GET"},
		StatusCode:                 403,
		CustomResponseText:         "403 Forbidden: Access to sensitive endpoint is blocked",
		Mode:                       "text",
		CheckQuery:                 false,
		CheckHeaders:               []string{},
		CheckBody:                  false,
		CheckBodyMaxBytes:          65536,
		CheckBodyPatterns:          []string{},
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
	if before, _, found := strings.Cut(rawURIPath, "#"); found {
		rawURIPath = before
	}
	if before, _, found := strings.Cut(rawURIPath, "?"); found {
		rawURIPath = before
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
			for i, seg := range parts {
				if semiIdx := strings.IndexByte(seg, ';'); semiIdx != -1 {
					cleanedSegments[i] = seg[:semiIdx]
				} else {
					cleanedSegments[i] = seg
				}
			}
			matrixStripped := strings.Join(cleanedSegments, "/")
			pathsToCheck = append(pathsToCheck, path.Clean(matrixStripped))

			semiAsSlash := strings.ReplaceAll(p, ";", "/")
			pathsToCheck = append(pathsToCheck, path.Clean(semiAsSlash))
		}
	}

	for _, p := range append([]string{}, pathsToCheck...) {
		if strings.ContainsRune(p, '\x00') {
			pathsToCheck = append(pathsToCheck, path.Clean(strings.ReplaceAll(p, "\x00", "")))
		}
	}

	for _, p := range append([]string{}, pathsToCheck...) {
		if before, _, found := strings.Cut(p, "#"); found {
			pathsToCheck = append(pathsToCheck, path.Clean(before))
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
	ASN              *ASNFilter
	Config           *Config
	Methods          map[string]struct{}
	BlockRegexes     []*regexp.Regexp
	AllowRegexes     []*regexp.Regexp
	BodyRegexes      []*regexp.Regexp
	AllowedIPs       []net.IP
	AllowedNets      []*net.IPNet
	TrustedProxyIPs  []net.IP
	TrustedProxyNets []*net.IPNet
}

// NewEngine validates and compiles a RouteWarden configuration.
func NewEngine(cfg *Config) (*Engine, error) {
	if cfg == nil {
		cfg = CreateConfig()
	}

	if cfg.ConfigFile == "" && cfg.ConfigFileSnake != "" {
		cfg.ConfigFile = cfg.ConfigFileSnake
	}

	if cfg.ConfigFile != "" {
		fileData, err := os.ReadFile(cfg.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read configFile %q: %w", cfg.ConfigFile, err)
		}
		fileCfg := CreateConfig()
		if err := json.Unmarshal(fileData, fileCfg); err != nil {
			return nil, fmt.Errorf("cannot parse configFile %q: %w", cfg.ConfigFile, err)
		}
		filePath := cfg.ConfigFile

		// Apply explicit inline overrides onto fileCfg
		defaultCfg := CreateConfig()
		if cfg.Enabled != defaultCfg.Enabled {
			fileCfg.Enabled = cfg.Enabled
		}
		if cfg.EnableDefaultPatterns != defaultCfg.EnableDefaultPatterns {
			fileCfg.EnableDefaultPatterns = cfg.EnableDefaultPatterns
		}
		if cfg.EnableDefaultAllowPatterns != defaultCfg.EnableDefaultAllowPatterns {
			fileCfg.EnableDefaultAllowPatterns = cfg.EnableDefaultAllowPatterns
		}
		if len(cfg.BlockPatterns) > 0 {
			fileCfg.BlockPatterns = cfg.BlockPatterns
		}
		if len(cfg.AllowPatterns) > 0 {
			fileCfg.AllowPatterns = cfg.AllowPatterns
		}
		if cfg.AllowedASNs != nil {
			fileCfg.AllowedASNs = cfg.AllowedASNs
		}
		if cfg.ASNDB != "" {
			fileCfg.ASNDB = cfg.ASNDB
		}
		if len(cfg.AllowedIPs) > 0 {
			fileCfg.AllowedIPs = cfg.AllowedIPs
		}
		if len(cfg.TrustedProxies) > 0 {
			fileCfg.TrustedProxies = cfg.TrustedProxies
		}
		if len(cfg.Methods) > 0 && !(len(cfg.Methods) == 1 && cfg.Methods[0] == "GET") {
			fileCfg.Methods = cfg.Methods
		}
		if cfg.StatusCode != 0 && cfg.StatusCode != defaultCfg.StatusCode {
			fileCfg.StatusCode = cfg.StatusCode
		}
		if cfg.CustomResponseText != "" && cfg.CustomResponseText != defaultCfg.CustomResponseText {
			fileCfg.CustomResponseText = cfg.CustomResponseText
		}
		if cfg.Mode != "" && cfg.Mode != defaultCfg.Mode {
			fileCfg.Mode = cfg.Mode
		}
		if cfg.CheckQuery != defaultCfg.CheckQuery {
			fileCfg.CheckQuery = cfg.CheckQuery
		}
		if len(cfg.CheckHeaders) > 0 {
			fileCfg.CheckHeaders = cfg.CheckHeaders
		}
		if cfg.CheckBody != defaultCfg.CheckBody {
			fileCfg.CheckBody = cfg.CheckBody
		}
		if cfg.CheckBodyMaxBytes != 0 && cfg.CheckBodyMaxBytes != defaultCfg.CheckBodyMaxBytes {
			fileCfg.CheckBodyMaxBytes = cfg.CheckBodyMaxBytes
		}
		if len(cfg.CheckBodyPatterns) > 0 {
			fileCfg.CheckBodyPatterns = cfg.CheckBodyPatterns
		}
		if cfg.Debug != defaultCfg.Debug {
			fileCfg.Debug = cfg.Debug
		}
		if cfg.SecurityLog != defaultCfg.SecurityLog {
			fileCfg.SecurityLog = cfg.SecurityLog
		}
		if cfg.Response != nil {
			if fileCfg.Response == nil {
				fileCfg.Response = cfg.Response
			} else {
				if cfg.Response.Mode != "" && cfg.Response.Mode != "text" {
					fileCfg.Response.Mode = cfg.Response.Mode
				}
				if cfg.Response.StatusCode != 0 {
					fileCfg.Response.StatusCode = cfg.Response.StatusCode
				}
				if cfg.Response.ContentType != "" {
					fileCfg.Response.ContentType = cfg.Response.ContentType
				}
				if cfg.Response.Body != "" {
					fileCfg.Response.Body = cfg.Response.Body
				}
				if len(cfg.Response.Headers) > 0 {
					fileCfg.Response.Headers = cfg.Response.Headers
				}
				if cfg.Response.RedirectURL != "" {
					fileCfg.Response.RedirectURL = cfg.Response.RedirectURL
				}
				if cfg.Response.ProxyURL != "" {
					fileCfg.Response.ProxyURL = cfg.Response.ProxyURL
				}
				if cfg.Response.Captcha != nil {
					fileCfg.Response.Captcha = cfg.Response.Captcha
				}
				if cfg.Response.GzipBombMB != 0 {
					fileCfg.Response.GzipBombMB = cfg.Response.GzipBombMB
				}
				if cfg.Response.RetryAfterSeconds != 0 {
					fileCfg.Response.RetryAfterSeconds = cfg.Response.RetryAfterSeconds
				}
				if cfg.Response.TarpitDelayMs != 0 {
					fileCfg.Response.TarpitDelayMs = cfg.Response.TarpitDelayMs
				}
				if cfg.Response.TarpitMaxDurationSeconds != 0 {
					fileCfg.Response.TarpitMaxDurationSeconds = cfg.Response.TarpitMaxDurationSeconds
				}
				if cfg.Response.StreamSizeMB != 0 {
					fileCfg.Response.StreamSizeMB = cfg.Response.StreamSizeMB
				}
			}
		}

		fileCfg.ConfigFile = filePath
		cfg = fileCfg
	}

	methodsMap := make(map[string]struct{})
	if len(cfg.Methods) == 0 {
		if cfg.CheckBody || len(cfg.CheckBodyPatterns) > 0 {
			for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
				methodsMap[m] = struct{}{}
			}
		} else {
			methodsMap["GET"] = struct{}{}
		}
	} else if len(cfg.Methods) == 1 && strings.EqualFold(cfg.Methods[0], "GET") && (cfg.CheckBody || len(cfg.CheckBodyPatterns) > 0) {
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			methodsMap[m] = struct{}{}
		}
	} else {
		for _, m := range cfg.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != "" {
				methodsMap[m] = struct{}{}
			}
		}
		if len(methodsMap) == 0 {
			if cfg.CheckBody || len(cfg.CheckBodyPatterns) > 0 {
				for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
					methodsMap[m] = struct{}{}
				}
			} else {
				methodsMap["GET"] = struct{}{}
			}
		}
	}

	var blockPatterns []string
	if cfg.EnableDefaultPatterns {
		blockPatterns = append(blockPatterns, DefaultBlockPatterns...)
	}
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

	compiledBody := make([]*regexp.Regexp, 0, len(cfg.CheckBodyPatterns))
	for _, p := range cfg.CheckBodyPatterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid body regex %q: %w", p, err)
		}
		compiledBody = append(compiledBody, re)
	}

	asn, err := NewASNFilter(cfg.AllowedASNs, cfg.ASNDB)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	var nets []*net.IPNet
	for _, ipStr := range cfg.AllowedIPs {
		ipStr = cleanIP(ipStr)
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

	var proxyIPs []net.IP
	var proxyNets []*net.IPNet
	for _, ipStr := range cfg.TrustedProxies {
		ipStr = cleanIP(ipStr)
		if ipStr == "" {
			continue
		}
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				return nil, fmt.Errorf("invalid trustedProxies CIDR %q: %w", ipStr, err)
			}
			proxyNets = append(proxyNets, ipNet)
		} else {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid trustedProxies IP address %q", ipStr)
			}
			proxyIPs = append(proxyIPs, ip)
		}
	}

	// Validate status code range if configured
	if cfg.StatusCode != 0 && (cfg.StatusCode < 100 || cfg.StatusCode > 599) {
		return nil, fmt.Errorf("invalid statusCode %d: must be between 100 and 599", cfg.StatusCode)
	}

	// Resolve top-level Mode into cfg.Response.Mode
	if cfg.Response == nil {
		cfg.Response = &ResponseConfig{Mode: "text"}
	}
	if strings.TrimSpace(cfg.Response.Mode) == "" || cfg.Response.Mode == "text" {
		if strings.TrimSpace(cfg.Mode) != "" {
			cfg.Response.Mode = strings.TrimSpace(cfg.Mode)
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

			if strings.EqualFold(cfg.Response.Mode, "redirect") {
				trimmedRedirect := strings.TrimSpace(cfg.Response.RedirectURL)
				if trimmedRedirect == "" {
					return nil, fmt.Errorf("redirectUrl is required when response.mode is 'redirect'")
				}
				if strings.HasPrefix(trimmedRedirect, "//") {
					return nil, fmt.Errorf("unsafe redirectUrl %q: protocol-relative URLs (starting with //) are not allowed", cfg.Response.RedirectURL)
				}
				parsedRedirect, err := url.ParseRequestURI(trimmedRedirect)
				if err != nil {
					return nil, fmt.Errorf("invalid redirectUrl %q: %w", cfg.Response.RedirectURL, err)
				}
				if parsedRedirect.Scheme != "" && parsedRedirect.Scheme != "https" && parsedRedirect.Scheme != "http" {
					return nil, fmt.Errorf("unsafe redirectUrl %q: only http/https or relative paths are permitted", cfg.Response.RedirectURL)
				}
			}

			if strings.EqualFold(cfg.Response.Mode, "proxy") {
				if strings.TrimSpace(cfg.Response.ProxyURL) == "" {
					return nil, fmt.Errorf("proxyUrl is required when response.mode is 'proxy'")
				}
				parsedProxy, err := url.ParseRequestURI(cfg.Response.ProxyURL)
				if err != nil {
					return nil, fmt.Errorf("invalid proxyUrl %q: %w", cfg.Response.ProxyURL, err)
				}
				if parsedProxy.Scheme != "http" && parsedProxy.Scheme != "https" {
					return nil, fmt.Errorf("unsafe proxyUrl %q: scheme must be http or https", cfg.Response.ProxyURL)
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
		Config:           cfg,
		Methods:          methodsMap,
		BlockRegexes:     compiledBlock,
		AllowRegexes:     compiledAllow,
		BodyRegexes:      compiledBody,
		ASN:              asn,
		AllowedIPs:       ips,
		AllowedNets:      nets,
		TrustedProxyIPs:  proxyIPs,
		TrustedProxyNets: proxyNets,
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
	return e.EvaluateWithBody(method, requestPath, queryString, headers, "", "")
}

// isTrustedProxy returns true if remoteIP matches any declared trusted proxy IP or CIDR.
// When no trusted proxies are declared, legacy mode applies (returns true).
func (e *Engine) isTrustedProxy(ip net.IP) bool {
	if len(e.TrustedProxyIPs) == 0 && len(e.TrustedProxyNets) == 0 {
		return true
	}
	for _, p := range e.TrustedProxyIPs {
		if p.Equal(ip) {
			return true
		}
	}
	for _, n := range e.TrustedProxyNets {
		if n.Contains(ip) || (ip.To4() != nil && n.Contains(ip.To4())) {
			return true
		}
	}
	return false
}

func cleanIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if slash := strings.IndexByte(raw, '/'); slash != -1 {
		ipPart := cleanIP(raw[:slash])
		maskPart := strings.TrimSpace(raw[slash+1:])
		if ipPart == "" {
			return ""
		}
		return ipPart + "/" + maskPart
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.ReplaceAll(raw, "[", "")
	raw = strings.ReplaceAll(raw, "]", "")
	if idx := strings.IndexByte(raw, '%'); idx != -1 {
		raw = raw[:idx]
	}
	return raw
}

// ExtractClientIP resolves the real client IP respecting trusted proxy configuration.
func (e *Engine) ExtractClientIP(headers map[string]string, remoteAddr string) string {
	remoteIPStr := cleanIP(remoteAddr)
	remoteIP := net.ParseIP(remoteIPStr)

	// If remoteAddr is provided, verify whether it is a declared trusted proxy
	isTrusted := true
	if remoteIP != nil && (len(e.TrustedProxyIPs) > 0 || len(e.TrustedProxyNets) > 0) {
		isTrusted = e.isTrustedProxy(remoteIP)
	}

	if isTrusted && headers != nil {
		for k, v := range headers {
			if strings.EqualFold(k, "X-Forwarded-For") {
				parts := strings.Split(v, ",")
				first := cleanIP(parts[0])
				if net.ParseIP(first) != nil {
					return first
				}
			}
		}
		for k, v := range headers {
			if strings.EqualFold(k, "X-Real-IP") {
				ip := cleanIP(v)
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
	}

	return remoteIPStr
}

// EvaluateWithClientIP inspects a simulated request against compiled rules including client IP check.
func (e *Engine) EvaluateWithClientIP(method, requestPath, queryString string, headers map[string]string, clientIPStr string) *EvaluationResult {
	return e.EvaluateWithBody(method, requestPath, queryString, headers, clientIPStr, "")
}

// EvaluateWithBody inspects a simulated request against compiled rules including client IP and body check.
func (e *Engine) EvaluateWithBody(method, requestPath, queryString string, headers map[string]string, clientIPStr string, body string) *EvaluationResult {
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
	_, hasWildcard := e.Methods["*"]
	_, hasAll := e.Methods["ALL"]
	if _, ok := e.Methods[method]; !ok && !hasWildcard && !hasAll {
		result.Bypassed = true
		result.Reason = fmt.Sprintf("method_%s_not_inspected", method)
		return result
	}

	asnIP := cleanIP(clientIPStr)
	if len(e.TrustedProxyIPs) > 0 || len(e.TrustedProxyNets) > 0 {
		asnIP = e.ExtractClientIP(headers, clientIPStr)
	}
	if e.ASN.IsAllowed(asnIP) {
		result.Allowed = true
		result.Reason = "asn_whitelisted"
		return result
	}

	// Check client IP whitelist
	effectiveIPStr := e.ExtractClientIP(headers, clientIPStr)
	if effectiveIPStr != "" {
		if ip := net.ParseIP(effectiveIPStr); ip != nil {
			for _, allowedIP := range e.AllowedIPs {
				if allowedIP.Equal(ip) {
					result.Allowed = true
					result.Reason = "ip_whitelisted"
					return result
				}
			}
			for _, allowedNet := range e.AllowedNets {
				if allowedNet.Contains(ip) || (ip.To4() != nil && allowedNet.Contains(ip.To4())) {
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
		parsed, _ := url.ParseQuery(queryString)
		for key, vals := range parsed {
			queryCandidates = append(queryCandidates, key)
			queryCandidates = append(queryCandidates, ExtractCandidatePaths("", key, key)...)
			for _, v := range vals {
				queryCandidates = append(queryCandidates, v)
				queryCandidates = append(queryCandidates, ExtractCandidatePaths("", v, v)...)
			}
		}
		// Also split raw query string on '&' and ';' to catch keys/values even when malformed encodings cause ParseQuery to error
		for _, pair := range strings.FieldsFunc(queryString, func(r rune) bool { return r == '&' || r == ';' }) {
			if k, v, ok := strings.Cut(pair, "="); ok {
				queryCandidates = append(queryCandidates, k, v)
				queryCandidates = append(queryCandidates, ExtractCandidatePaths("", k, k)...)
				queryCandidates = append(queryCandidates, ExtractCandidatePaths("", v, v)...)
			} else if pair != "" {
				queryCandidates = append(queryCandidates, pair)
				queryCandidates = append(queryCandidates, ExtractCandidatePaths("", pair, pair)...)
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
					rawVals := []string{v}
					if strings.Contains(v, ",") {
						for _, part := range strings.Split(v, ",") {
							part = strings.TrimSpace(part)
							if part != "" && part != v {
								rawVals = append(rawVals, part)
							}
						}
					}
					for _, val := range rawVals {
						hdrCandidates := append([]string{val}, ExtractCandidatePaths("", val, val)...)
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
	}

	// Check body
	shouldCheckBody := e.Config.CheckBody || len(e.BodyRegexes) > 0
	if shouldCheckBody && body != "" {
		maxBytes := e.Config.CheckBodyMaxBytes
		if maxBytes <= 0 {
			maxBytes = 65536
		}
		bodyBytes := []byte(body)
		if int64(len(bodyBytes)) > maxBytes {
			bodyBytes = bodyBytes[:maxBytes]
		}
		bodyStr := string(bodyBytes)
		unescapedBody, err := url.QueryUnescape(bodyStr)
		if err != nil {
			unescapedBody = bodyStr
		}

		bodyCandidates := []string{bodyStr}
		if unescapedBody != bodyStr {
			bodyCandidates = append(bodyCandidates, unescapedBody)
		}

		patternsToCheck := e.BodyRegexes
		if len(patternsToCheck) == 0 {
			patternsToCheck = e.BlockRegexes
		}

		for _, bCand := range bodyCandidates {
			for _, re := range patternsToCheck {
				if re.MatchString(bCand) {
					result.Blocked = true
					result.MatchedPattern = re.String()
					result.MatchedTarget = "[body payload]"
					result.Reason = "body_blocked"
					return result
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
	case "traefik", "traefik-yaml", "traefik.yaml", "traefik.yml", "traefik-yml", "treafik-yaml", "yaml", "yml":
		return cfg.GenerateTraefikYAML(), nil
	case "traefik-toml", "traefik.toml", "treafik-toml", "toml":
		return cfg.GenerateTraefikTOML(), nil
	case "traefik-labels", "traefik_labels", "treafik-labels", "labels", "compose", "docker-compose":
		return cfg.GenerateTraefikLabels(), nil
	case "caddy", "caddyfile":
		return cfg.GenerateCaddyfile(), nil
	case "nginx", "openresty", "nginx.conf":
		return cfg.GenerateNginxLua(), nil
	case "tcp-warden", "tcp", "tcpwarden", "tcp-warden.yaml", "tcp-warden.yml":
		return cfg.GenerateTCPWardenYAML(), nil
	default:
		return "", fmt.Errorf("unsupported target: %s (must be 'traefik-yaml', 'traefik-toml', 'traefik-labels', 'caddy', 'nginx', or 'tcp-warden')", target)
	}
}

// ResolveResponse returns a normalized ResponseConfig incorporating top-level mode/action aliases.
func (cfg *Config) ResolveResponse() (string, int, string) {
	mode := "text"
	status := 0
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
		}
	}

	// Mode-specific status defaults when not explicitly provided by user
	if (cfg.Response == nil || cfg.Response.StatusCode == 0) && (cfg.StatusCode == 0 || cfg.StatusCode == 403) {
		switch strings.ToLower(mode) {
		case "gzipbomb", "bomb":
			status = 200
		case "fakesuccess", "decoy":
			status = 200
		case "ratelimit", "ratelimitchallenge", "backoff":
			status = 429
		case "redirect":
			status = 302
		default:
			if status == 0 {
				status = 403
			}
		}
	} else if status == 0 {
		status = 403
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
	if cf := cfg.GetConfigFile(); cf != "" {
		fmt.Fprintf(&b, "          configFile: %s\n", cf)
	}
	fmt.Fprintf(&b, "          enabled: %t\n", cfg.Enabled)
	fmt.Fprintf(&b, "          enableDefaultPatterns: %t\n", cfg.EnableDefaultPatterns)
	fmt.Fprintf(&b, "          enableDefaultAllowPatterns: %t\n", cfg.EnableDefaultAllowPatterns)
	if cfg.Debug {
		b.WriteString("          debug: true\n")
	}
	if !cfg.SecurityLog {
		b.WriteString("          securityLog: false\n")
	}

	if len(cfg.BlockPatterns) > 0 {
		b.WriteString("          blockPatterns:\n")
		for _, p := range cfg.BlockPatterns {
			fmt.Fprintf(&b, "            - '%s'\n", strings.ReplaceAll(p, "'", "''"))
		}
	}
	if len(cfg.AllowPatterns) > 0 {
		b.WriteString("          allowPatterns:\n")
		for _, a := range cfg.AllowPatterns {
			fmt.Fprintf(&b, "            - '%s'\n", strings.ReplaceAll(a, "'", "''"))
		}
	}
	if cfg.AllowedASNs != nil {
		if len(cfg.AllowedASNs) == 0 {
			b.WriteString("          allowedASNs: []\n")
		} else {
			b.WriteString("          allowedASNs:\n")
		}
		for _, asn := range cfg.AllowedASNs {
			fmt.Fprintf(&b, "            - %q\n", asn)
		}
	}
	if cfg.ASNDB != "" {
		fmt.Fprintf(&b, "          asnDB: %q\n", cfg.ASNDB)
	}
	if len(cfg.AllowedIPs) > 0 {
		b.WriteString("          allowedIps:\n")
		for _, ip := range cfg.AllowedIPs {
			fmt.Fprintf(&b, "            - '%s'\n", ip)
		}
	}
	if len(cfg.TrustedProxies) > 0 {
		b.WriteString("          trustedProxies:\n")
		for _, proxy := range cfg.TrustedProxies {
			fmt.Fprintf(&b, "            - '%s'\n", proxy)
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
	if cfg.CheckBody {
		b.WriteString("          checkBody: true\n")
	}
	if cfg.CheckBodyMaxBytes > 0 {
		fmt.Fprintf(&b, "          checkBodyMaxBytes: %d\n", cfg.CheckBodyMaxBytes)
	}
	if len(cfg.CheckBodyPatterns) > 0 {
		b.WriteString("          checkBodyPatterns:\n")
		for _, p := range cfg.CheckBodyPatterns {
			fmt.Fprintf(&b, "            - '%s'\n", strings.ReplaceAll(p, "'", "''"))
		}
	}

	mode, status, body := cfg.ResolveResponse()
	b.WriteString("          response:\n")
	fmt.Fprintf(&b, "            mode: %s\n", mode)
	fmt.Fprintf(&b, "            statusCode: %d\n", status)
	if body != "" {
		fmt.Fprintf(&b, "            body: %q\n", body)
	}
	if cfg.Response != nil {
		if cfg.Response.ContentType != "" {
			fmt.Fprintf(&b, "            contentType: %q\n", cfg.Response.ContentType)
		}
		if cfg.Response.RedirectURL != "" {
			fmt.Fprintf(&b, "            redirectUrl: %q\n", cfg.Response.RedirectURL)
		}
		if cfg.Response.ProxyURL != "" {
			fmt.Fprintf(&b, "            proxyUrl: %q\n", cfg.Response.ProxyURL)
		}
		if cfg.Response.GzipBombMB > 0 {
			fmt.Fprintf(&b, "            gzipBombMB: %s\n", formatFloat(cfg.Response.GzipBombMB))
		}
		if cfg.Response.RetryAfterSeconds > 0 {
			fmt.Fprintf(&b, "            retryAfterSeconds: %d\n", cfg.Response.RetryAfterSeconds)
		}
		if cfg.Response.TarpitDelayMs > 0 {
			fmt.Fprintf(&b, "            tarpitDelayMs: %d\n", cfg.Response.TarpitDelayMs)
		}
		if cfg.Response.TarpitMaxDurationSeconds > 0 {
			fmt.Fprintf(&b, "            tarpitMaxDurationSeconds: %d\n", cfg.Response.TarpitMaxDurationSeconds)
		}
		if cfg.Response.StreamSizeMB > 0 {
			fmt.Fprintf(&b, "            streamSizeMB: %d\n", cfg.Response.StreamSizeMB)
		}
		if cfg.Response.Captcha != nil {
			b.WriteString("            captcha:\n")
			if cfg.Response.Captcha.Provider != "" {
				fmt.Fprintf(&b, "              provider: %s\n", cfg.Response.Captcha.Provider)
			}
			if cfg.Response.Captcha.SiteKey != "" {
				fmt.Fprintf(&b, "              siteKey: %q\n", cfg.Response.Captcha.SiteKey)
			}
			if cfg.Response.Captcha.Title != "" {
				fmt.Fprintf(&b, "              title: %q\n", cfg.Response.Captcha.Title)
			}
			if cfg.Response.Captcha.Template != "" {
				fmt.Fprintf(&b, "              template: %q\n", cfg.Response.Captcha.Template)
			}
		}
		if len(cfg.Response.Headers) > 0 {
			b.WriteString("            headers:\n")
			var hKeys []string
			for k := range cfg.Response.Headers {
				hKeys = append(hKeys, k)
			}
			sort.Strings(hKeys)
			for _, k := range hKeys {
				cleanKey := strings.ReplaceAll(strings.ReplaceAll(k, "\r", ""), "\n", "")
				if cleanKey != "" {
					fmt.Fprintf(&b, "              %s: %q\n", cleanKey, cfg.Response.Headers[k])
				}
			}
		}
	}

	return b.String()
}

// GenerateTraefikTOML outputs Traefik dynamic TOML middleware configuration.
func (cfg *Config) GenerateTraefikTOML() string {
	var b strings.Builder
	b.WriteString("# Traefik dynamic TOML configuration generated by RouteWarden CLI\n")
	b.WriteString("[http.middlewares.routewarden.plugin.routewarden]\n")
	if cf := cfg.GetConfigFile(); cf != "" {
		fmt.Fprintf(&b, "  configFile = %q\n", cf)
	}
	fmt.Fprintf(&b, "  enabled = %t\n", cfg.Enabled)
	fmt.Fprintf(&b, "  enableDefaultPatterns = %t\n", cfg.EnableDefaultPatterns)
	fmt.Fprintf(&b, "  enableDefaultAllowPatterns = %t\n", cfg.EnableDefaultAllowPatterns)
	if cfg.Debug {
		b.WriteString("  debug = true\n")
	}
	if !cfg.SecurityLog {
		b.WriteString("  securityLog = false\n")
	}

	if len(cfg.BlockPatterns) > 0 {
		b.WriteString("  blockPatterns = [")
		for i, p := range cfg.BlockPatterns {
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
	if cfg.AllowedASNs != nil {
		b.WriteString("  allowedASNs = [")
		for i, asn := range cfg.AllowedASNs {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", asn)
		}
		b.WriteString("]\n")
	}
	if cfg.ASNDB != "" {
		fmt.Fprintf(&b, "  asnDB = %q\n", cfg.ASNDB)
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
	if len(cfg.TrustedProxies) > 0 {
		b.WriteString("  trustedProxies = [")
		for i, proxy := range cfg.TrustedProxies {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", proxy)
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
	if cfg.CheckBody {
		b.WriteString("  checkBody = true\n")
	}
	if cfg.CheckBodyMaxBytes > 0 {
		fmt.Fprintf(&b, "  checkBodyMaxBytes = %d\n", cfg.CheckBodyMaxBytes)
	}
	if len(cfg.CheckBodyPatterns) > 0 {
		b.WriteString("  checkBodyPatterns = [")
		for i, p := range cfg.CheckBodyPatterns {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", p)
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
	if cfg.Response != nil {
		if cfg.Response.ContentType != "" {
			fmt.Fprintf(&b, "  contentType = %q\n", cfg.Response.ContentType)
		}
		if cfg.Response.RedirectURL != "" {
			fmt.Fprintf(&b, "  redirectUrl = %q\n", cfg.Response.RedirectURL)
		}
		if cfg.Response.ProxyURL != "" {
			fmt.Fprintf(&b, "  proxyUrl = %q\n", cfg.Response.ProxyURL)
		}
		if cfg.Response.GzipBombMB > 0 {
			fmt.Fprintf(&b, "  gzipBombMB = %s\n", formatFloat(cfg.Response.GzipBombMB))
		}
		if cfg.Response.RetryAfterSeconds > 0 {
			fmt.Fprintf(&b, "  retryAfterSeconds = %d\n", cfg.Response.RetryAfterSeconds)
		}
		if cfg.Response.TarpitDelayMs > 0 {
			fmt.Fprintf(&b, "  tarpitDelayMs = %d\n", cfg.Response.TarpitDelayMs)
		}
		if cfg.Response.TarpitMaxDurationSeconds > 0 {
			fmt.Fprintf(&b, "  tarpitMaxDurationSeconds = %d\n", cfg.Response.TarpitMaxDurationSeconds)
		}
		if cfg.Response.StreamSizeMB > 0 {
			fmt.Fprintf(&b, "  streamSizeMB = %d\n", cfg.Response.StreamSizeMB)
		}
		if cfg.Response.Captcha != nil {
			b.WriteString("\n[http.middlewares.routewarden.plugin.routewarden.response.captcha]\n")
			if cfg.Response.Captcha.Provider != "" {
				fmt.Fprintf(&b, "  provider = %q\n", cfg.Response.Captcha.Provider)
			}
			if cfg.Response.Captcha.SiteKey != "" {
				fmt.Fprintf(&b, "  siteKey = %q\n", cfg.Response.Captcha.SiteKey)
			}
			if cfg.Response.Captcha.Title != "" {
				fmt.Fprintf(&b, "  title = %q\n", cfg.Response.Captcha.Title)
			}
			if cfg.Response.Captcha.Template != "" {
				fmt.Fprintf(&b, "  template = %q\n", cfg.Response.Captcha.Template)
			}
		}
		if len(cfg.Response.Headers) > 0 {
			b.WriteString("\n[http.middlewares.routewarden.plugin.routewarden.response.headers]\n")
			var hKeys []string
			for k := range cfg.Response.Headers {
				hKeys = append(hKeys, k)
			}
			sort.Strings(hKeys)
			for _, k := range hKeys {
				cleanKey := strings.ReplaceAll(strings.ReplaceAll(k, "\r", ""), "\n", "")
				cleanKey = strings.TrimSpace(cleanKey)
				cleanVal := strings.ReplaceAll(strings.ReplaceAll(cfg.Response.Headers[k], "\r", ""), "\n", "")
				if cleanKey != "" {
					fmt.Fprintf(&b, "  %s = %q\n", cleanKey, cleanVal)
				}
			}
		}
	}

	return b.String()
}

// GenerateTraefikLabels outputs Docker Compose label strings for Traefik.
func (cfg *Config) GenerateTraefikLabels() string {
	var b strings.Builder
	b.WriteString("labels:\n")
	b.WriteString("  - \"traefik.enable=true\"\n")
	if cf := cfg.GetConfigFile(); cf != "" {
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.configFile=%s\"\n", cf)
	}
	fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.enabled=%t\"\n", cfg.Enabled)
	fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.enableDefaultPatterns=%t\"\n", cfg.EnableDefaultPatterns)
	fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.enableDefaultAllowPatterns=%t\"\n", cfg.EnableDefaultAllowPatterns)
	if cfg.Debug {
		b.WriteString("  - \"traefik.http.middlewares.warden.plugin.routewarden.debug=true\"\n")
	}
	if !cfg.SecurityLog {
		b.WriteString("  - \"traefik.http.middlewares.warden.plugin.routewarden.securityLog=false\"\n")
	}

	if len(cfg.BlockPatterns) > 0 {
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.blockPatterns=%s\"\n", strings.Join(cfg.BlockPatterns, ","))
	}
	if len(cfg.AllowPatterns) > 0 {
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.allowPatterns=%s\"\n", strings.Join(cfg.AllowPatterns, ","))
	}
	if cfg.AllowedASNs != nil {
		fmt.Fprintf(&b, "  - %q\n", "traefik.http.middlewares.warden.plugin.routewarden.allowedASNs="+strings.Join(cfg.AllowedASNs, ","))
	}
	if cfg.ASNDB != "" {
		fmt.Fprintf(&b, "  - %q\n", "traefik.http.middlewares.warden.plugin.routewarden.asnDB="+cfg.ASNDB)
	}
	if len(cfg.AllowedIPs) > 0 {
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.allowedIps=%s\"\n", strings.Join(cfg.AllowedIPs, ","))
	}
	if len(cfg.TrustedProxies) > 0 {
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.trustedProxies=%s\"\n", strings.Join(cfg.TrustedProxies, ","))
	}
	if len(cfg.Methods) > 0 {
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.methods=%s\"\n", strings.Join(cfg.Methods, ","))
	}
	if cfg.CheckQuery {
		b.WriteString("  - \"traefik.http.middlewares.warden.plugin.routewarden.checkQuery=true\"\n")
	}
	if len(cfg.CheckHeaders) > 0 {
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.checkHeaders=%s\"\n", strings.Join(cfg.CheckHeaders, ","))
	}
	if cfg.CheckBody {
		b.WriteString("  - \"traefik.http.middlewares.warden.plugin.routewarden.checkBody=true\"\n")
	}
	if cfg.CheckBodyMaxBytes > 0 {
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.checkBodyMaxBytes=%d\"\n", cfg.CheckBodyMaxBytes)
	}
	if len(cfg.CheckBodyPatterns) > 0 {
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.checkBodyPatterns=%s\"\n", strings.Join(cfg.CheckBodyPatterns, ","))
	}

	mode, status, body := cfg.ResolveResponse()
	fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.mode=%s\"\n", mode)
	fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.statusCode=%d\"\n", status)
	if body != "" {
		escapedBody := strings.ReplaceAll(body, "\\", "\\\\")
		escapedBody = strings.ReplaceAll(escapedBody, "\"", "\\\"")
		escapedBody = strings.ReplaceAll(escapedBody, "\r", "\\r")
		escapedBody = strings.ReplaceAll(escapedBody, "\n", "\\n")
		fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.body=%s\"\n", escapedBody)
	}
	if cfg.Response != nil {
		if cfg.Response.ContentType != "" {
			esc := strings.ReplaceAll(strings.ReplaceAll(cfg.Response.ContentType, "\r", ""), "\n", "")
			fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.contentType=%s\"\n", esc)
		}
		if cfg.Response.RedirectURL != "" {
			esc := strings.ReplaceAll(strings.ReplaceAll(cfg.Response.RedirectURL, "\r", ""), "\n", "")
			fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.redirectUrl=%s\"\n", esc)
		}
		if cfg.Response.ProxyURL != "" {
			esc := strings.ReplaceAll(strings.ReplaceAll(cfg.Response.ProxyURL, "\r", ""), "\n", "")
			fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.proxyUrl=%s\"\n", esc)
		}
		if cfg.Response.GzipBombMB > 0 {
			fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.gzipBombMB=%s\"\n", formatFloat(cfg.Response.GzipBombMB))
		}
		if cfg.Response.RetryAfterSeconds > 0 {
			fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.retryAfterSeconds=%d\"\n", cfg.Response.RetryAfterSeconds)
		}
		if cfg.Response.TarpitDelayMs > 0 {
			fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.tarpitDelayMs=%d\"\n", cfg.Response.TarpitDelayMs)
		}
		if cfg.Response.TarpitMaxDurationSeconds > 0 {
			fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.tarpitMaxDurationSeconds=%d\"\n", cfg.Response.TarpitMaxDurationSeconds)
		}
		if cfg.Response.StreamSizeMB > 0 {
			fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.streamSizeMB=%d\"\n", cfg.Response.StreamSizeMB)
		}
		if cfg.Response.Captcha != nil {
			if cfg.Response.Captcha.Provider != "" {
				fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.captcha.provider=%s\"\n", cfg.Response.Captcha.Provider)
			}
			if cfg.Response.Captcha.SiteKey != "" {
				fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.captcha.siteKey=%s\"\n", cfg.Response.Captcha.SiteKey)
			}
			if cfg.Response.Captcha.Title != "" {
				fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.captcha.title=%s\"\n", cfg.Response.Captcha.Title)
			}
		}
		if len(cfg.Response.Headers) > 0 {
			var hKeys []string
			for k := range cfg.Response.Headers {
				hKeys = append(hKeys, k)
			}
			sort.Strings(hKeys)
			for _, k := range hKeys {
				cleanKey := strings.ReplaceAll(strings.ReplaceAll(k, "\r", ""), "\n", "")
				cleanVal := strings.ReplaceAll(strings.ReplaceAll(cfg.Response.Headers[k], "\r", ""), "\n", "")
				cleanVal = strings.ReplaceAll(cleanVal, "\"", "\\\"")
				if cleanKey != "" {
					fmt.Fprintf(&b, "  - \"traefik.http.middlewares.warden.plugin.routewarden.response.headers.%s=%s\"\n", cleanKey, cleanVal)
				}
			}
		}
	}
	return b.String()
}

// GenerateCaddyfile outputs Caddyfile directive block.
func (cfg *Config) GenerateCaddyfile() string {
	var b strings.Builder
	b.WriteString("routewarden {\n")
	if cf := cfg.GetConfigFile(); cf != "" {
		fmt.Fprintf(&b, "    config_file %s\n", cf)
	}
	if !cfg.Enabled {
		b.WriteString("    enabled false\n")
	}
	if !cfg.EnableDefaultPatterns {
		b.WriteString("    enable_default_patterns false\n")
	}
	if !cfg.EnableDefaultAllowPatterns {
		b.WriteString("    enable_default_allow_patterns false\n")
	}
	if cfg.Debug {
		b.WriteString("    debug\n")
	}
	if !cfg.SecurityLog {
		b.WriteString("    security_log false\n")
	}
	if cfg.CheckQuery {
		b.WriteString("    check_query\n")
	}
	if len(cfg.CheckHeaders) > 0 {
		fmt.Fprintf(&b, "    check_headers %s\n", strings.Join(cfg.CheckHeaders, " "))
	}
	if cfg.CheckBody {
		b.WriteString("    check_body\n")
	}
	if cfg.CheckBodyMaxBytes > 0 {
		fmt.Fprintf(&b, "    check_body_max_bytes %d\n", cfg.CheckBodyMaxBytes)
	}
	for _, p := range cfg.CheckBodyPatterns {
		fmt.Fprintf(&b, "    check_body_patterns %q\n", p)
	}
	for _, p := range cfg.BlockPatterns {
		fmt.Fprintf(&b, "    block_patterns %q\n", p)
	}
	for _, a := range cfg.AllowPatterns {
		fmt.Fprintf(&b, "    allow_patterns %q\n", a)
	}
	if cfg.AllowedASNs != nil {
		fmt.Fprintf(&b, "    allowed_asns %s\n", strings.Join(cfg.AllowedASNs, " "))
	}
	if cfg.ASNDB != "" {
		fmt.Fprintf(&b, "    asn_db %q\n", cfg.ASNDB)
	}
	for _, ip := range cfg.AllowedIPs {
		fmt.Fprintf(&b, "    allowed_ips %s\n", ip)
	}
	for _, proxy := range cfg.TrustedProxies {
		fmt.Fprintf(&b, "    trusted_proxies %s\n", proxy)
	}
	if len(cfg.Methods) > 0 {
		fmt.Fprintf(&b, "    methods %s\n", strings.Join(cfg.Methods, " "))
	}
	mode, status, body := cfg.ResolveResponse()
	hasExtended := false
	if cfg.Response != nil {
		hasExtended = cfg.Response.ContentType != "" || cfg.Response.RedirectURL != "" || cfg.Response.ProxyURL != "" ||
			cfg.Response.GzipBombMB > 0 || cfg.Response.RetryAfterSeconds > 0 || cfg.Response.TarpitDelayMs > 0 ||
			cfg.Response.TarpitMaxDurationSeconds > 0 || cfg.Response.StreamSizeMB > 0 || cfg.Response.Captcha != nil || len(cfg.Response.Headers) > 0
	}
	if mode != "" || status != 403 || body != "" || hasExtended {
		b.WriteString("    response {\n")
		if mode != "" {
			fmt.Fprintf(&b, "        mode %s\n", mode)
		}
		if status != 0 {
			fmt.Fprintf(&b, "        status_code %d\n", status)
		}
		if body != "" {
			fmt.Fprintf(&b, "        body %q\n", body)
		}
		if cfg.Response != nil {
			if cfg.Response.ContentType != "" {
				fmt.Fprintf(&b, "        content_type %q\n", cfg.Response.ContentType)
			}
			if cfg.Response.RedirectURL != "" {
				fmt.Fprintf(&b, "        redirect_url %q\n", cfg.Response.RedirectURL)
			}
			if cfg.Response.ProxyURL != "" {
				fmt.Fprintf(&b, "        proxy_url %q\n", cfg.Response.ProxyURL)
			}
			if cfg.Response.GzipBombMB > 0 {
				fmt.Fprintf(&b, "        gzip_bomb_mb %s\n", formatFloat(cfg.Response.GzipBombMB))
			}
			if cfg.Response.RetryAfterSeconds > 0 {
				fmt.Fprintf(&b, "        retry_after_seconds %d\n", cfg.Response.RetryAfterSeconds)
			}
			if cfg.Response.TarpitDelayMs > 0 {
				fmt.Fprintf(&b, "        tarpit_delay_ms %d\n", cfg.Response.TarpitDelayMs)
			}
			if cfg.Response.TarpitMaxDurationSeconds > 0 {
				fmt.Fprintf(&b, "        tarpit_max_duration_seconds %d\n", cfg.Response.TarpitMaxDurationSeconds)
			}
			if cfg.Response.StreamSizeMB > 0 {
				fmt.Fprintf(&b, "        stream_size_mb %d\n", cfg.Response.StreamSizeMB)
			}
			if cfg.Response.Captcha != nil {
				if cfg.Response.Captcha.Title != "" {
					fmt.Fprintf(&b, "        captcha %s %s %q\n", cfg.Response.Captcha.Provider, cfg.Response.Captcha.SiteKey, cfg.Response.Captcha.Title)
				} else if cfg.Response.Captcha.Provider != "" || cfg.Response.Captcha.SiteKey != "" {
					fmt.Fprintf(&b, "        captcha %s %s\n", cfg.Response.Captcha.Provider, cfg.Response.Captcha.SiteKey)
				}
			}
			if len(cfg.Response.Headers) > 0 {
				var hKeys []string
				for k := range cfg.Response.Headers {
					hKeys = append(hKeys, k)
				}
				sort.Strings(hKeys)
				for _, k := range hKeys {
					cleanKey := strings.ReplaceAll(strings.ReplaceAll(k, "\r", ""), "\n", "")
					if cleanKey != "" {
						fmt.Fprintf(&b, "        header %s %q\n", cleanKey, cfg.Response.Headers[k])
					}
				}
			}
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
	if cf := cfg.GetConfigFile(); cf != "" {
		fmt.Fprintf(&b, "    config_file = %q,\n", cf)
	}
	fmt.Fprintf(&b, "    enabled = %t,\n", cfg.Enabled)
	fmt.Fprintf(&b, "    enable_default_patterns = %t,\n", cfg.EnableDefaultPatterns)
	fmt.Fprintf(&b, "    enable_default_allow_patterns = %t,\n", cfg.EnableDefaultAllowPatterns)
	if cfg.Debug {
		b.WriteString("    debug = true,\n")
	}
	if !cfg.SecurityLog {
		b.WriteString("    security_log = false,\n")
	}
	if len(cfg.BlockPatterns) > 0 {
		b.WriteString("    block_patterns = {\n")
		for _, p := range cfg.BlockPatterns {
			fmt.Fprintf(&b, "        %q,\n", p)
		}
		b.WriteString("    },\n")
	}
	if len(cfg.AllowPatterns) > 0 {
		b.WriteString("    allow_patterns = {\n")
		for _, a := range cfg.AllowPatterns {
			fmt.Fprintf(&b, "        %q,\n", a)
		}
		b.WriteString("    },\n")
	}
	if cfg.AllowedASNs != nil {
		b.WriteString("    allowed_asns = { ")
		for _, asn := range cfg.AllowedASNs {
			fmt.Fprintf(&b, "%q, ", asn)
		}
		b.WriteString("},\n")
	}
	if cfg.ASNDB != "" {
		fmt.Fprintf(&b, "    asn_db = %q,\n", cfg.ASNDB)
	}
	if len(cfg.AllowedIPs) > 0 {
		b.WriteString("    allowed_ips = {\n")
		for _, ip := range cfg.AllowedIPs {
			fmt.Fprintf(&b, "        %q,\n", ip)
		}
		b.WriteString("    },\n")
	}
	if len(cfg.TrustedProxies) > 0 {
		b.WriteString("    trusted_proxies = {\n")
		for _, proxy := range cfg.TrustedProxies {
			fmt.Fprintf(&b, "        %q,\n", proxy)
		}
		b.WriteString("    },\n")
	}
	if len(cfg.Methods) > 0 {
		b.WriteString("    methods = {\n")
		for _, m := range cfg.Methods {
			fmt.Fprintf(&b, "        %q,\n", m)
		}
		b.WriteString("    },\n")
	}
	if cfg.CheckQuery {
		b.WriteString("    check_query = true,\n")
	}
	if len(cfg.CheckHeaders) > 0 {
		b.WriteString("    check_headers = {\n")
		for _, h := range cfg.CheckHeaders {
			fmt.Fprintf(&b, "        %q,\n", h)
		}
		b.WriteString("    },\n")
	}
	if cfg.CheckBody {
		b.WriteString("    check_body = true,\n")
	}
	if cfg.CheckBodyMaxBytes > 0 {
		fmt.Fprintf(&b, "    check_body_max_bytes = %d,\n", cfg.CheckBodyMaxBytes)
	}
	if len(cfg.CheckBodyPatterns) > 0 {
		b.WriteString("    check_body_patterns = {\n")
		for _, p := range cfg.CheckBodyPatterns {
			fmt.Fprintf(&b, "        %q,\n", p)
		}
		b.WriteString("    },\n")
	}
	mode, status, body := cfg.ResolveResponse()
	b.WriteString("    response = {\n")
	if mode != "" {
		fmt.Fprintf(&b, "        mode = %q,\n", mode)
	}
	if status != 0 {
		fmt.Fprintf(&b, "        status_code = %d,\n", status)
	}
	if body != "" {
		fmt.Fprintf(&b, "        body = %q,\n", body)
	}
	if cfg.Response != nil {
		if cfg.Response.ContentType != "" {
			fmt.Fprintf(&b, "        content_type = %q,\n", cfg.Response.ContentType)
		}
		if cfg.Response.RedirectURL != "" {
			fmt.Fprintf(&b, "        redirect_url = %q,\n", cfg.Response.RedirectURL)
		}
		if cfg.Response.ProxyURL != "" {
			fmt.Fprintf(&b, "        proxy_url = %q,\n", cfg.Response.ProxyURL)
		}
		if cfg.Response.GzipBombMB > 0 {
			fmt.Fprintf(&b, "        gzip_bomb_mb = %s,\n", formatFloat(cfg.Response.GzipBombMB))
		}
		if cfg.Response.RetryAfterSeconds > 0 {
			fmt.Fprintf(&b, "        retry_after_seconds = %d,\n", cfg.Response.RetryAfterSeconds)
		}
		if cfg.Response.TarpitDelayMs > 0 {
			fmt.Fprintf(&b, "        tarpit_delay_ms = %d,\n", cfg.Response.TarpitDelayMs)
		}
		if cfg.Response.TarpitMaxDurationSeconds > 0 {
			fmt.Fprintf(&b, "        tarpit_max_duration_seconds = %d,\n", cfg.Response.TarpitMaxDurationSeconds)
		}
		if cfg.Response.StreamSizeMB > 0 {
			fmt.Fprintf(&b, "        stream_size_mb = %d,\n", cfg.Response.StreamSizeMB)
		}
		if cfg.Response.Captcha != nil {
			b.WriteString("        captcha = {\n")
			if cfg.Response.Captcha.Provider != "" {
				fmt.Fprintf(&b, "            provider = %q,\n", cfg.Response.Captcha.Provider)
			}
			if cfg.Response.Captcha.SiteKey != "" {
				fmt.Fprintf(&b, "            site_key = %q,\n", cfg.Response.Captcha.SiteKey)
			}
			if cfg.Response.Captcha.Title != "" {
				fmt.Fprintf(&b, "            title = %q,\n", cfg.Response.Captcha.Title)
			}
			if cfg.Response.Captcha.Template != "" {
				fmt.Fprintf(&b, "            template = %q,\n", cfg.Response.Captcha.Template)
			}
			b.WriteString("        },\n")
		}
		if len(cfg.Response.Headers) > 0 {
			b.WriteString("        headers = {\n")
			var hKeys []string
			for k := range cfg.Response.Headers {
				hKeys = append(hKeys, k)
			}
			sort.Strings(hKeys)
			for _, k := range hKeys {
				cleanKey := strings.ReplaceAll(strings.ReplaceAll(k, "\r", ""), "\n", "")
				cleanVal := strings.ReplaceAll(strings.ReplaceAll(cfg.Response.Headers[k], "\r", ""), "\n", "")
				if cleanKey != "" {
					fmt.Fprintf(&b, "            [%q] = %q,\n", cleanKey, cleanVal)
				}
			}
			b.WriteString("        },\n")
		}
	}
	b.WriteString("    },\n")
	b.WriteString("}\n")
	return b.String()
}

// GenerateTCPWardenYAML outputs tcp-warden.yaml configuration.
func (cfg *Config) GenerateTCPWardenYAML() string {
	var b strings.Builder
	b.WriteString("# RouteWarden TCP Warden Configuration\n")
	b.WriteString("# Generated by rwarden generate tcp-warden\n\n")
	b.WriteString("version: \"1.0\"\n\n")
	b.WriteString("global:\n")
	b.WriteString("  max_connections: 10000\n")
	b.WriteString("  ban_duration: \"1h\"\n")
	b.WriteString("  ban_after_failures: 5\n")
	b.WriteString("  tarpit_ms: 1000\n")
	b.WriteString("  log_file: \"/var/log/routewarden/tcp-warden.jsonl\"\n")
	if cfg.AllowedASNs != nil {
		if len(cfg.AllowedASNs) == 0 {
			b.WriteString("  allowed_asns: []\n")
		} else {
			b.WriteString("  allowed_asns:\n")
		}
		for _, asn := range cfg.AllowedASNs {
			fmt.Fprintf(&b, "    - %q\n", asn)
		}
	}
	if cfg.ASNDB != "" {
		fmt.Fprintf(&b, "  asn_db: %q\n", cfg.ASNDB)
	}
	b.WriteString("  ip_filter:\n")
	if len(cfg.AllowedIPs) > 0 {
		b.WriteString("    allow:\n")
		for _, ip := range cfg.AllowedIPs {
			fmt.Fprintf(&b, "      - \"%s\"\n", ip)
		}
	} else {
		b.WriteString("    allow: []\n")
	}
	b.WriteString("    deny: []\n\n")
	b.WriteString("api:\n")
	b.WriteString("  enabled: true\n")
	b.WriteString("  listen: \"127.0.0.1:9091\"\n\n")
	b.WriteString("crowdsec:\n")
	b.WriteString("  enabled: false\n")
	b.WriteString("  lapi_url: \"http://127.0.0.1:8080\"\n")
	b.WriteString("  api_key: \"${CROWDSEC_API_KEY}\"\n")
	b.WriteString("  update_frequency: \"10s\"\n\n")
	b.WriteString("services:\n")
	b.WriteString("  ssh:\n")
	b.WriteString("    listen: \":2222\"\n")
	b.WriteString("    upstream: \"127.0.0.1:22\"\n")
	b.WriteString("    protocol: \"ssh\"\n")
	b.WriteString("    rate_limit:\n")
	b.WriteString("      connections_per_minute: 20\n")
	b.WriteString("      burst: 5\n")
	b.WriteString("    max_auth_failures: 3\n")
	b.WriteString("    ban_after_failures: 3\n")
	b.WriteString("    ban_duration: \"2h\"\n")
	b.WriteString("    ssh:\n")
	b.WriteString("      banner: \"RouteWarden SSH Warden\"\n\n")
	b.WriteString("  smtp:\n")
	b.WriteString("    listen: \":2525\"\n")
	b.WriteString("    upstream: \"127.0.0.1:25\"\n")
	b.WriteString("    protocol: \"smtp\"\n")
	b.WriteString("    rate_limit:\n")
	b.WriteString("      connections_per_minute: 30\n")
	b.WriteString("      burst: 10\n")
	b.WriteString("    smtp:\n")
	b.WriteString("      max_recipients: 10\n")
	b.WriteString("      blocked_sender_domains:\n")
	b.WriteString("        - \"*.tempmail.com\"\n")
	b.WriteString("        - \"spam.org\"\n")
	return b.String()
}
