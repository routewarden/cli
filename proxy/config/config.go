package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/routewarden/cli/proxy/plugins"
	_ "github.com/routewarden/cli/proxy/plugins/all"
	"github.com/routewarden/cli/proxy/plugins/sdk"
)

// Duration is a wrapper around time.Duration that supports YAML unmarshalling
// from string formats ("1h", "30m", "15s") or integer seconds (3600).
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		if sec, err := strconv.Atoi(s); err == nil {
			*d = Duration(time.Duration(sec) * time.Second)
			return nil
		}
		if strings.HasSuffix(s, "d") {
			daysStr := strings.TrimSuffix(s, "d")
			if days, err := strconv.Atoi(daysStr); err == nil && days > 0 {
				*d = Duration(time.Duration(days) * 24 * time.Hour)
				return nil
			}
			if daysF, err := strconv.ParseFloat(daysStr, 64); err == nil && daysF > 0 {
				*d = Duration(time.Duration(daysF * 24 * float64(time.Hour)))
				return nil
			}
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}

	var sec int
	if err := value.Decode(&sec); err == nil {
		*d = Duration(time.Duration(sec) * time.Second)
		return nil
	}

	return fmt.Errorf("duration must be a string (e.g. '1h', '30s') or integer seconds")
}

func (d Duration) Duration() time.Duration {
	if time.Duration(d) == 0 {
		return 0
	}
	return time.Duration(d)
}

func (d Duration) Seconds() int {
	return int(time.Duration(d).Seconds())
}

// Config represents the root configuration of tcp-warden.
type Config struct {
	Version  string                   `yaml:"version"`
	Global   GlobalConfig             `yaml:"global"`
	Plugins  PluginsConfig            `yaml:"plugins"`
	API      APIConfig                `yaml:"api"`
	CrowdSec CrowdSecConfig           `yaml:"crowdsec"`
	Services map[string]ServiceConfig `yaml:"services"`
	Warnings []string                 `yaml:"-"`
}

// PluginsConfig manages enablement and configuration of modular plugins.
type PluginsConfig struct {
	Enabled  []string                     `yaml:"enabled"`
	Disabled []string                     `yaml:"disabled"`
	Entries  map[string]PluginStateConfig `yaml:"-"`
}

// PluginStateConfig defines enablement and options for an individual plugin.
type PluginStateConfig struct {
	Name    string         `yaml:"name,omitempty"`
	Enabled *bool          `yaml:"enabled"`
	Source  string         `yaml:"source,omitempty"`
	Version string         `yaml:"version,omitempty"`
	Config  map[string]any `yaml:"config,omitempty"`
}

func (p *PluginsConfig) UnmarshalYAML(value *yaml.Node) error {
	// 1. Try simple list of strings: ["postgres", "redis"]
	var list []string
	if err := value.Decode(&list); err == nil {
		p.Enabled = list
		return nil
	}

	// 2. Try list of plugin objects: [{name: postgres, enabled: true, source: ...}]
	var listNodes []yaml.Node
	if err := value.Decode(&listNodes); err == nil && len(listNodes) > 0 {
		p.Entries = make(map[string]PluginStateConfig)
		for _, itemNode := range listNodes {
			if itemNode.Kind == yaml.ScalarNode {
				p.Enabled = append(p.Enabled, itemNode.Value)
			} else if itemNode.Kind == yaml.MappingNode {
				var itemMap map[string]any
				if err := itemNode.Decode(&itemMap); err == nil {
					name, _ := itemMap["name"].(string)
					if name != "" {
						var state PluginStateConfig
						state.Name = name
						if en, ok := itemMap["enabled"].(bool); ok {
							state.Enabled = &en
							if en {
								p.Enabled = append(p.Enabled, name)
							} else {
								p.Disabled = append(p.Disabled, name)
							}
						}
						if src, ok := itemMap["source"].(string); ok {
							state.Source = src
						} else if src, ok := itemMap["install"].(string); ok {
							state.Source = src
						}
						if ver, ok := itemMap["version"].(string); ok {
							state.Version = ver
						}
						p.Entries[name] = state
					}
				}
			}
		}
		return nil
	}

	// 3. Try map format: {postgres: {enabled: true, source: ...}, mysql: ...}
	var m map[string]any
	if err := value.Decode(&m); err == nil {
		p.Entries = make(map[string]PluginStateConfig)
		for k, v := range m {
			if strings.EqualFold(k, "enabled") {
				if items, ok := v.([]any); ok {
					for _, item := range items {
						if s, ok := item.(string); ok {
							p.Enabled = append(p.Enabled, s)
						}
					}
				}
				continue
			}
			if strings.EqualFold(k, "disabled") {
				if items, ok := v.([]any); ok {
					for _, item := range items {
						if s, ok := item.(string); ok {
							p.Disabled = append(p.Disabled, s)
						}
					}
				}
				continue
			}

			if sub, ok := v.(map[string]any); ok {
				var state PluginStateConfig
				state.Name = k
				if en, ok := sub["enabled"].(bool); ok {
					state.Enabled = &en
					if en {
						p.Enabled = append(p.Enabled, k)
					} else {
						p.Disabled = append(p.Disabled, k)
					}
				}
				if src, ok := sub["source"].(string); ok {
					state.Source = src
				} else if src, ok := sub["install"].(string); ok {
					state.Source = src
				} else if src, ok := sub["repo"].(string); ok {
					state.Source = src
				}
				if ver, ok := sub["version"].(string); ok {
					state.Version = ver
				}
				if cfg, ok := sub["config"].(map[string]any); ok {
					state.Config = cfg
				}
				p.Entries[k] = state
			} else if en, ok := v.(bool); ok {
				state := PluginStateConfig{Name: k, Enabled: &en}
				if en {
					p.Enabled = append(p.Enabled, k)
				} else {
					p.Disabled = append(p.Disabled, k)
				}
				p.Entries[k] = state
			}
		}
		return nil
	}

	return nil
}

// UpdatePluginEnablement modifies the given YAML configuration file to set a plugin's
// enabled state to true or false. It preserves existing comments and formatting by modifying
// the yaml.Node abstract syntax tree directly.
func UpdatePluginEnablement(configPath string, pluginName string, enabled bool) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config file %s: %w", configPath, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parsing YAML from %s: %w", configPath, err)
	}

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return fmt.Errorf("invalid YAML document in %s", configPath)
	}

	topMap := root.Content[0]
	if topMap.Kind != yaml.MappingNode {
		return fmt.Errorf("expected root mapping in %s", configPath)
	}

	pluginNameLower := strings.ToLower(pluginName)
	var pluginsValNode *yaml.Node

	for i := 0; i < len(topMap.Content); i += 2 {
		if strings.EqualFold(topMap.Content[i].Value, "plugins") {
			pluginsValNode = topMap.Content[i+1]
			break
		}
	}

	boolStr := "false"
	if enabled {
		boolStr = "true"
	}

	if pluginsValNode == nil {
		// Create 'plugins' section
		keyNode := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: "plugins",
		}
		newPluginsMap := &yaml.Node{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}
		topMap.Content = append(topMap.Content, keyNode, newPluginsMap)
		pluginsValNode = newPluginsMap
	}

	if pluginsValNode.Kind == yaml.MappingNode {
		pluginsValNode.Style = 0 // format as block-style multiline mapping
		var targetPluginNode *yaml.Node
		for i := 0; i < len(pluginsValNode.Content); i += 2 {
			if strings.EqualFold(pluginsValNode.Content[i].Value, pluginNameLower) {
				targetPluginNode = pluginsValNode.Content[i+1]
				break
			}
		}

		if targetPluginNode == nil {
			// Add new plugin entry
			pKey := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: pluginNameLower,
			}
			pMap := &yaml.Node{
				Kind: yaml.MappingNode,
				Tag:  "!!map",
				Content: []*yaml.Node{
					{
						Kind:  yaml.ScalarNode,
						Tag:   "!!str",
						Value: "enabled",
					},
					{
						Kind:  yaml.ScalarNode,
						Tag:   "!!bool",
						Value: boolStr,
					},
				},
			}
			pluginsValNode.Content = append(pluginsValNode.Content, pKey, pMap)
		} else if targetPluginNode.Kind == yaml.MappingNode {
			foundEnabled := false
			for j := 0; j < len(targetPluginNode.Content); j += 2 {
				if strings.EqualFold(targetPluginNode.Content[j].Value, "enabled") {
					targetPluginNode.Content[j+1].Value = boolStr
					targetPluginNode.Content[j+1].Tag = "!!bool"
					foundEnabled = true
					break
				}
			}
			if !foundEnabled {
				targetPluginNode.Content = append(targetPluginNode.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "enabled"},
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: boolStr},
				)
			}
		} else if targetPluginNode.Kind == yaml.ScalarNode {
			targetPluginNode.Value = boolStr
			targetPluginNode.Tag = "!!bool"
		}

		// Prune conflicting plugin entries from any child "disabled" or "enabled" lists
		for i := 0; i < len(pluginsValNode.Content); i += 2 {
			k := strings.ToLower(pluginsValNode.Content[i].Value)
			val := pluginsValNode.Content[i+1]
			if k == "disabled" && val.Kind == yaml.SequenceNode && enabled {
				var pruned []*yaml.Node
				for _, item := range val.Content {
					if !strings.EqualFold(item.Value, pluginNameLower) {
						pruned = append(pruned, item)
					}
				}
				val.Content = pruned
			} else if k == "enabled" && val.Kind == yaml.SequenceNode && !enabled {
				var pruned []*yaml.Node
				for _, item := range val.Content {
					if !strings.EqualFold(item.Value, pluginNameLower) {
						pruned = append(pruned, item)
					}
				}
				val.Content = pruned
			}
		}
	} else if pluginsValNode.Kind == yaml.SequenceNode {
		// List format
		var newSeq []*yaml.Node
		for _, item := range pluginsValNode.Content {
			if item.Kind == yaml.ScalarNode {
				if !strings.EqualFold(item.Value, pluginNameLower) {
					newSeq = append(newSeq, item)
				}
			} else {
				newSeq = append(newSeq, item)
			}
		}
		if enabled {
			newSeq = append(newSeq, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: pluginNameLower,
			})
		}
		pluginsValNode.Content = newSeq
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return fmt.Errorf("encoding updated YAML: %w", err)
	}
	_ = enc.Close()

	perm := os.FileMode(0644)
	if fi, err := os.Stat(configPath); err == nil {
		perm = fi.Mode().Perm()
	}

	if err := os.WriteFile(configPath, buf.Bytes(), perm); err != nil {
		return fmt.Errorf("writing updated config to %s: %w", configPath, err)
	}

	return nil
}

// AddDefaultPluginService adds a default service entry to the given YAML configuration file
// if a service for that protocol or name does not already exist.
// Returns (added bool, serviceName string, err error).
func AddDefaultPluginService(configPath string, pluginName string, defSvc *sdk.DefaultServiceConfig) (bool, string, error) {
	if defSvc == nil {
		defSvc = plugins.GetDefaultServiceForPlugin(pluginName, nil, nil)
	}
	if defSvc == nil {
		return false, "", nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, "", fmt.Errorf("reading config file %s: %w", configPath, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false, "", fmt.Errorf("parsing YAML from %s: %w", configPath, err)
	}

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return false, "", fmt.Errorf("invalid YAML document in %s", configPath)
	}

	topMap := root.Content[0]
	if topMap.Kind != yaml.MappingNode {
		return false, "", fmt.Errorf("expected root mapping in %s", configPath)
	}

	var servicesValNode *yaml.Node
	for i := 0; i < len(topMap.Content); i += 2 {
		if strings.EqualFold(topMap.Content[i].Value, "services") {
			servicesValNode = topMap.Content[i+1]
			break
		}
	}

	if servicesValNode == nil {
		keyNode := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: "services",
		}
		newServicesMap := &yaml.Node{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}
		topMap.Content = append(topMap.Content, keyNode, newServicesMap)
		servicesValNode = newServicesMap
	}

	if servicesValNode.Kind != yaml.MappingNode {
		return false, "", fmt.Errorf("expected services to be a mapping in %s", configPath)
	}

	svcName := defSvc.ServiceName
	if svcName == "" {
		svcName = pluginName
	}
	svcNameLower := strings.ToLower(svcName)
	protoLower := strings.ToLower(defSvc.Protocol)
	if protoLower == "" {
		protoLower = strings.ToLower(pluginName)
	}

	// Check if a service with the same name OR same protocol already exists
	for i := 0; i < len(servicesValNode.Content); i += 2 {
		curKey := strings.ToLower(servicesValNode.Content[i].Value)
		if curKey == svcNameLower {
			return false, servicesValNode.Content[i].Value, nil // service already exists
		}
		curVal := servicesValNode.Content[i+1]
		if curVal.Kind == yaml.MappingNode {
			for j := 0; j < len(curVal.Content); j += 2 {
				if strings.EqualFold(curVal.Content[j].Value, "protocol") {
					if strings.EqualFold(curVal.Content[j+1].Value, protoLower) {
						return false, servicesValNode.Content[i].Value, nil // protocol already configured
					}
				}
			}
		}
	}

	// Format servicesValNode as block style
	servicesValNode.Style = 0

	// Construct service node
	serviceKeyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: svcName,
	}

	serviceMapNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}

	// listen
	serviceMapNode.Content = append(serviceMapNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "listen"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: defSvc.Listen},
	)

	// upstream
	serviceMapNode.Content = append(serviceMapNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "upstream"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: defSvc.Upstream},
	)

	// protocol
	serviceMapNode.Content = append(serviceMapNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "protocol"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: protoLower},
	)

	// rate_limit
	if defSvc.RateLimitCPM > 0 {
		rateLimitMap := &yaml.Node{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "connections_per_minute"},
				{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(defSvc.RateLimitCPM)},
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "burst"},
				{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(defSvc.RateLimitBurst)},
			},
		}
		serviceMapNode.Content = append(serviceMapNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rate_limit"},
			rateLimitMap,
		)
	}

	// max_auth_failures
	if defSvc.MaxAuthFailures > 0 {
		serviceMapNode.Content = append(serviceMapNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "max_auth_failures"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(defSvc.MaxAuthFailures)},
		)
	}

	// ban_after_failures
	if defSvc.BanAfterFailures > 0 {
		serviceMapNode.Content = append(serviceMapNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ban_after_failures"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(defSvc.BanAfterFailures)},
		)
	}

	// plugin_config
	if len(defSvc.PluginConfig) > 0 {
		cfgBytes, err := yaml.Marshal(defSvc.PluginConfig)
		if err == nil {
			var pCfgNode yaml.Node
			if err := yaml.Unmarshal(cfgBytes, &pCfgNode); err == nil && len(pCfgNode.Content) > 0 {
				serviceMapNode.Content = append(serviceMapNode.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "plugin_config"},
					pCfgNode.Content[0],
				)
			}
		}
	}

	servicesValNode.Content = append(servicesValNode.Content, serviceKeyNode, serviceMapNode)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return false, "", fmt.Errorf("encoding updated YAML: %w", err)
	}
	_ = enc.Close()

	perm := os.FileMode(0644)
	if fi, err := os.Stat(configPath); err == nil {
		perm = fi.Mode().Perm()
	}

	if err := os.WriteFile(configPath, buf.Bytes(), perm); err != nil {
		return false, "", fmt.Errorf("writing updated config to %s: %w", configPath, err)
	}

	return true, svcName, nil
}

// IsPluginEnabled checks if a plugin is explicitly enabled.
// Precedence:
// 1. Runtime CLI overrides in plugins.json (enabled / disabled by user)
// 2. YAML configuration file (plugins.disabled / plugins.enabled)
// 3. Default: false (non-standard plugins are disabled by default)
func (c *Config) IsPluginEnabled(pluginName string) bool {
	nameLower := strings.ToLower(pluginName)

	// Check runtime / CLI overrides (plugins.json) first
	if pEnabled, pDisabled, err := plugins.GetPluginEnablement(plugins.ResolveProjectDir("")); err == nil {
		for _, pd := range pDisabled {
			if strings.EqualFold(pd, nameLower) {
				return false
			}
		}
		for _, pe := range pEnabled {
			if strings.EqualFold(pe, nameLower) {
				return true
			}
		}
	}

	// Check explicit disablement in configuration file
	for _, disabled := range c.Plugins.Disabled {
		if strings.EqualFold(disabled, nameLower) {
			return false
		}
	}

	// Check explicit enablement in configuration file
	for _, enabled := range c.Plugins.Enabled {
		if strings.EqualFold(enabled, nameLower) {
			return true
		}
	}

	return false
}

// GlobalConfig contains daemon-wide defaults.
type GlobalConfig struct {
	MaxConnections     int            `yaml:"max_connections"`
	BanDuration        Duration       `yaml:"ban_duration"`
	BanAfterFailures   int            `yaml:"ban_after_failures"`
	TarpitMs           int            `yaml:"tarpit_ms"`
	LogLevel           string         `yaml:"log_level"`
	LogFile            string         `yaml:"log_file"`
	GeoIPDB            string         `yaml:"geoip_db"`
	DataDir            string         `yaml:"data_dir"` // directory for persistent state (bans.db SQLite, etc.)
	IPFilter           IPFilterConfig `yaml:"ip_filter"`
	GeoBlock           GeoBlockConfig `yaml:"geo_block"`
}

// APIConfig controls the management REST & SSE API.
type APIConfig struct {
	Enabled    bool       `yaml:"enabled"`
	Listen     string     `yaml:"listen"`      // e.g. ":9091" or "127.0.0.1:9091" or "unix:///var/run/routewarden/tcp-warden.sock"
	Socket     string     `yaml:"socket"`      // optional Unix domain socket path, e.g. "/var/run/routewarden/tcp-warden.sock"
	SocketMode SocketMode `yaml:"socket_mode"` // permissions for Unix socket (default: 0666)
	AuthToken  string     `yaml:"auth_token"`  // optional Bearer token
}

// SocketMode represents an octal file permission mode (e.g. 0666 or 0660).
type SocketMode uint32

func (s *SocketMode) UnmarshalYAML(value *yaml.Node) error {
	var str string
	if err := value.Decode(&str); err == nil {
		m, err := strconv.ParseUint(str, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid socket_mode %q: expected an octal value such as '0660' or '0600'", str)
		}
		*s = SocketMode(m)
		return nil
	}
	var val uint32
	if err := value.Decode(&val); err == nil {
		*s = SocketMode(val)
		return nil
	}
	*s = 0666
	return nil
}

func (a *APIConfig) FileMode() os.FileMode {
	if a.SocketMode == 0 {
		return 0666
	}
	return os.FileMode(a.SocketMode)
}

// CrowdSecConfig controls the CrowdSec LAPI bouncer integration.
type CrowdSecConfig struct {
	Enabled         bool     `yaml:"enabled"`
	LAPIURL         string   `yaml:"lapi_url"`
	APIKey          string   `yaml:"api_key"`
	UpdateFrequency Duration `yaml:"update_frequency"`
	FallbackAction  string   `yaml:"fallback_action"` // "ban", "throttle", "bypass"
}

// IPFilterConfig defines CIDRs or IPs allowed or denied.
type IPFilterConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// GeoBlockConfig defines ISO 3166-1 alpha-2 country rules.
type GeoBlockConfig struct {
	DenyCountries  []string `yaml:"deny_countries"`
	AllowCountries []string `yaml:"allow_countries"`
}

// RateLimitConfig defines token-bucket rate limiting rules.
type RateLimitConfig struct {
	ConnectionsPerMinute int `yaml:"connections_per_minute"`
	Burst                int `yaml:"burst"`
}

// ResponseConfig defines action taken when a connection is rejected.
type ResponseConfig struct {
	Mode          string `yaml:"mode"`           // "drop" | "reject" | "tarpit" | "silent"
	TarpitMs      int    `yaml:"tarpit_ms"`      // delay in ms
	RejectMessage string `yaml:"reject_message"` // custom reject banner/message
}

// SSHSpecificConfig holds protocol options specific to SSH.
type SSHSpecificConfig struct {
	Banner       string `yaml:"banner"`
	MaxAuthTries int    `yaml:"max_auth_tries"`
}

// SMTPSpecificConfig holds protocol options specific to SMTP.
type SMTPSpecificConfig struct {
	BlockedSenderDomains []string `yaml:"blocked_sender_domains"`
	RequireSTARTTLS      bool     `yaml:"require_starttls"`
	MaxRecipients        int      `yaml:"max_recipients"`
}

// POP3SpecificConfig holds protocol options specific to POP3.
type POP3SpecificConfig struct {
	MaxAuthFailures int `yaml:"max_auth_failures"`
}

// IMAPSpecificConfig holds protocol options specific to IMAP.
type IMAPSpecificConfig struct {
	MaxAuthFailures int `yaml:"max_auth_failures"`
}

// PostgresSpecificConfig holds options specific to PostgreSQL.
type PostgresSpecificConfig struct {
	MaxAuthFailures int `yaml:"max_auth_failures"`
}

// MySQLSpecificConfig holds options specific to MySQL / MariaDB.
type MySQLSpecificConfig struct {
	MaxAuthFailures int `yaml:"max_auth_failures"`
}

// RedisSpecificConfig holds options specific to Redis.
type RedisSpecificConfig struct {
	BlockedCommands []string `yaml:"blocked_commands"`
}

// FTPSpecificConfig holds options specific to FTP.
type FTPSpecificConfig struct {
	MaxAuthFailures int `yaml:"max_auth_failures"`
}

// TLSSpecificConfig holds options specific to TLS SNI domain filtering.
type TLSSpecificConfig struct {
	AllowedDomains []string `yaml:"allowed_domains"`
	BlockedDomains []string `yaml:"blocked_domains"`
}

// UDPConfig defines per-service tuning parameters for UDP transport.
type UDPConfig struct {
	// SessionTimeout is how long a UDP session may be idle before it is reaped.
	// Defaults to 30s when unset.
	SessionTimeout Duration `yaml:"session_timeout"`

	// MaxSessions caps the number of concurrent UDP sessions from unique clients.
	// 0 (default) means unlimited.
	MaxSessions int `yaml:"max_sessions"`

	// ReadBufferSize is the per-datagram read buffer in bytes (default: 65535).
	ReadBufferSize int `yaml:"read_buffer_size"`
}

// ServiceConfig defines a single proxy service (TCP, UDP, or both).
type ServiceConfig struct {
	Name             string                 `yaml:"-"` // injected from map key
	Enabled          *bool                  `yaml:"enabled"`
	Listen           string                 `yaml:"listen"`
	Upstream         string                 `yaml:"upstream"`
	// Transport selects the network transport: "tcp" (default) | "udp" | "both".
	// "both" binds listeners on both TCP and UDP for the same port (e.g. DNS on :53).
	Transport        string                 `yaml:"transport"`
	Protocol         string                 `yaml:"protocol"` // "ssh" | "smtp" | "dns" | ... | "tcp"
	RateLimit        RateLimitConfig        `yaml:"rate_limit"`
	IPFilter         IPFilterConfig         `yaml:"ip_filter"`
	GeoBlock         GeoBlockConfig         `yaml:"geo_block"`
	MaxAuthFailures  int                    `yaml:"max_auth_failures"`
	BanAfterFailures int                    `yaml:"ban_after_failures"`
	BanDuration      Duration               `yaml:"ban_duration"`
	Response         ResponseConfig         `yaml:"response"`
	PluginConfig     map[string]any         `yaml:"plugin_config,omitempty"`
	UDP              UDPConfig              `yaml:"udp"`
	SSH              SSHSpecificConfig      `yaml:"ssh"`
	SMTP             SMTPSpecificConfig     `yaml:"smtp"`
	POP3             POP3SpecificConfig     `yaml:"pop3"`
	IMAP             IMAPSpecificConfig     `yaml:"imap"`
	Postgres         PostgresSpecificConfig `yaml:"postgres"`
	MySQL            MySQLSpecificConfig    `yaml:"mysql"`
	Redis            RedisSpecificConfig    `yaml:"redis"`
	FTP              FTPSpecificConfig      `yaml:"ftp"`
	TLS              TLSSpecificConfig      `yaml:"tls"`
}

// GetPluginOptions collects plugin configuration options from PluginConfig or typed legacy fields.
func (s *ServiceConfig) GetPluginOptions() map[string]any {
	opts := make(map[string]any)
	if s.PluginConfig != nil {
		for k, v := range s.PluginConfig {
			opts[k] = v
		}
	}

	switch s.Protocol {
	case "ssh":
		if s.SSH.Banner != "" {
			opts["banner"] = s.SSH.Banner
		}
		if s.SSH.MaxAuthTries > 0 {
			opts["max_auth_tries"] = s.SSH.MaxAuthTries
		} else if s.MaxAuthFailures > 0 {
			opts["max_auth_tries"] = s.MaxAuthFailures
		}
	case "smtp", "mail":
		if len(s.SMTP.BlockedSenderDomains) > 0 {
			opts["blocked_sender_domains"] = s.SMTP.BlockedSenderDomains
		}
		if s.SMTP.MaxRecipients > 0 {
			opts["max_recipients"] = s.SMTP.MaxRecipients
		}
		opts["require_starttls"] = s.SMTP.RequireSTARTTLS
	case "pop3":
		if s.POP3.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.POP3.MaxAuthFailures
		} else if s.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.MaxAuthFailures
		}
	case "imap":
		if s.IMAP.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.IMAP.MaxAuthFailures
		} else if s.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.MaxAuthFailures
		}
	case "postgres", "postgresql":
		if s.Postgres.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.Postgres.MaxAuthFailures
		} else if s.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.MaxAuthFailures
		}
	case "mysql", "mariadb":
		if s.MySQL.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.MySQL.MaxAuthFailures
		} else if s.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.MaxAuthFailures
		}
	case "redis":
		if len(s.Redis.BlockedCommands) > 0 {
			opts["blocked_commands"] = s.Redis.BlockedCommands
		}
	case "ftp":
		if s.FTP.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.FTP.MaxAuthFailures
		} else if s.MaxAuthFailures > 0 {
			opts["max_auth_failures"] = s.MaxAuthFailures
		}
	case "tls", "sni":
		if len(s.TLS.AllowedDomains) > 0 {
			opts["allowed_domains"] = s.TLS.AllowedDomains
		}
		if len(s.TLS.BlockedDomains) > 0 {
			opts["blocked_domains"] = s.TLS.BlockedDomains
		}
	}

	return opts
}

// IsEnabled returns true unless explicitly disabled.
func (s *ServiceConfig) IsEnabled() bool {
	if s.Enabled == nil {
		return true
	}
	return *s.Enabled
}

// ParsePortRange parses addresses with single ports or port ranges.
// Supported formats:
//   ":8080"               -> host: "", start: 8080, end: 8080
//   ":8000-8005"          -> host: "", start: 8000, end: 8005
//   "127.0.0.1:8080"      -> host: "127.0.0.1", start: 8080, end: 8080
//   "127.0.0.1:8000-8005" -> host: "127.0.0.1", start: 8000, end: 8005
//   "[::1]:8000-8005"     -> host: "::1", start: 8000, end: 8005
//   "8080"                -> host: "", start: 8080, end: 8080
//   "8000-8005"           -> host: "", start: 8000, end: 8005
func ParsePortRange(addr string) (host string, startPort, endPort int, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0, 0, fmt.Errorf("empty address")
	}

	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		// Port or port range without host (e.g. "8080" or "8000-8005")
		start, end, err := parseRange(addr)
		if err != nil {
			return "", 0, 0, err
		}
		return "", start, end, nil
	}

	host = addr[:lastColon]
	portPart := addr[lastColon+1:]

	// Strip IPv6 brackets if present
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	start, end, err := parseRange(portPart)
	if err != nil {
		return "", 0, 0, err
	}
	return host, start, end, nil
}

func parseRange(portPart string) (int, int, error) {
	portPart = strings.TrimSpace(portPart)
	if idx := strings.Index(portPart, "-"); idx != -1 {
		startStr := strings.TrimSpace(portPart[:idx])
		endStr := strings.TrimSpace(portPart[idx+1:])
		start, err := strconv.Atoi(startStr)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid start port %q: %w", startStr, err)
		}
		end, err := strconv.Atoi(endStr)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid end port %q: %w", endStr, err)
		}
		if start < 1 || start > 65535 {
			return 0, 0, fmt.Errorf("start port %d out of valid range (1-65535)", start)
		}
		if end < 1 || end > 65535 {
			return 0, 0, fmt.Errorf("end port %d out of valid range (1-65535)", end)
		}
		if start > end {
			return 0, 0, fmt.Errorf("start port %d must be <= end port %d", start, end)
		}
		if end-start > 1000 {
			return 0, 0, fmt.Errorf("port range (%d-%d) exceeds maximum allowed range of 1000 ports", start, end)
		}
		return start, end, nil
	}

	port, err := strconv.Atoi(portPart)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q: %w", portPart, err)
	}
	if port < 1 || port > 65535 {
		return 0, 0, fmt.Errorf("port %d out of valid range (1-65535)", port)
	}
	return port, port, nil
}

// FormatHostPort formats host and port into host:port or [ipv6]:port.
func FormatHostPort(host string, port int) string {
	if host != "" && strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// ListenPorts returns the host and individual port numbers for this service listener.
func (s *ServiceConfig) ListenPorts() (host string, ports []int, err error) {
	h, start, end, err := ParsePortRange(s.Listen)
	if err != nil {
		return "", nil, err
	}
	ports = make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return h, ports, nil
}

// ResolveUpstream calculates the target upstream address (host:port) for an incoming connection.
// For many-to-one mapping (e.g. listen: ":8000-8005", upstream: "127.0.0.1:8080"), it routes all connections to the single upstream port.
// For 1:1 port range mapping (e.g. listen: ":8000-8005", upstream: "10.0.0.1:9000-9005"), it offsets the incoming port:
//   upstreamPort = uStart + (clientLocalPort - lStart).
func (s *ServiceConfig) ResolveUpstream(localAddr net.Addr) (string, error) {
	_, lStart, lEnd, err := ParsePortRange(s.Listen)
	if err != nil {
		return s.Upstream, err
	}
	uHost, uStart, uEnd, err := ParsePortRange(s.Upstream)
	if err != nil {
		return s.Upstream, err
	}

	// Many-to-one (single upstream target)
	if uStart == uEnd {
		return FormatHostPort(uHost, uStart), nil
	}

	// 1:1 range mapping
	localPort := 0
	if tcpAddr, ok := localAddr.(*net.TCPAddr); ok {
		localPort = tcpAddr.Port
	} else if udpAddr, ok := localAddr.(*net.UDPAddr); ok {
		localPort = udpAddr.Port
	} else if localAddr != nil {
		_, pStr, err := net.SplitHostPort(localAddr.String())
		if err == nil {
			localPort, _ = strconv.Atoi(pStr)
		}
	}

	if localPort < lStart || localPort > lEnd {
		return FormatHostPort(uHost, uStart), nil
	}

	offset := localPort - lStart
	targetPort := uStart + offset
	return FormatHostPort(uHost, targetPort), nil
}

// Load reads and parses a YAML configuration file with environment variable expansion.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}
	return Parse(data)
}

var envPattern = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)(?::-([^}]*))?\}`)

// expandEnvWithDefaults replaces ${VAR} or ${VAR:-default} with env values.
func expandEnvWithDefaults(s string) string {
	return envPattern.ReplaceAllStringFunc(s, func(match string) string {
		sub := envPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		varName := sub[1]
		val, exists := os.LookupEnv(varName)
		if exists && val != "" {
			return val
		}
		if len(sub) >= 3 && sub[2] != "" {
			return sub[2]
		}
		return val
	})
}

// Parse parses raw YAML config bytes with defaults and validation.
func Parse(data []byte) (*Config, error) {
	expanded := expandEnvWithDefaults(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML config: %w", err)
	}

	applyDefaults(&cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Version == "" {
		cfg.Version = "1.0"
	}
	if cfg.Global.BanDuration.Duration() == 0 {
		cfg.Global.BanDuration = Duration(1 * time.Hour)
	}
	if cfg.Global.LogLevel == "" {
		cfg.Global.LogLevel = "warn"
	}
	// Note: cfg.Global.LogFile intentionally has no default — file logging is opt-in.
	// Users who want SIEM/CrowdSec log output must set log_file explicitly in their config.

	if cfg.Global.DataDir == "" {
		cfg.Global.DataDir = "/var/lib/routewarden"
	}

	// Only apply the TCP listen default when no socket is configured either.
	// If the user sets only api.socket, leave api.listen empty so the daemon
	// doesn't bind an unexpected TCP port.
	if cfg.API.Listen == "" && cfg.API.Socket == "" {
		cfg.API.Listen = "127.0.0.1:9091"
	}

	if cfg.CrowdSec.UpdateFrequency.Duration() == 0 {
		cfg.CrowdSec.UpdateFrequency = Duration(10 * time.Second)
	}
	if cfg.CrowdSec.FallbackAction == "" {
		cfg.CrowdSec.FallbackAction = "ban"
	}

	for name, svc := range cfg.Services {
		svc.Name = name
		if svc.Protocol == "" {
			if strings.EqualFold(strings.TrimSpace(svc.Transport), "udp") {
				svc.Protocol = "udp"
			} else {
				svc.Protocol = "tcp"
			}
		} else {
			svc.Protocol = strings.ToLower(strings.TrimSpace(svc.Protocol))
		}

		if svc.Response.Mode == "" {
			svc.Response.Mode = "drop"
		}

		if svc.BanDuration.Duration() == 0 {
			svc.BanDuration = cfg.Global.BanDuration
		}
		if svc.BanAfterFailures == 0 && cfg.Global.BanAfterFailures > 0 {
			svc.BanAfterFailures = cfg.Global.BanAfterFailures
		}
		if svc.Response.TarpitMs == 0 && cfg.Global.TarpitMs > 0 {
			svc.Response.TarpitMs = cfg.Global.TarpitMs
		}

		cfg.Services[name] = svc
	}
}

// Validate checks configuration for syntactic and semantic correctness.
func (c *Config) Validate() error {
	if len(c.Services) == 0 {
		return fmt.Errorf("no services defined in configuration")
	}

	usedListenPorts := make(map[string]string)

	for name, svc := range c.Services {
		if !svc.IsEnabled() {
			continue
		}
		if svc.Listen == "" {
			return fmt.Errorf("service %q: listen address cannot be empty", name)
		}
		if svc.Upstream == "" {
			return fmt.Errorf("service %q: upstream address cannot be empty", name)
		}

		lHost, lStart, lEnd, err := ParsePortRange(svc.Listen)
		if err != nil {
			return fmt.Errorf("service %q: invalid listen address %q: %w", name, svc.Listen, err)
		}

		_, uStart, uEnd, err := ParsePortRange(svc.Upstream)
		if err != nil {
			return fmt.Errorf("service %q: invalid upstream address %q: %w", name, svc.Upstream, err)
		}

		lSpan := lEnd - lStart + 1
		uSpan := uEnd - uStart + 1
		if lSpan == 1 && uSpan > 1 {
			return fmt.Errorf("service %q: single listen port cannot map to an upstream port range", name)
		}
		if lSpan > 1 && uSpan > 1 && lSpan != uSpan {
			return fmt.Errorf("service %q: upstream port range size (%d) must match listen port range size (%d) for 1:1 mapping, or specify a single upstream port for many-to-one", name, uSpan, lSpan)
		}

		var transports []string
		tr := strings.ToLower(strings.TrimSpace(svc.Transport))
		switch tr {
		case "udp":
			transports = []string{"udp"}
		case "both":
			transports = []string{"tcp", "udp"}
		default:
			transports = []string{"tcp"}
		}

		for p := lStart; p <= lEnd; p++ {
			for _, t := range transports {
				portKey := fmt.Sprintf("%s/%s", t, FormatHostPort(lHost, p))
				if prev, exists := usedListenPorts[portKey]; exists {
					return fmt.Errorf("service %q: duplicate listen address %q (%s, already used by %q)", name, FormatHostPort(lHost, p), strings.ToUpper(t), prev)
				}

				// If wildcard listener (e.g. ":8080" or "0.0.0.0:8080"), conflict with other wildcards
				if lHost == "" || lHost == "0.0.0.0" || lHost == "::" {
					anyKey := fmt.Sprintf("%s/*:%d", t, p)
					if prev, exists := usedListenPorts[anyKey]; exists {
						return fmt.Errorf("service %q: duplicate listen address %q (%s, already used by %q)", name, FormatHostPort(lHost, p), strings.ToUpper(t), prev)
					}
					usedListenPorts[anyKey] = name
				}

				usedListenPorts[portKey] = name
			}
		}

		switch strings.ToLower(strings.TrimSpace(svc.Protocol)) {
		case "ssh", "smtp", "pop3", "imap", "tcp", "udp", "generic", "":
			// valid standard built-in protocols
		default:
			// Check if supported by registered plugin
			p, ok := plugins.Get(svc.Protocol)
			if !ok {
				if entry, hasEntry := c.Plugins.Entries[svc.Protocol]; hasEntry && entry.Source != "" {
					break
				}
				c.Warnings = append(c.Warnings, fmt.Sprintf("service %q: protocol %q requires plugin %q which is not installed. Install it via 'tcp-warden plugins install https://github.com/routewarden/plugins/%s' or configure source under 'plugins.%s.source' in tcp-warden.yaml",
					name, svc.Protocol, svc.Protocol, svc.Protocol, svc.Protocol))
				break
			}
			// Non-standard plugins are disabled by default and must be explicitly enabled
			if !c.IsPluginEnabled(p.Manifest().Name) {
				c.Warnings = append(c.Warnings, fmt.Sprintf("service %q: protocol %q requires plugin %q which is DISABLED by default. Enable it under 'plugins.%s.enabled: true' in tcp-warden.yaml or run 'tcp-warden plugins enable %s'",
					name, svc.Protocol, p.Manifest().Name, p.Manifest().Name, p.Manifest().Name))
				break
			}
			if err := p.ValidateConfig(svc.GetPluginOptions()); err != nil {
				return fmt.Errorf("service %q: plugin %q config error: %w", name, p.Manifest().Name, err)
			}
		}

		// Validate IP filters
		for _, ipStr := range svc.IPFilter.Allow {
			if !isValidIPOrCIDR(ipStr) {
				return fmt.Errorf("service %q: invalid allowed IP/CIDR %q", name, ipStr)
			}
		}
		for _, ipStr := range svc.IPFilter.Deny {
			if !isValidIPOrCIDR(ipStr) {
				return fmt.Errorf("service %q: invalid denied IP/CIDR %q", name, ipStr)
			}
		}

		// Validate response mode
		switch strings.ToLower(svc.Response.Mode) {
		case "drop", "reject", "tarpit", "silent":
			// valid
		default:
			return fmt.Errorf("service %q: unsupported response mode %q (must be 'drop', 'reject', 'tarpit', or 'silent')", name, svc.Response.Mode)
		}
	}

	// Validate global IP filters
	for _, ipStr := range c.Global.IPFilter.Allow {
		if !isValidIPOrCIDR(ipStr) {
			return fmt.Errorf("global: invalid allowed IP/CIDR %q", ipStr)
		}
	}
	for _, ipStr := range c.Global.IPFilter.Deny {
		if !isValidIPOrCIDR(ipStr) {
			return fmt.Errorf("global: invalid denied IP/CIDR %q", ipStr)
		}
	}

	return nil
}

func isValidIPOrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '%'); idx != -1 {
		s = s[:idx]
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

