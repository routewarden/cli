package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ProxyResult tracks bytes transferred and errors during inspection/proxying.
type ProxyResult struct {
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
	Err      error `json:"err,omitempty"`
}

// Context gives inspectors access to connection metadata and security callbacks.
type Context interface {
	Context() context.Context
	Service() string
	ClientIP() string
	OnAuthFailure()
	OnSecurityEvent(action, reason string)
}

// Inspector is implemented by each protocol inspection session.
type Inspector interface {
	// Run inspects traffic between client and upstream until session completion.
	// Returns proxy accounting results, whether the session was actively blocked,
	// the reason for blocking (if blocked), and any underlying network error.
	Run(ctx Context, client, upstream net.Conn) (result ProxyResult, blocked bool, reason string, err error)
}

// DefaultServiceConfig defines the template for a service auto-generated when the plugin is installed.
type DefaultServiceConfig struct {
	ServiceName      string         `json:"name,omitempty" yaml:"name,omitempty"`
	Listen           string         `json:"listen,omitempty" yaml:"listen,omitempty"`
	Upstream         string         `json:"upstream,omitempty" yaml:"upstream,omitempty"`
	Protocol         string         `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	RateLimitCPM     int            `json:"connections_per_minute,omitempty" yaml:"connections_per_minute,omitempty"`
	RateLimitBurst   int            `json:"burst,omitempty" yaml:"burst,omitempty"`
	MaxAuthFailures  int            `json:"max_auth_failures,omitempty" yaml:"max_auth_failures,omitempty"`
	BanAfterFailures int            `json:"ban_after_failures,omitempty" yaml:"ban_after_failures,omitempty"`
	PluginConfig     map[string]any `json:"plugin_config,omitempty" yaml:"plugin_config,omitempty"`
}

// ManifestVersion is the specification version of the RouteWarden Plugin Manifest format (v1).
// Plugins declare compatibility with this manifest schema version (e.g., "1.0.0", "^1.0.0").
// It evolves independently from host application releases and is not updated by release scripts.
const ManifestVersion = "1.0.0"

// Version is the current release version of the RouteWarden Plugin SDK (synchronized with RouteWarden releases).
const Version = "5.4.0"

// Manifest defines identity, version, and capabilities of a plugin.
type Manifest struct {
	Name            string                `json:"name" yaml:"name"`
	Version         string                `json:"version" yaml:"version"`
	ManifestVersion string                `json:"manifest_version,omitempty" yaml:"manifest_version,omitempty"`
	Description     string                `json:"description" yaml:"description"`
	Author          string                `json:"author,omitempty" yaml:"author,omitempty"`
	Protocols       []string              `json:"protocols" yaml:"protocols"`
	Config          map[string]any        `json:"config,omitempty" yaml:"config,omitempty"`
	DefaultService  *DefaultServiceConfig `json:"default_service,omitempty" yaml:"default_service,omitempty"`
}

// Validate checks that the manifest contains required identity fields and valid declarations.
func (m *Manifest) Validate() error {
	name := strings.TrimSpace(m.Name)
	if name == "" {
		return errors.New("plugin manifest missing required 'name' field")
	}
	if strings.ContainsAny(name, "/\\:") || strings.Contains(name, "..") {
		return fmt.Errorf("plugin manifest 'name' %q contains invalid characters or path separators", m.Name)
	}
	if strings.TrimSpace(m.Version) == "" {
		return errors.New("plugin manifest missing required 'version' field")
	}
	if len(m.Protocols) == 0 {
		return errors.New("plugin manifest missing required 'protocols' field")
	}
	for i, p := range m.Protocols {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("plugin manifest protocols[%d] cannot be empty", i)
		}
	}
	return nil
}

// CheckCompatibility checks if the manifest is compatible with the given host manifest version using SemVer rules.
// If hostVersion is omitted, sdk.ManifestVersion is used.
func (m *Manifest) CheckCompatibility(hostVersion ...string) error {
	if m.ManifestVersion == "" {
		return nil
	}
	hVer := ManifestVersion
	if len(hostVersion) > 0 && hostVersion[0] != "" {
		hVer = hostVersion[0]
	}
	return CheckSemVerCompatibility(hVer, m.ManifestVersion)
}

// ConfigMigrator is an optional interface plugins can implement to automatically
// migrate their service configuration when the plugin or SDK version updates.
type ConfigMigrator interface {
	MigrateConfig(fromVersion string, config map[string]any) (map[string]any, error)
}

// Plugin is the primary interface that all RouteWarden plugins must implement.
type Plugin interface {
	// Manifest returns the plugin's identity, version, and supported protocols.
	Manifest() Manifest

	// ValidateConfig validates protocol-specific configuration options.
	ValidateConfig(config map[string]any) error

	// CreateInspector creates an inspector instance configured with options.
	CreateInspector(config map[string]any) (Inspector, error)

	// SelfTest executes automated tests (using synthetic in-memory connections like net.Pipe)
	// to verify that the inspector functions properly in the current runtime environment.
	// If SelfTest returns an error, the plugin will be AUTOMATICALLY DISABLED by the engine.
	SelfTest() error
}

// TestResult records the outcome of a plugin's self-test execution.
type TestResult struct {
	PluginName string        `json:"plugin_name"`
	Passed     bool          `json:"passed"`
	Error      error         `json:"error,omitempty"`
	Duration   time.Duration `json:"duration"`
}

// DefaultContext is a helper implementation of Context for tests and standard pipelines.
type DefaultContext struct {
	Ctx             context.Context
	ServiceName     string
	ClientAddress   string
	AuthFailureFunc func()
	SecurityFunc    func(action, reason string)
}

func (d *DefaultContext) Context() context.Context {
	if d.Ctx == nil {
		return context.Background()
	}
	return d.Ctx
}

func (d *DefaultContext) Service() string {
	return d.ServiceName
}

func (d *DefaultContext) ClientIP() string {
	return d.ClientAddress
}

func (d *DefaultContext) OnAuthFailure() {
	if d.AuthFailureFunc != nil {
		d.AuthFailureFunc()
	}
}

func (d *DefaultContext) OnSecurityEvent(action, reason string) {
	if d.SecurityFunc != nil {
		d.SecurityFunc(action, reason)
	}
}

// ParseManifest parses YAML data into an sdk.Manifest and validates its required fields.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parsing plugin manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, fmt.Errorf("validating plugin manifest: %w", err)
	}
	return m, nil
}

// MustParseManifest parses YAML data into an sdk.Manifest or panics on malformed YAML.
// Ideal for loading embedded plugin.yaml via //go:embed.
func MustParseManifest(data []byte) Manifest {
	m, err := ParseManifest(data)
	if err != nil {
		panic(fmt.Sprintf("invalid embedded plugin manifest: %v", err))
	}
	return m
}

