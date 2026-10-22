package plugins

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/routewarden/cli/proxy/logger"
	"github.com/routewarden/cli/proxy/plugins/sdk"
)

// PluginStatus represents the operational health status of a plugin.
type PluginStatus string

const (
	StatusPending      PluginStatus = "PENDING"
	StatusActive       PluginStatus = "ACTIVE"
	StatusDisabled     PluginStatus = "DISABLED"
	StatusIncompatible PluginStatus = "INCOMPATIBLE"
)

// PluginInfo provides human-readable summary of a registered plugin.
type PluginInfo struct {
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	Description   string       `json:"description"`
	Protocols     []string     `json:"protocols"`
	Enabled       bool         `json:"enabled"`
	Status        PluginStatus `json:"status"`
	DisableReason string       `json:"disable_reason,omitempty"`
	TestError     string       `json:"test_error,omitempty"`
	TestTime      time.Time    `json:"test_time,omitempty"`
}

type entry struct {
	plugin        sdk.Plugin
	enabled       bool
	status        PluginStatus
	disableReason string
	testError     error
	testTime      time.Time
}

type Registry struct {
	mu          sync.RWMutex
	plugins     map[string]*entry // keyed by plugin name (lowercase)
	protocolMap map[string]string // protocol -> plugin name
}

var globalRegistry = NewRegistry()

// NewRegistry creates a new plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins:     make(map[string]*entry),
		protocolMap: make(map[string]string),
	}
}

// Global returns the global singleton registry.
func Global() *Registry {
	return globalRegistry
}

// Register registers a plugin with the global registry.
// Non-standard plugins are registered as DISABLED by default until explicitly enabled.
func Register(p sdk.Plugin) {
	globalRegistry.Register(p)
}

// CompareVersions compares two semver version strings (e.g. "1.2.0" and "1.1.5").
// Returns -1 if v1 < v2, 0 if v1 == v2, and 1 if v1 > v2.
func CompareVersions(v1, v2 string) int {
	sv1, err1 := ParseSemVer(v1)
	sv2, err2 := ParseSemVer(v2)
	if err1 == nil && err2 == nil {
		return CompareSemVer(sv1, sv2)
	}

	v1 = strings.TrimPrefix(strings.TrimSpace(v1), "v")
	v2 = strings.TrimPrefix(strings.TrimSpace(v2), "v")

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			n1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			n2, _ = strconv.Atoi(parts2[i])
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}
	return 0
}

// CheckCompatibility verifies if a plugin manifest is compatible with the running RouteWarden manifest version
// using Semantic Versioning (SemVer 2.0.0) rules.
func CheckCompatibility(m sdk.Manifest) error {
	if m.ManifestVersion != "" {
		if err := CheckSemVerCompatibility(sdk.ManifestVersion, m.ManifestVersion); err != nil {
			return fmt.Errorf("incompatible manifest version %q with host %s: %w", m.ManifestVersion, sdk.ManifestVersion, err)
		}
	}
	return nil
}

func (r *Registry) Register(p sdk.Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()

	manifest := p.Manifest()
	nameKey := strings.ToLower(manifest.Name)

	status := StatusDisabled
	reason := "disabled by default"
	if err := manifest.Validate(); err != nil {
		status = StatusIncompatible
		reason = fmt.Sprintf("invalid manifest: %v", err)
		logger.Default().Warn("[REGISTRY] Plugin %q manifest validation failed: %v. Disabling.", manifest.Name, err)
	} else if err := CheckCompatibility(manifest); err != nil {
		status = StatusIncompatible
		reason = fmt.Sprintf("incompatible manifest version: %v", err)
		logger.Default().Warn("[REGISTRY] Plugin %q is incompatible: %v. Disabling.", manifest.Name, err)
	}

	r.plugins[nameKey] = &entry{
		plugin:        p,
		enabled:       false, // pre-shipped non-standard plugins disabled by default
		status:        status,
		disableReason: reason,
	}

	for _, proto := range manifest.Protocols {
		r.protocolMap[strings.ToLower(proto)] = nameKey
	}
}

// Enable enables a plugin and runs its pre-flight self-test.
// If the self-test fails, the plugin remains DISABLED and an error is returned.
func Enable(nameOrProto string) error {
	return globalRegistry.Enable(nameOrProto)
}

func (r *Registry) Enable(nameOrProto string) error {
	// 1. Locate the entry under a read lock (non-blocking for live traffic).
	r.mu.RLock()
	key := strings.ToLower(nameOrProto)
	ent, ok := r.plugins[key]
	if !ok {
		if pluginName, found := r.protocolMap[key]; found {
			ent = r.plugins[pluginName]
			ok = true
		}
	}
	r.mu.RUnlock()

	if !ok || ent == nil {
		return fmt.Errorf("plugin %q not found", nameOrProto)
	}

	// 2. Validate manifest and check compatibility
	man := ent.plugin.Manifest()
	if err := man.Validate(); err != nil {
		r.mu.Lock()
		ent.enabled = false
		ent.status = StatusIncompatible
		ent.disableReason = fmt.Sprintf("invalid manifest: %v", err)
		r.mu.Unlock()
		return fmt.Errorf("plugin %q has invalid manifest: %w", nameOrProto, err)
	}
	if err := CheckCompatibility(man); err != nil {
		r.mu.Lock()
		ent.enabled = false
		ent.status = StatusIncompatible
		ent.disableReason = fmt.Sprintf("incompatible manifest version: %v", err)
		r.mu.Unlock()
		return fmt.Errorf("plugin %q is incompatible with RouteWarden manifest version %s: %w", nameOrProto, sdk.ManifestVersion, err)
	}

	// 3. Run self-test without holding any lock (may take up to 3 seconds).
	err := safeSelfTest(ent.plugin)
	testTime := time.Now()

	// 4. Commit result under write lock.
	r.mu.Lock()
	defer r.mu.Unlock()

	ent.testTime = testTime
	if err != nil {
		ent.enabled = false
		ent.status = StatusDisabled
		ent.disableReason = "self-test failed"
		ent.testError = err
		return fmt.Errorf("plugin %q self-test failed: %w", ent.plugin.Manifest().Name, err)
	}

	ent.enabled = true
	ent.status = StatusActive
	ent.disableReason = ""
	ent.testError = nil
	return nil
}

// Disable marks a plugin as disabled.
func Disable(nameOrProto string, reason string) error {
	return globalRegistry.Disable(nameOrProto, reason)
}

func (r *Registry) Disable(nameOrProto string, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := strings.ToLower(nameOrProto)
	ent, ok := r.plugins[key]
	if !ok {
		if pluginName, found := r.protocolMap[key]; found {
			ent = r.plugins[pluginName]
			ok = true
		}
	}
	if !ok || ent == nil {
		return fmt.Errorf("plugin %q not found", nameOrProto)
	}

	if reason == "" {
		reason = "disabled by administrator"
	}
	ent.enabled = false
	ent.status = StatusDisabled
	ent.disableReason = reason
	return nil
}

// ApplyConfiguration applies enabled and disabled plugin lists from configuration.
func ApplyConfiguration(enabled []string, disabled []string) map[string]error {
	return globalRegistry.ApplyConfiguration(enabled, disabled)
}

func (r *Registry) ApplyConfiguration(enabled []string, disabled []string) map[string]error {
	errs := make(map[string]error)

	for _, name := range enabled {
		if err := r.Enable(name); err != nil {
			errs[name] = err
		}
	}

	for _, name := range disabled {
		_ = r.Disable(name, "disabled in configuration")
	}

	return errs
}

// RunSelfTests executes SelfTest() on all registered plugins (or enabled ones).
func RunSelfTests() map[string]sdk.TestResult {
	return globalRegistry.RunSelfTests()
}

func (r *Registry) RunSelfTests() map[string]sdk.TestResult {
	type target struct {
		name   string
		plugin sdk.Plugin
	}

	// 1. Snapshot plugin list under read lock so live traffic is not blocked during tests
	r.mu.RLock()
	targets := make([]target, 0, len(r.plugins))
	for name, ent := range r.plugins {
		targets = append(targets, target{name: name, plugin: ent.plugin})
	}
	r.mu.RUnlock()

	// 2. Run self-tests outside locks
	type outcome struct {
		target target
		res    sdk.TestResult
	}
	outcomes := make([]outcome, 0, len(targets))
	for _, t := range targets {
		start := time.Now()
		err := safeSelfTest(t.plugin)
		dur := time.Since(start)

		res := sdk.TestResult{
			PluginName: t.plugin.Manifest().Name,
			Passed:     err == nil,
			Error:      err,
			Duration:   dur,
		}
		outcomes = append(outcomes, outcome{target: t, res: res})
	}

	// 3. Commit results under write lock
	r.mu.Lock()
	defer r.mu.Unlock()

	results := make(map[string]sdk.TestResult, len(outcomes))
	now := time.Now()
	for _, o := range outcomes {
		results[o.target.name] = o.res
		if ent, ok := r.plugins[o.target.name]; ok {
			ent.testTime = now
			if o.res.Error != nil {
				ent.status = StatusDisabled
				ent.testError = o.res.Error
				ent.disableReason = "self-test failed"
			} else if ent.enabled {
				ent.status = StatusActive
				ent.testError = nil
				ent.disableReason = ""
			}
		}
	}

	return results
}

// RunSelfTest runs self test for a single plugin.
func (r *Registry) RunSelfTest(name string) (sdk.TestResult, error) {
	nameKey := strings.ToLower(name)

	// 1. Find plugin under read lock
	r.mu.RLock()
	ent, exists := r.plugins[nameKey]
	if !exists {
		if pName, found := r.protocolMap[nameKey]; found {
			nameKey = pName
			ent, exists = r.plugins[pName]
		}
	}
	var p sdk.Plugin
	if exists && ent != nil {
		p = ent.plugin
	}
	r.mu.RUnlock()

	if !exists || p == nil {
		return sdk.TestResult{}, fmt.Errorf("plugin %q not found", name)
	}

	// 2. Run self-test outside locks
	start := time.Now()
	err := safeSelfTest(p)
	dur := time.Since(start)

	res := sdk.TestResult{
		PluginName: p.Manifest().Name,
		Passed:     err == nil,
		Error:      err,
		Duration:   dur,
	}

	// 3. Commit status under write lock
	r.mu.Lock()
	defer r.mu.Unlock()

	if ent, ok := r.plugins[nameKey]; ok {
		ent.testTime = time.Now()
		if err != nil {
			ent.status = StatusDisabled
			ent.testError = err
			ent.disableReason = "self-test failed"
		} else if ent.enabled {
			ent.status = StatusActive
			ent.testError = nil
			ent.disableReason = ""
		}
	}

	return res, nil
}

// Get finds a plugin by protocol name (e.g. "postgres", "redis").
func Get(protocol string) (sdk.Plugin, bool) {
	return globalRegistry.Get(protocol)
}

func (r *Registry) Get(protocol string) (sdk.Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(protocol)
	nameKey, ok := r.protocolMap[key]
	if !ok {
		nameKey = key
	}

	ent, ok := r.plugins[nameKey]
	if !ok || ent == nil {
		return nil, false
	}
	return ent.plugin, true
}

// GetByName finds a plugin by its name.
func GetByName(name string) (sdk.Plugin, bool) {
	return globalRegistry.GetByName(name)
}

func (r *Registry) GetByName(name string) (sdk.Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ent, ok := r.plugins[strings.ToLower(name)]
	if !ok {
		return nil, false
	}
	return ent.plugin, true
}

// IsEnabled returns true if the plugin is explicitly enabled.
func IsEnabled(nameOrProtocol string) bool {
	return globalRegistry.IsEnabled(nameOrProtocol)
}

func (r *Registry) IsEnabled(nameOrProtocol string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(nameOrProtocol)
	ent, ok := r.plugins[key]
	if !ok {
		if pluginName, found := r.protocolMap[key]; found {
			ent = r.plugins[pluginName]
			ok = true
		}
	}
	if !ok || ent == nil {
		return false
	}
	return ent.enabled
}

// IsActive returns true if the plugin exists, is enabled, and passed its self-test.
func IsActive(nameOrProtocol string) bool {
	return globalRegistry.IsActive(nameOrProtocol)
}

func (r *Registry) IsActive(nameOrProtocol string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(nameOrProtocol)
	ent, ok := r.plugins[key]
	if !ok {
		if pluginName, found := r.protocolMap[key]; found {
			ent = r.plugins[pluginName]
			ok = true
		}
	}

	if !ok || ent == nil {
		return false
	}
	return ent.enabled && ent.status == StatusActive
}

// GetStatus returns the operational status, disable reason, and any test error.
func GetStatus(nameOrProtocol string) (PluginStatus, string, error) {
	return globalRegistry.GetStatus(nameOrProtocol)
}

func (r *Registry) GetStatus(nameOrProtocol string) (PluginStatus, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := strings.ToLower(nameOrProtocol)
	ent, ok := r.plugins[key]
	if !ok {
		if pluginName, found := r.protocolMap[key]; found {
			ent = r.plugins[pluginName]
			ok = true
		}
	}

	if !ok || ent == nil {
		return StatusDisabled, "plugin not found", fmt.Errorf("plugin %q not found", nameOrProtocol)
	}
	return ent.status, ent.disableReason, ent.testError
}

// List returns a sorted list of registered plugin descriptions.
func List() []PluginInfo {
	return globalRegistry.List()
}

func (r *Registry) List() []PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []PluginInfo
	for _, ent := range r.plugins {
		m := ent.plugin.Manifest()
		testErrStr := ""
		if ent.testError != nil {
			testErrStr = ent.testError.Error()
		}
		list = append(list, PluginInfo{
			Name:          m.Name,
			Version:       m.Version,
			Description:   m.Description,
			Protocols:     m.Protocols,
			Enabled:       ent.enabled,
			Status:        ent.status,
			DisableReason: ent.disableReason,
			TestError:     testErrStr,
			TestTime:      ent.testTime,
		})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})

	return list
}

func safeSelfTest(p sdk.Plugin) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("plugin panicked during self-test: %v", r)
		}
	}()
	return p.SelfTest()
}
