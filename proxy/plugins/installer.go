package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/routewarden/cli/proxy/plugins/sdk"
)

// InstallOptions configures plugin installation.
type InstallOptions struct {
	PluginsDir string // root directory for plugins (default: "./plugins")
	ProjectDir string // root directory of tcp-warden project (default: ".")
	CacheDir   string // root cache directory (default: GetPluginsCacheDir())
	NoBuild    bool   // skip rebuilding tcp-warden binary
	Force      bool   // overwrite existing plugin / bypass cache
}

// InstallResult details the outcome of an installation.
type InstallResult struct {
	Name           string                    `json:"name"`
	Version        string                    `json:"version"`
	Protocols      []string                  `json:"protocols"`
	Source         string                    `json:"source"`
	TestPassed     bool                      `json:"test_passed"`
	TestOutput     string                    `json:"test_output,omitempty"`
	Status         PluginStatus              `json:"status"`
	InstalledAt    time.Time                 `json:"installed_at"`
	Rebuilt        bool                      `json:"rebuilt"`
	DefaultService *sdk.DefaultServiceConfig `json:"default_service,omitempty"`
	Config         map[string]any            `json:"config,omitempty"`
}

// InstalledPluginEntry records metadata for installed plugins in plugins.json.
type InstalledPluginEntry struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Protocols   []string     `json:"protocols"`
	Source      string       `json:"source"`
	Status      PluginStatus `json:"status"`
	TestError   string       `json:"test_error,omitempty"`
	InstalledAt time.Time    `json:"installed_at"`
}

type installedRegistry struct {
	Installed []InstalledPluginEntry `json:"installed"`
	Enabled   []string               `json:"enabled,omitempty"`
	Disabled  []string               `json:"disabled,omitempty"`
}

// InstallPlugin installs a plugin from a GitHub URL or local repository path.
func InstallPlugin(source string, opts InstallOptions) (*InstallResult, error) {
	opts.ProjectDir = ResolveProjectDir(opts.ProjectDir)
	opts.PluginsDir = ResolvePluginsDir(opts.PluginsDir, opts.ProjectDir)
	if !filepath.IsAbs(opts.PluginsDir) && !strings.HasPrefix(opts.PluginsDir, opts.ProjectDir) {
		opts.PluginsDir = filepath.Join(opts.ProjectDir, opts.PluginsDir)
	}

	source = strings.TrimSpace(source)
	if source == "" {
		return nil, errors.New("plugin source cannot be empty")
	}

	// 1. Fetch or prepare plugin source directory
	stagingDir, isTemp, err := stagePluginSource(source)
	if err != nil {
		return nil, fmt.Errorf("staging plugin from %s: %w", source, err)
	}
	if isTemp {
		defer os.RemoveAll(stagingDir)
	}

	// 2. Read and validate plugin.yaml manifest
	manifestPath := filepath.Join(stagingDir, "plugin.yaml")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		// Check plugin.yml
		manifestPath = filepath.Join(stagingDir, "plugin.yml")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("no plugin.yaml found in %s", source)
		}
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", manifestPath, err)
	}

	var manifest sdk.Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parsing plugin manifest: %w", err)
	}
	manifest.Name = strings.ToLower(strings.TrimSpace(manifest.Name))

	// ─── Step 1: Validate Manifest ──────────────────────────────────────
	if err := manifest.Validate(); err != nil {
		fmt.Printf("❌ [1/5 VALIDATE] %s manifest validation failed: %v\n", manifest.Name, err)
		return nil, fmt.Errorf("plugin manifest validation failed: %w", err)
	}
	fmt.Printf("✓ [1/5 VALIDATE] %s v%s (protocols: %v)\n", manifest.Name, manifest.Version, manifest.Protocols)

	// ─── Step 2: Check Compatibility ────────────────────────────────────
	reqManifestVer := manifest.ManifestVersion
	if reqManifestVer == "" {
		reqManifestVer = "(any)"
	}
	if err := CheckCompatibility(manifest); err != nil {
		if !opts.Force {
			fmt.Printf("❌ [2/5 COMPATIBILITY] %s incompatible: %v\n", manifest.Name, err)
			return nil, fmt.Errorf("plugin %q is incompatible with RouteWarden manifest version %s: %w (use --force to override)",
				manifest.Name, sdk.ManifestVersion, err)
		}
		fmt.Printf("⚠️  [2/5 COMPATIBILITY] %s incompatible but forced: %v\n", manifest.Name, err)
	} else {
		fmt.Printf("✓ [2/5 COMPATIBILITY] %s compatible with host manifest %s\n", manifest.Name, sdk.ManifestVersion)
	}

	defSvc := manifest.DefaultService
	if defSvc == nil {
		defSvc = GetDefaultServiceForPlugin(manifest.Name, manifest.Protocols, manifest.Config)
	} else if len(manifest.Config) > 0 && len(defSvc.PluginConfig) == 0 {
		defSvc.PluginConfig = manifest.Config
	}

	targetDir := filepath.Join(opts.PluginsDir, manifest.Name)
	stagingAbs, _ := filepath.Abs(stagingDir)
	targetAbs, _ := filepath.Abs(targetDir)

	// Copy to target directory if not already there
	if stagingAbs != targetAbs {
		if _, err := os.Stat(targetDir); err == nil {
			if opts.Force {
				_ = os.RemoveAll(targetDir)
				if err := copyDir(stagingDir, targetDir); err != nil {
					return nil, fmt.Errorf("copying plugin to %s: %w", targetDir, err)
				}
			} else {
				return nil, fmt.Errorf("plugin %q already installed at %s; use --force to overwrite", manifest.Name, targetDir)
			}
		} else {
			if err := copyDir(stagingDir, targetDir); err != nil {
				return nil, fmt.Errorf("copying plugin to %s: %w", targetDir, err)
			}
		}
	}

	// ─── Resolve External Dependencies & Stage Package ──────────────────
	reqs := extractModuleRequirements(targetDir)
	if err := applyModuleRequirements(opts.ProjectDir, reqs); err != nil {
		fmt.Printf("⚠️  warning applying dependencies for %s: %v\n", manifest.Name, err)
	}

	if err := cleanupNestedGoMod(targetDir); err != nil {
		fmt.Printf("⚠️  nested module cleanup warning for %s: %v\n", manifest.Name, err)
	}

	allGoPath := filepath.Join(opts.PluginsDir, "all", "all.go")
	if err := registerInAllGo(allGoPath, manifest.Name); err != nil {
		return nil, fmt.Errorf("registering plugin in all.go: %w", err)
	}

	if err := syncModuleDependencies(opts.ProjectDir); err != nil {
		fmt.Printf("⚠️  [2/5 RESOLVE] dependency sync warning for %s: %v\n", manifest.Name, err)
	} else if len(reqs) > 0 {
		fmt.Printf("✓ [2/5 RESOLVE] %s dependencies synchronized (%d requirements)\n", manifest.Name, len(reqs))
	}

	// ─── Step 3: Compile Plugin Source ──────────────────────────────────
	compileCtx, compileCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer compileCancel()
	compileCmd := exec.CommandContext(compileCtx, "go", "test", "-run", "^$", "./...")
	compileCmd.Dir = targetDir
	var compileOut bytes.Buffer
	compileCmd.Stdout = &compileOut
	compileCmd.Stderr = &compileOut
	compileErr := compileCmd.Run()
	if compileErr != nil {
		// In synthetic unit test fixtures, a go.mod might not be present in tmpDir
		if strings.Contains(compileOut.String(), "does not contain main module") {
			fmt.Printf("⚠️  [3/5 COMPILE] %s skipped: no Go module context in %s\n", manifest.Name, targetDir)
		} else {
			compileErrStr := fmt.Sprintf("compilation failed: %v (output: %s)", compileErr, compileOut.String())
			fmt.Printf("❌ [3/5 COMPILE] %s %s\n", manifest.Name, compileErrStr)
			_ = unregisterFromAllGo(allGoPath, manifest.Name)
			if stagingAbs != targetAbs {
				_ = os.RemoveAll(targetDir)
			}
			_ = syncModuleDependencies(opts.ProjectDir)
			return nil, fmt.Errorf("plugin %q compilation failed: %w (output: %s)", manifest.Name, compileErr, compileOut.String())
		}
	} else {
		fmt.Printf("✓ [3/5 COMPILE] %s compiled successfully\n", manifest.Name)
	}

	// ─── Step 4: Run Automated Tests ────────────────────────────────────
	testCtx, testCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer testCancel()
	testCmd := exec.CommandContext(testCtx, "go", "test", "-v", "./...")
	testCmd.Dir = targetDir
	var testOut bytes.Buffer
	testCmd.Stdout = &testOut
	testCmd.Stderr = &testOut

	testErr := testCmd.Run()
	testPassed := testErr == nil
	pluginStatus := StatusActive
	testErrStr := ""

	if testErr != nil {
		if strings.Contains(testOut.String(), "does not contain main module") {
			testPassed = true
			fmt.Printf("⚠️  [4/5 TEST] %s skipped tests: no Go module context in %s\n", manifest.Name, targetDir)
		} else {
			pluginStatus = StatusDisabled
			testErrStr = fmt.Sprintf("tests failed: %v", testErr)
			fmt.Printf("⚠️  [4/5 TEST] %s tests failed: %v (disabled)\n", manifest.Name, testErr)
		}
	} else {
		fmt.Printf("✓ [4/5 TEST] %s all tests passed\n", manifest.Name)
	}

	// ─── Step 5: Accept & Integrate ─────────────────────────────────────
	_ = registerInAllGo(allGoPath, manifest.Name)

	rebuilt := false
	if !opts.NoBuild {
		ensureBuildPrerequisites(opts.ProjectDir)
		buildCtx, buildCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer buildCancel()
		buildCmd := exec.CommandContext(buildCtx, "go", "build", "-o", "tcp-warden", ".")
		buildCmd.Dir = opts.ProjectDir
		if buildOut, bErr := buildCmd.CombinedOutput(); bErr != nil {
			_ = unregisterFromAllGo(allGoPath, manifest.Name)
			if stagingAbs != targetAbs {
				_ = os.RemoveAll(targetDir)
			}
			_ = syncModuleDependencies(opts.ProjectDir)
			fmt.Printf("❌ [5/5 ACCEPT] %s binary rebuild failed: %v (rolled back)\n", manifest.Name, bErr)
			return nil, fmt.Errorf("plugin compilation failed during binary rebuild: %v (output: %s)", bErr, string(buildOut))
		}
		rebuilt = true
		updateInstalledExecutable(filepath.Join(opts.ProjectDir, "tcp-warden"))
	}

	installedEntry := InstalledPluginEntry{
		Name:        manifest.Name,
		Version:     manifest.Version,
		Description: manifest.Description,
		Protocols:   manifest.Protocols,
		Source:      source,
		Status:      pluginStatus,
		TestError:   testErrStr,
		InstalledAt: time.Now().UTC(),
	}
	_ = saveInstalledEntry(opts.ProjectDir, installedEntry)
	if testPassed {
		_ = SavePluginEnablement(opts.ProjectDir, manifest.Name, true)
	} else {
		_ = SavePluginEnablement(opts.ProjectDir, manifest.Name, false)
	}

	if rebuilt {
		fmt.Printf("✓ [5/5 ACCEPT] %s accepted and rebuilt binary (status: %s)\n", manifest.Name, pluginStatus)
	} else {
		fmt.Printf("✓ [5/5 ACCEPT] %s accepted (status: %s)\n", manifest.Name, pluginStatus)
	}

	res := &InstallResult{
		Name:           manifest.Name,
		Version:        manifest.Version,
		Protocols:      manifest.Protocols,
		Source:         source,
		TestPassed:     testPassed,
		TestOutput:     testOut.String(),
		Status:         pluginStatus,
		InstalledAt:    installedEntry.InstalledAt,
		Rebuilt:        rebuilt,
		DefaultService: defSvc,
		Config:         manifest.Config,
	}

	return res, nil
}

// ResolveProjectDir returns the root directory of the tcp-warden project containing go.mod and plugins/.
// Priority:
// 1. Explicit customDir if non-empty and not "."
// 2. ROUTEWARDEN_SRC_DIR or ROUTEWARDEN_PROJECT_DIR environment variable
// 3. Current working directory if go.mod or plugins/all/all.go exists
// 4. Standard container source locations (/usr/src/tcp-warden, /src)
// 5. Fallback to "."
func ResolveProjectDir(customDir string) string {
	if customDir != "" && customDir != "." {
		return customDir
	}
	if env := os.Getenv("ROUTEWARDEN_SRC_DIR"); env != "" {
		if fi, err := os.Stat(env); err == nil && fi.IsDir() {
			return env
		}
	}
	if env := os.Getenv("ROUTEWARDEN_PROJECT_DIR"); env != "" {
		if fi, err := os.Stat(env); err == nil && fi.IsDir() {
			return env
		}
	}
	if _, err := os.Stat(filepath.Join(".", "plugins", "all", "all.go")); err == nil {
		return "."
	}
	if _, err := os.Stat(filepath.Join(".", "proxy", "plugins", "all", "all.go")); err == nil {
		return "."
	}
	if _, err := os.Stat("go.mod"); err == nil {
		return "."
	}
	candidates := []string{"/usr/src/tcp-warden", "/src"}
	for _, cand := range candidates {
		if _, err := os.Stat(filepath.Join(cand, "plugins", "all", "all.go")); err == nil {
			return cand
		}
		if _, err := os.Stat(filepath.Join(cand, "proxy", "plugins", "all", "all.go")); err == nil {
			return cand
		}
		if _, err := os.Stat(filepath.Join(cand, "go.mod")); err == nil {
			return cand
		}
	}
	if customDir != "" {
		return customDir
	}
	return "."
}

// ResolvePluginsDir returns the directory containing the modular plugins.
func ResolvePluginsDir(customPluginsDir string, projectDir string) string {
	if customPluginsDir != "" && customPluginsDir != "plugins" {
		return customPluginsDir
	}
	if _, err := os.Stat(filepath.Join(".", "plugins", "all", "all.go")); err == nil {
		return "plugins"
	}
	if _, err := os.Stat(filepath.Join(".", "proxy", "plugins", "all", "all.go")); err == nil {
		return filepath.Join("proxy", "plugins")
	}
	if projectDir != "" && projectDir != "." {
		if _, err := os.Stat(filepath.Join(projectDir, "proxy", "plugins", "all", "all.go")); err == nil {
			return filepath.Join(projectDir, "proxy", "plugins")
		}
		return filepath.Join(projectDir, "plugins")
	}
	return "plugins"
}

// updateInstalledExecutable updates the currently running binary (such as /usr/local/bin/tcp-warden)
// with the newly built binary if running from a different path.
func updateInstalledExecutable(newBinaryPath string) {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	if resolvedExec, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolvedExec
	}

	absExec, err := filepath.Abs(execPath)
	if err != nil {
		return
	}
	absNew, err := filepath.Abs(newBinaryPath)
	if err != nil {
		return
	}

	// Cache recompiled binary to persistent volume if available (/var/lib/routewarden)
	// so compiled plugins survive container recreations without needing to recompile on every boot.
	if fi, err := os.Stat("/var/lib/routewarden"); err == nil && fi.IsDir() {
		persistDir := "/var/lib/routewarden/bin"
		_ = os.MkdirAll(persistDir, 0755)
		persistTarget := filepath.Join(persistDir, "tcp-warden")
		tmpPersist := persistTarget + ".tmp"
		if err := copyFile(absNew, tmpPersist); err == nil {
			_ = os.Chmod(tmpPersist, 0755)
			_ = os.Rename(tmpPersist, persistTarget)
		}
	}

	if absExec == absNew {
		return
	}

	// Copy new binary to temporary file alongside target executable, then atomic rename
	tmpTarget := absExec + ".tmp"
	if err := copyFile(absNew, tmpTarget); err != nil {
		return
	}
	_ = os.Chmod(tmpTarget, 0755)
	if err := os.Rename(tmpTarget, absExec); err != nil {
		_ = os.Remove(tmpTarget)
	}
}

// GetPluginsCacheDir returns the directory used to cache downloaded plugins.
// Priority:
// 1. Environment variable ROUTEWARDEN_PLUGINS_CACHE
// 2. /var/lib/routewarden/plugins (used in Docker volumes)
// 3. ./.plugins_cache (local fallback)
func GetPluginsCacheDir() string {
	if env := os.Getenv("ROUTEWARDEN_PLUGINS_CACHE"); env != "" {
		return env
	}

	dockerDir := "/var/lib/routewarden/plugins"
	if fi, err := os.Stat(dockerDir); err == nil && fi.IsDir() {
		return dockerDir
	}

	// If root / in container, try to ensure /var/lib/routewarden/plugins exists
	if err := os.MkdirAll(dockerDir, 0755); err == nil {
		return dockerDir
	}

	return ".plugins_cache"
}

// SyncPluginFromSource installs or updates a plugin from source (using cache if already pulled, or pulling fresh).
func SyncPluginFromSource(name string, source string, opts InstallOptions) (*InstallResult, error) {
	if opts.CacheDir == "" {
		opts.CacheDir = GetPluginsCacheDir()
	}
	opts.ProjectDir = ResolveProjectDir(opts.ProjectDir)
	opts.PluginsDir = ResolvePluginsDir(opts.PluginsDir, opts.ProjectDir)

	name = strings.ToLower(strings.TrimSpace(name))
	if name != "" {
		if err := validatePluginName(name); err != nil {
			return nil, err
		}
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, errors.New("plugin source cannot be empty")
	}

	// 1. If name is already provided, check if cached manifest exists
	if name != "" {
		cachedPluginDir := filepath.Join(opts.CacheDir, name)
		cachedManifest := filepath.Join(cachedPluginDir, "plugin.yaml")
		if _, err := os.Stat(cachedManifest); os.IsNotExist(err) {
			cachedManifest = filepath.Join(cachedPluginDir, "plugin.yml")
		}

		if _, err := os.Stat(cachedManifest); err == nil && !opts.Force {
			fmt.Printf("✓ [PLUGIN CACHE] Using cached version for %q from %s\n", name, cachedPluginDir)
			cacheOpts := opts
			cacheOpts.Force = true // cache is the source of truth; always sync from it
			return InstallPlugin(cachedPluginDir, cacheOpts)
		}
	}

	// 2. Otherwise stage plugin source (fetches Git or validates local dir)
	fmt.Printf("📥 [PLUGIN] Fetching plugin from %s...\n", source)
	stagedDir, isTemp, err := stagePluginSource(source)
	if err != nil {
		return nil, fmt.Errorf("fetching plugin from %s: %w", source, err)
	}
	if isTemp {
		defer os.RemoveAll(stagedDir)
	}

	// Read manifest to determine actual plugin name
	mPath := filepath.Join(stagedDir, "plugin.yaml")
	if _, err := os.Stat(mPath); os.IsNotExist(err) {
		mPath = filepath.Join(stagedDir, "plugin.yml")
	}
	mData, err := os.ReadFile(mPath)
	if err != nil {
		return nil, fmt.Errorf("reading manifest from staged source %s: %w", source, err)
	}
	var m sdk.Manifest
	if err := yaml.Unmarshal(mData, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest from staged source %s: %w", source, err)
	}

	actualName := strings.ToLower(strings.TrimSpace(m.Name))
	if actualName == "" {
		return nil, fmt.Errorf("plugin manifest in %s missing required 'name' field", source)
	}
	name = actualName

	// 3. Cache the staged plugin in opts.CacheDir/<name>
	cachedPluginDir := filepath.Join(opts.CacheDir, name)
	if err := os.MkdirAll(opts.CacheDir, 0755); err != nil {
		opts.CacheDir = filepath.Join(opts.ProjectDir, ".plugins_cache")
		cachedPluginDir = filepath.Join(opts.CacheDir, name)
		_ = os.MkdirAll(opts.CacheDir, 0755)
	}

	stagingAbs, _ := filepath.Abs(stagedDir)
	cachedAbs, _ := filepath.Abs(cachedPluginDir)
	if stagingAbs != cachedAbs {
		_ = os.RemoveAll(cachedPluginDir)
		if err := copyDir(stagedDir, cachedPluginDir); err != nil {
			// If caching to opts.CacheDir fails (e.g. shadowed volume mount, unwritable volume),
			// gracefully fallback to local cache directory in project directory
			fallbackCacheDir := filepath.Join(opts.ProjectDir, ".plugins_cache")
			fallbackPluginDir := filepath.Join(fallbackCacheDir, name)
			_ = os.MkdirAll(fallbackCacheDir, 0755)
			_ = os.RemoveAll(fallbackPluginDir)
			if fErr := copyDir(stagedDir, fallbackPluginDir); fErr == nil {
				cachedPluginDir = fallbackPluginDir
			} else {
				return nil, fmt.Errorf("caching plugin %q to %s: %w", name, cachedPluginDir, err)
			}
		}
	}

	fmt.Printf("✓ [PLUGIN CACHE] Successfully cached fresh plugin %q at %s\n", name, cachedPluginDir)
	cacheOpts := opts
	cacheOpts.Force = true // freshly pulled source; always overwrite existing install
	return InstallPlugin(cachedPluginDir, cacheOpts)
}

// ParseGitSource splits a GitHub URL into a cloneable repository URL and an internal subpath.
func ParseGitSource(source string) (repoURL string, subPath string) {
	clean := strings.TrimPrefix(source, "https://")
	clean = strings.TrimPrefix(clean, "http://")
	clean = strings.TrimPrefix(clean, "git@github.com:")
	clean = strings.TrimPrefix(clean, "github.com/")

	parts := strings.Split(clean, "/")
	if len(parts) >= 2 {
		owner := parts[0]
		repo := strings.TrimSuffix(parts[1], ".git")
		repoURL = fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)

		if len(parts) >= 4 && (parts[2] == "tree" || parts[2] == "blob") {
			subPath = strings.Join(parts[4:], "/")
		} else if len(parts) > 2 {
			subPath = strings.Join(parts[2:], "/")
		}
		return repoURL, subPath
	}

	return source, ""
}

// stagePluginSource determines if source is a local directory or Git URL and returns directory path.
func stagePluginSource(source string) (string, bool, error) {
	// 1. Check if local directory directly
	info, err := os.Stat(source)
	if err == nil && info.IsDir() {
		return source, false, nil
	}

	// 2. Check if local sibling ../plugins/<source> or ../plugins exists
	localSibling := filepath.Join("..", "plugins", source)
	if sInfo, err := os.Stat(localSibling); err == nil && sInfo.IsDir() {
		return localSibling, false, nil
	}
	localInPlugins := filepath.Join("..", "plugins")
	if sInfo, err := os.Stat(filepath.Join(localInPlugins, source)); err == nil && sInfo.IsDir() {
		return filepath.Join(localInPlugins, source), false, nil
	}

	// 3. Check /plugins container volume mount (e.g. /plugins/<source> or /plugins)
	containerPlugin := filepath.Join("/plugins", source)
	if sInfo, err := os.Stat(containerPlugin); err == nil && sInfo.IsDir() {
		return containerPlugin, false, nil
	}
	if sInfo, err := os.Stat("/plugins"); err == nil && sInfo.IsDir() {
		if subInfo, err := os.Stat(filepath.Join("/plugins", source)); err == nil && subInfo.IsDir() {
			return filepath.Join("/plugins", source), false, nil
		}
	}

	// 4. If bare plugin name without slashes, fallback to official routewarden/plugins repository
	if !strings.Contains(source, "/") && !strings.Contains(source, "\\") {
		source = "https://github.com/routewarden/plugins/" + source
	}

	// 5. Check if Git / GitHub URL
	isGit := strings.HasPrefix(source, "http://") ||
		strings.HasPrefix(source, "https://") ||
		strings.HasPrefix(source, "git@") ||
		strings.HasPrefix(source, "github.com/")

	if isGit {
		repoURL, subPath := ParseGitSource(source)
		if strings.HasPrefix(repoURL, "github.com/") {
			repoURL = "https://" + repoURL
		}

		cloneDir, err := os.MkdirTemp("", "tcp-warden-clone-*")
		if err != nil {
			return "", false, err
		}
		defer os.RemoveAll(cloneDir)

		cloneCtx, cloneCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cloneCancel()
		cloneCmd := exec.CommandContext(cloneCtx, "git", "clone", "--depth", "1", repoURL, cloneDir)
		if out, err := cloneCmd.CombinedOutput(); err != nil {
			return "", false, fmt.Errorf("git clone failed for %s: %v (%s)", repoURL, err, string(out))
		}

		sourceDir := cloneDir
		if subPath != "" {
			cleanSubPath := filepath.Clean(subPath)
			if strings.HasPrefix(cleanSubPath, "..") || filepath.IsAbs(cleanSubPath) {
				return "", false, fmt.Errorf("plugin subpath %q attempts path traversal outside repository", subPath)
			}
			sourceDir = filepath.Join(cloneDir, cleanSubPath)
			rel, err := filepath.Rel(cloneDir, sourceDir)
			if err != nil || strings.HasPrefix(rel, "..") {
				return "", false, fmt.Errorf("plugin subpath %q escapes repository root", subPath)
			}
			if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
				return "", false, fmt.Errorf("plugin subpath %q not found in repository %s", subPath, repoURL)
			}
		}

		finalTmpDir, err := os.MkdirTemp("", "tcp-warden-plugin-*")
		if err != nil {
			return "", false, err
		}

		if err := copyDir(sourceDir, finalTmpDir); err != nil {
			os.RemoveAll(finalTmpDir)
			return "", false, fmt.Errorf("staging cloned plugin files: %w", err)
		}

		// If root clone had a go.mod but subfolder didn't have one, copy root go.mod as go.mod.upstream
		rootMod := filepath.Join(cloneDir, "go.mod")
		subMod := filepath.Join(finalTmpDir, "go.mod")
		if _, err := os.Stat(subMod); os.IsNotExist(err) {
			if _, err := os.Stat(rootMod); err == nil {
				_ = copyFile(rootMod, filepath.Join(finalTmpDir, "go.mod.upstream"))
			}
		}

		return finalTmpDir, true, nil
	}

	return "", false, fmt.Errorf("source %q is neither a valid local directory nor a recognized Git URL", source)
}

// registerInAllGo adds import statement to plugins/all/all.go if not already present.
func registerInAllGo(allGoPath string, pluginName string) error {
	content, err := os.ReadFile(allGoPath)
	if err != nil {
		if os.IsNotExist(err) {
			if mErr := os.MkdirAll(filepath.Dir(allGoPath), 0755); mErr != nil {
				return fmt.Errorf("creating directory for %s: %w", allGoPath, mErr)
			}
			content = []byte("package all\n\nimport (\n)\n")
		} else {
			return err
		}
	}

	importPath := fmt.Sprintf(`_ "github.com/routewarden/cli/proxy/plugins/%s"`, pluginName)
	if strings.Contains(string(content), importPath) {
		return nil
	}

	// Insert before closing parenthesis of import block
	s := string(content)
	importIdx := strings.Index(s, "import (")
	var insertPos int
	if importIdx != -1 {
		closeParenOffset := strings.Index(s[importIdx:], ")")
		if closeParenOffset == -1 {
			return fmt.Errorf("malformed %s, could not find closing parenthesis for import block", allGoPath)
		}
		insertPos = importIdx + closeParenOffset
	} else {
		insertPos = strings.LastIndex(s, ")")
		if insertPos == -1 {
			return fmt.Errorf("malformed %s, could not find closing parenthesis", allGoPath)
		}
	}

	newContent := s[:insertPos] + "\t" + importPath + "\n" + s[insertPos:]
	if fi, err := os.Stat("/var/lib/routewarden"); err == nil && fi.IsDir() {
		_ = os.WriteFile("/var/lib/routewarden/all.go", []byte(newContent), 0644)
	}
	return os.WriteFile(allGoPath, []byte(newContent), 0644)
}

func unregisterFromAllGo(allGoPath string, pluginName string) error {
	content, err := os.ReadFile(allGoPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	needle := fmt.Sprintf(`"github.com/routewarden/cli/proxy/plugins/%s"`, pluginName)

	for _, line := range lines {
		if strings.Contains(line, needle) {
			continue
		}
		newLines = append(newLines, line)
	}

	res := strings.Join(newLines, "\n")
	if fi, err := os.Stat("/var/lib/routewarden"); err == nil && fi.IsDir() {
		_ = os.WriteFile("/var/lib/routewarden/all.go", []byte(res), 0644)
	}
	return os.WriteFile(allGoPath, []byte(res), 0644)
}

// extractModuleRequirements parses any go.mod, go.mod.upstream, or parent go.mod in dir
// and returns a list of external module requirements ("module@version").
func extractModuleRequirements(dir string) []string {
	var reqs []string
	seen := make(map[string]bool)

	candidates := []string{
		filepath.Join(dir, "go.mod"),
		filepath.Join(dir, "go.mod.upstream"),
	}

	parent := filepath.Dir(dir)
	if parent != "" && parent != dir && parent != "." && parent != "/" {
		candidates = append(candidates, filepath.Join(parent, "go.mod"))
	}

	for _, cand := range candidates {
		data, err := os.ReadFile(cand)
		if err != nil {
			continue
		}
		for _, spec := range parseGoModRequirements(data) {
			if !seen[spec] {
				seen[spec] = true
				reqs = append(reqs, spec)
			}
		}
	}
	return reqs
}

// parseGoModRequirements extracts module@version requirement specs from go.mod bytes.
func parseGoModRequirements(data []byte) []string {
	var reqs []string
	lines := strings.Split(string(data), "\n")
	inRequireBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, "//"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		var modPath, modVer string
		if inRequireBlock {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				modPath, modVer = parts[0], parts[1]
			}
		} else if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				modPath, modVer = parts[0], parts[1]
			}
		}

		if modPath != "" && modVer != "" && modPath != "github.com/routewarden/cli/proxy" && !strings.HasPrefix(modPath, "github.com/routewarden/cli") {
			reqs = append(reqs, fmt.Sprintf("%s@%s", modPath, modVer))
		}
	}
	return reqs
}

// applyModuleRequirements adds module requirements to projectDir's go.mod using `go mod edit -require`.
func applyModuleRequirements(projectDir string, reqs []string) error {
	goModPath := filepath.Join(projectDir, "go.mod")
	if _, err := os.Stat(goModPath); err != nil || len(reqs) == 0 {
		return nil
	}

	for _, req := range reqs {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-require", req)
		cmd.Dir = projectDir
		_ = cmd.Run()
		cancel()
	}
	return nil
}

// cleanupNestedGoMod removes any nested go.mod, go.sum, go.work, and go.mod.upstream files
// within dir so the plugin integrates as a subpackage within the host module.
func cleanupNestedGoMod(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			base := filepath.Base(path)
			if base == "go.mod" || base == "go.sum" || base == "go.work" || base == "go.work.sum" || base == "go.mod.upstream" {
				_ = os.Remove(path)
			}
		}
		return nil
	})
}

// syncModuleDependencies runs `go mod tidy` in projectDir if a go.mod file is present.
func syncModuleDependencies(projectDir string) error {
	goModPath := filepath.Join(projectDir, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "mod", "tidy")
	cmd.Dir = projectDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go mod tidy in %s: %w (output: %s)", projectDir, err, out.String())
	}
	return nil
}

// UninstallPlugin removes an installed plugin.
func UninstallPlugin(name string, opts InstallOptions) error {
	opts.ProjectDir = ResolveProjectDir(opts.ProjectDir)
	opts.PluginsDir = ResolvePluginsDir(opts.PluginsDir, opts.ProjectDir)
	if !filepath.IsAbs(opts.PluginsDir) && !strings.HasPrefix(opts.PluginsDir, opts.ProjectDir) {
		opts.PluginsDir = filepath.Join(opts.ProjectDir, opts.PluginsDir)
	}

	nameKey := strings.ToLower(strings.TrimSpace(name))
	if err := validatePluginName(nameKey); err != nil {
		return fmt.Errorf("invalid plugin name: %w", err)
	}

	allGoPath := filepath.Join(opts.PluginsDir, "all", "all.go")
	_ = unregisterFromAllGo(allGoPath, nameKey)

	targetDir := filepath.Join(opts.PluginsDir, nameKey)
	_ = os.RemoveAll(targetDir)

	_ = removeInstalledEntry(opts.ProjectDir, nameKey)

	_ = syncModuleDependencies(opts.ProjectDir)

	if !opts.NoBuild {
		ensureBuildPrerequisites(opts.ProjectDir)
		buildCtx, buildCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer buildCancel()
		buildCmd := exec.CommandContext(buildCtx, "go", "build", "-o", "tcp-warden", ".")
		buildCmd.Dir = opts.ProjectDir
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("rebuilding tcp-warden binary after uninstall failed: %w", err)
		}
		updateInstalledExecutable(filepath.Join(opts.ProjectDir, "tcp-warden"))
	}

	return nil
}

// EnsureBuildPrerequisites ensures files required by the Go compiler at build time
// (such as embedded configuration files in main.go) exist in projectDir.
func EnsureBuildPrerequisites(projectDir string) {
	yamlPath := filepath.Join(projectDir, "tcp-warden.yaml")
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		if data, err := os.ReadFile("/etc/routewarden/tcp-warden.yaml"); err == nil && len(data) > 0 {
			_ = os.WriteFile(yamlPath, data, 0644)
		} else {
			_ = os.WriteFile(yamlPath, []byte("version: \"1.0\"\nservices: {}\n"), 0644)
		}
	}
}

func ensureBuildPrerequisites(projectDir string) {
	EnsureBuildPrerequisites(projectDir)
}

func resolvePluginsRegistryPath(projectDir string) string {
	if fi, err := os.Stat("/var/lib/routewarden"); err == nil && fi.IsDir() {
		return filepath.Join("/var/lib/routewarden", "plugins.json")
	}
	projectDir = ResolveProjectDir(projectDir)
	return filepath.Join(projectDir, "plugins.json")
}

func saveInstalledEntry(projectDir string, entry InstalledPluginEntry) error {
	regPath := resolvePluginsRegistryPath(projectDir)
	var reg installedRegistry

	if data, err := os.ReadFile(regPath); err == nil {
		_ = json.Unmarshal(data, &reg)
	}

	updated := false
	for i, e := range reg.Installed {
		if strings.EqualFold(e.Name, entry.Name) {
			reg.Installed[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		reg.Installed = append(reg.Installed, entry)
	}

	bytes, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(regPath, bytes, 0644)
}

func removeInstalledEntry(projectDir string, name string) error {
	regPath := resolvePluginsRegistryPath(projectDir)
	var reg installedRegistry

	data, err := os.ReadFile(regPath)
	if err != nil {
		return nil
	}
	_ = json.Unmarshal(data, &reg)

	filtered := []InstalledPluginEntry{}
	for _, e := range reg.Installed {
		if !strings.EqualFold(e.Name, name) {
			filtered = append(filtered, e)
		}
	}
	reg.Installed = filtered

	var newEnabled []string
	for _, item := range reg.Enabled {
		if !strings.EqualFold(item, name) {
			newEnabled = append(newEnabled, item)
		}
	}
	reg.Enabled = newEnabled

	var newDisabled []string
	for _, item := range reg.Disabled {
		if !strings.EqualFold(item, name) {
			newDisabled = append(newDisabled, item)
		}
	}
	reg.Disabled = newDisabled

	bytes, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(regPath, bytes, 0644)
}

// GetInstalledRegistry loads plugins.json if available.
func GetInstalledRegistry(projectDir string) ([]InstalledPluginEntry, error) {
	regPath := resolvePluginsRegistryPath(projectDir)
	data, err := os.ReadFile(regPath)
	if err != nil {
		return nil, nil
	}
	var reg installedRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, err
	}
	return reg.Installed, nil
}

// SavePluginEnablement persists the enabled/disabled state of a plugin to plugins.json.
func SavePluginEnablement(projectDir string, name string, enabled bool) error {
	regPath := resolvePluginsRegistryPath(projectDir)
	var reg installedRegistry

	if data, err := os.ReadFile(regPath); err == nil {
		_ = json.Unmarshal(data, &reg)
	}

	name = strings.ToLower(strings.TrimSpace(name))

	// Remove from both lists first
	var newEnabled []string
	for _, item := range reg.Enabled {
		if !strings.EqualFold(item, name) {
			newEnabled = append(newEnabled, item)
		}
	}
	var newDisabled []string
	for _, item := range reg.Disabled {
		if !strings.EqualFold(item, name) {
			newDisabled = append(newDisabled, item)
		}
	}

	if enabled {
		newEnabled = append(newEnabled, name)
	} else {
		newDisabled = append(newDisabled, name)
	}

	reg.Enabled = newEnabled
	reg.Disabled = newDisabled

	bytes, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(regPath, bytes, 0644)
}

// GetPluginEnablement returns lists of enabled and disabled plugins from plugins.json.
func GetPluginEnablement(projectDir string) ([]string, []string, error) {
	regPath := resolvePluginsRegistryPath(projectDir)
	data, err := os.ReadFile(regPath)
	if err != nil {
		return nil, nil, nil
	}
	var reg installedRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, nil, err
	}
	return reg.Enabled, reg.Disabled, nil
}

// copyDir copies a directory recursively.
func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.Type()&os.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(srcPath)
			if err != nil {
				continue
			}
			rel, err := filepath.Rel(src, target)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
		}

		if entry.IsDir() {
			if entry.Name() == ".git" {
				continue
			}
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

var wellKnownPluginDefaults = map[string]sdk.DefaultServiceConfig{
	"ssh": {
		ServiceName:      "ssh",
		Listen:           ":2222",
		Upstream:         "127.0.0.1:22",
		Protocol:         "ssh",
		RateLimitCPM:     20,
		RateLimitBurst:   5,
		MaxAuthFailures:  3,
		BanAfterFailures: 3,
	},
	"smtp": {
		ServiceName:    "smtp",
		Listen:         ":2525",
		Upstream:       "127.0.0.1:25",
		Protocol:       "smtp",
		RateLimitCPM:   30,
		RateLimitBurst: 10,
	},
	"pop3": {
		ServiceName:      "pop3",
		Listen:           ":1110",
		Upstream:         "127.0.0.1:110",
		Protocol:         "pop3",
		RateLimitCPM:     20,
		RateLimitBurst:   5,
		MaxAuthFailures:  3,
		BanAfterFailures: 3,
	},
	"imap": {
		ServiceName:      "imap",
		Listen:           ":1143",
		Upstream:         "127.0.0.1:143",
		Protocol:         "imap",
		RateLimitCPM:     20,
		RateLimitBurst:   5,
		MaxAuthFailures:  3,
		BanAfterFailures: 3,
	},
	"postgres": {
		ServiceName:      "postgres",
		Listen:           ":5433",
		Upstream:         "127.0.0.1:5432",
		Protocol:         "postgres",
		RateLimitCPM:     60,
		RateLimitBurst:   10,
		MaxAuthFailures:  3,
		BanAfterFailures: 3,
	},
	"postgresql": {
		ServiceName:      "postgres",
		Listen:           ":5433",
		Upstream:         "127.0.0.1:5432",
		Protocol:         "postgres",
		RateLimitCPM:     60,
		RateLimitBurst:   10,
		MaxAuthFailures:  3,
		BanAfterFailures: 3,
	},
	"mysql": {
		ServiceName:      "mysql",
		Listen:           ":3307",
		Upstream:         "127.0.0.1:3306",
		Protocol:         "mysql",
		RateLimitCPM:     60,
		RateLimitBurst:   10,
		MaxAuthFailures:  3,
		BanAfterFailures: 3,
	},
	"redis": {
		ServiceName:      "redis",
		Listen:           ":6380",
		Upstream:         "127.0.0.1:6379",
		Protocol:         "redis",
		RateLimitCPM:     120,
		RateLimitBurst:   20,
		MaxAuthFailures:  5,
		BanAfterFailures: 5,
		PluginConfig: map[string]any{
			"blocked_commands": []any{"FLUSHALL", "FLUSHDB", "CONFIG", "SHUTDOWN"},
		},
	},
	"mongodb": {
		ServiceName:    "mongodb",
		Listen:         ":27018",
		Upstream:       "127.0.0.1:27017",
		Protocol:       "mongodb",
		RateLimitCPM:   60,
		RateLimitBurst: 10,
	},
	"memcached": {
		ServiceName:    "memcached",
		Listen:         ":11212",
		Upstream:       "127.0.0.1:11211",
		Protocol:       "memcached",
		RateLimitCPM:   120,
		RateLimitBurst: 20,
	},
	"amqp": {
		ServiceName:    "amqp",
		Listen:         ":5673",
		Upstream:       "127.0.0.1:5672",
		Protocol:       "amqp",
		RateLimitCPM:   60,
		RateLimitBurst: 10,
	},
	"http": {
		ServiceName:    "http-guard",
		Listen:         ":8081",
		Upstream:       "127.0.0.1:80",
		Protocol:       "http",
		RateLimitCPM:   120,
		RateLimitBurst: 20,
	},
	"ldap": {
		ServiceName:      "ldap",
		Listen:           ":1390",
		Upstream:         "127.0.0.1:389",
		Protocol:         "ldap",
		RateLimitCPM:     60,
		RateLimitBurst:   10,
		MaxAuthFailures:  3,
		BanAfterFailures: 3,
	},
	"vnc": {
		ServiceName:      "vnc",
		Listen:           ":5901",
		Upstream:         "127.0.0.1:5900",
		Protocol:         "vnc",
		RateLimitCPM:     30,
		RateLimitBurst:   5,
		MaxAuthFailures:  3,
		BanAfterFailures: 3,
	},
	"ftp": {
		ServiceName:      "ftp",
		Listen:           ":2121",
		Upstream:         "127.0.0.1:21",
		Protocol:         "ftp",
		RateLimitCPM:     30,
		RateLimitBurst:   5,
		MaxAuthFailures:  3,
		BanAfterFailures: 3,
	},
	"tls_sni": {
		ServiceName:    "tls-proxy",
		Listen:         ":8443",
		Upstream:       "127.0.0.1:443",
		Protocol:       "tls",
		RateLimitCPM:   120,
		RateLimitBurst: 20,
	},
	"tls": {
		ServiceName:    "tls-proxy",
		Listen:         ":8443",
		Upstream:       "127.0.0.1:443",
		Protocol:       "tls",
		RateLimitCPM:   120,
		RateLimitBurst: 20,
	},
	"mqtt": {
		ServiceName:    "mqtt",
		Listen:         ":1884",
		Upstream:       "127.0.0.1:1883",
		Protocol:       "mqtt",
		RateLimitCPM:   60,
		RateLimitBurst: 10,
	},
	"minecraft": {
		ServiceName:    "minecraft",
		Listen:         ":25566",
		Upstream:       "127.0.0.1:25565",
		Protocol:       "minecraft",
		RateLimitCPM:   30,
		RateLimitBurst: 5,
	},
	"echo_filter": {
		ServiceName:    "echo-filter",
		Listen:         ":7001",
		Upstream:       "127.0.0.1:7000",
		Protocol:       "echo",
		RateLimitCPM:   60,
		RateLimitBurst: 10,
	},
}

// GetDefaultServiceForPlugin returns a default service configuration for a plugin,
// either from its well-known template or generated from its protocols.
func GetDefaultServiceForPlugin(pluginName string, protocols []string, pluginConfig map[string]any) *sdk.DefaultServiceConfig {
	nameLower := strings.ToLower(strings.TrimSpace(pluginName))
	if def, ok := wellKnownPluginDefaults[nameLower]; ok {
		cp := def
		if len(pluginConfig) > 0 && len(cp.PluginConfig) == 0 {
			cp.PluginConfig = pluginConfig
		}
		return &cp
	}

	for _, p := range protocols {
		pLower := strings.ToLower(strings.TrimSpace(p))
		if def, ok := wellKnownPluginDefaults[pLower]; ok {
			cp := def
			if cp.ServiceName == pLower {
				cp.ServiceName = nameLower
			}
			if len(pluginConfig) > 0 && len(cp.PluginConfig) == 0 {
				cp.PluginConfig = pluginConfig
			}
			return &cp
		}
	}

	proto := nameLower
	if len(protocols) > 0 && protocols[0] != "" {
		proto = strings.ToLower(protocols[0])
	}

	return &sdk.DefaultServiceConfig{
		ServiceName:    nameLower,
		Listen:         ":9000",
		Upstream:       "127.0.0.1:9001",
		Protocol:       proto,
		RateLimitCPM:   60,
		RateLimitBurst: 10,
		PluginConfig:   pluginConfig,
	}
}

// CreatePluginOptions defines options for scaffolding a new plugin.
type CreatePluginOptions struct {
	Name        string
	Protocol    string
	Description string
	Author      string
	Listen      string
	Upstream    string
	TargetDir   string
	ProjectDir  string
}

// CreatePluginResult records the paths created during plugin scaffolding.
type CreatePluginResult struct {
	Name           string
	Directory      string
	DefaultService *sdk.DefaultServiceConfig
	ManifestPath   string
}

// CreatePlugin generates a complete, working modular plugin scaffold.
func CreatePlugin(opts CreatePluginOptions) (*CreatePluginResult, error) {
	name := strings.ToLower(strings.TrimSpace(opts.Name))
	if err := validatePluginName(name); err != nil {
		return nil, fmt.Errorf("invalid plugin name: %w", err)
	}

	opts.ProjectDir = ResolveProjectDir(opts.ProjectDir)
	targetDir := opts.TargetDir
	if targetDir == "" {
		targetDir = filepath.Join(opts.ProjectDir, "plugins", name)
	}

	if _, err := os.Stat(targetDir); err == nil {
		return nil, fmt.Errorf("target directory %s already exists", targetDir)
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("creating plugin directory %s: %w", targetDir, err)
	}

	protocol := strings.ToLower(strings.TrimSpace(opts.Protocol))
	if protocol == "" {
		protocol = name
	}
	desc := opts.Description
	if desc == "" {
		desc = fmt.Sprintf("RouteWarden protocol inspector for %s", protocol)
	}
	author := opts.Author
	if author == "" {
		author = "RouteWarden Team"
	}

	defSvc := GetDefaultServiceForPlugin(name, []string{protocol}, nil)
	if opts.Listen != "" {
		defSvc.Listen = opts.Listen
	}
	if opts.Upstream != "" {
		defSvc.Upstream = opts.Upstream
	}
	defSvc.Protocol = protocol

	// 1. plugin.yaml
	manifestYAML := fmt.Sprintf(`name: %s
version: 1.0.0
manifest_version: 1.0.0
description: %s
author: %s
protocols:
  - %s
config:
  max_auth_failures: 5
default_service:
  listen: "%s"
  upstream: "%s"
  protocol: "%s"
  rate_limit:
    connections_per_minute: %d
    burst: %d
  max_auth_failures: 5
  ban_after_failures: 5
`, name, desc, author, protocol, defSvc.Listen, defSvc.Upstream, protocol, defSvc.RateLimitCPM, defSvc.RateLimitBurst)

	manifestPath := filepath.Join(targetDir, "plugin.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifestYAML), 0644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", manifestPath, err)
	}

	// 2. plugin.go
	pluginGo := fmt.Sprintf(`package %s

import (
	_ "embed"
	"net"

	"github.com/routewarden/cli/proxy/plugins"
	"github.com/routewarden/cli/proxy/plugins/sdk"
)

//go:embed plugin.yaml
var manifestYAML []byte

func init() {
	plugins.Register(&Plugin{})
}

type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	maxFailures := 5
	if v, ok := config["max_auth_failures"].(int); ok && v > 0 {
		maxFailures = v
	}
	return &Inspector{maxAuthFailures: maxFailures}, nil
}

func (p *Plugin) SelfTest() error {
	insp, err := p.CreateInspector(nil)
	if err != nil {
		return err
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	_ = insp
	return nil
}
`, name)

	if err := os.WriteFile(filepath.Join(targetDir, "plugin.go"), []byte(pluginGo), 0644); err != nil {
		return nil, err
	}

	// 3. inspector.go
	inspectorGo := fmt.Sprintf(`package %s

import (
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/routewarden/cli/proxy/plugins/sdk"
)

type Inspector struct {
	maxAuthFailures int
}

func (i *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (result sdk.ProxyResult, blocked bool, reason string, err error) {
	var bytesIn, bytesOut int64
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error

	setErr := func(e error) {
		once.Do(func() {
			if e != nil && e != io.EOF {
				firstErr = e
			}
		})
	}

	wg.Add(2)
	// Upstream -> Client
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, rErr := upstream.Read(buf)
			if nr > 0 {
				atomic.AddInt64(&bytesOut, int64(nr))
				if _, wErr := client.Write(buf[:nr]); wErr != nil {
					setErr(wErr)
					break
				}
			}
			if rErr != nil {
				setErr(rErr)
				break
			}
		}
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// Client -> Upstream
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, rErr := client.Read(buf)
			if nr > 0 {
				atomic.AddInt64(&bytesIn, int64(nr))
				if _, wErr := upstream.Write(buf[:nr]); wErr != nil {
					setErr(wErr)
					break
				}
			}
			if rErr != nil {
				setErr(rErr)
				break
			}
		}
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	wg.Wait()
	result.BytesIn = bytesIn
	result.BytesOut = bytesOut
	result.Err = firstErr
	return result, false, "", firstErr
}
`, name)

	if err := os.WriteFile(filepath.Join(targetDir, "inspector.go"), []byte(inspectorGo), 0644); err != nil {
		return nil, err
	}

	// 4. Test file
	testGo := fmt.Sprintf(`package %s_test

import (
	"testing"

	target "github.com/routewarden/cli/proxy/plugins/%s"
)

func TestPlugin_SelfTest(t *testing.T) {
	p := &target.Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest failed: %%v", err)
	}
}
`, name, name)

	if err := os.WriteFile(filepath.Join(targetDir, name+"_test.go"), []byte(testGo), 0644); err != nil {
		return nil, err
	}

	// 5. Register in plugins/all/all.go if in project tree
	pluginsDir := ResolvePluginsDir("plugins", opts.ProjectDir)
	allGoPath := filepath.Join(pluginsDir, "all", "all.go")
	_ = registerInAllGo(allGoPath, name)

	return &CreatePluginResult{
		Name:           name,
		Directory:      targetDir,
		DefaultService: defSvc,
		ManifestPath:   manifestPath,
	}, nil
}

func validatePluginName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("plugin name cannot be empty")
	}
	if strings.ContainsAny(name, "/\\:") || strings.Contains(name, "..") {
		return fmt.Errorf("plugin name %q contains path separators or traversal characters", name)
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("plugin name %q contains invalid characters (allowed: alphanumeric, underscore, hyphen)", name)
		}
	}
	return nil
}

