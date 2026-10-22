package plugins_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routewarden/cli/proxy/plugins"
)

func TestInstallPlugin_FromLocalRepo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-install-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockPluginDir := filepath.Join(tmpDir, "mock_plugin")
	if err := os.MkdirAll(mockPluginDir, 0755); err != nil {
		t.Fatal(err)
	}

	manifestContent := `name: mock_plugin
version: 1.2.0
description: A mock plugin for installer testing
protocols:
  - mock_proto
`
	if err := os.WriteFile(filepath.Join(mockPluginDir, "plugin.yaml"), []byte(manifestContent), 0644); err != nil {
		t.Fatal(err)
	}

	pluginGo := `package mock_plugin

import "testing"

func TestMock(t *testing.T) {
	// Passing test
}
`
	if err := os.WriteFile(filepath.Join(mockPluginDir, "mock_test.go"), []byte(pluginGo), 0644); err != nil {
		t.Fatal(err)
	}

	targetPluginsDir := filepath.Join(tmpDir, "plugins")
	_ = os.MkdirAll(filepath.Join(targetPluginsDir, "all"), 0755)
	_ = os.WriteFile(filepath.Join(targetPluginsDir, "all", "all.go"), []byte("package all\n\nimport (\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module github.com/routewarden/cli/proxy\n\ngo 1.22\n"), 0644)

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		NoBuild:    true,
	}

	res, err := plugins.InstallPlugin(mockPluginDir, opts)
	if err != nil {
		t.Fatalf("InstallPlugin failed: %v", err)
	}

	if res.Name != "mock_plugin" {
		t.Errorf("expected name mock_plugin, got %s", res.Name)
	}
	if !res.TestPassed {
		t.Errorf("expected tests to pass, output: %s", res.TestOutput)
	}
	if res.Status != plugins.StatusActive {
		t.Errorf("expected status ACTIVE, got %v", res.Status)
	}

	// Verify installed entry in plugins.json
	entries, err := plugins.GetInstalledRegistry(tmpDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 installed entry, got %d (err: %v)", len(entries), err)
	}
	if entries[0].Name != "mock_plugin" {
		t.Errorf("expected mock_plugin, got %s", entries[0].Name)
	}

	// Test Uninstall
	if err := plugins.UninstallPlugin("mock_plugin", opts); err != nil {
		t.Fatalf("UninstallPlugin failed: %v", err)
	}

	entriesAfter, _ := plugins.GetInstalledRegistry(tmpDir)
	if len(entriesAfter) != 0 {
		t.Errorf("expected 0 entries after uninstall, got %d", len(entriesAfter))
	}
}

func TestInstallPlugin_FailingTestsDisabled(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-install-fail-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockPluginDir := filepath.Join(tmpDir, "broken_plugin")
	_ = os.MkdirAll(mockPluginDir, 0755)

	manifestContent := `name: broken_plugin
version: 0.1.0
description: A plugin with failing tests
protocols:
  - broken_proto
`
	_ = os.WriteFile(filepath.Join(mockPluginDir, "plugin.yaml"), []byte(manifestContent), 0644)

	brokenTestGo := `package broken_plugin

import "testing"

func TestBroken(t *testing.T) {
	t.Fatalf("intentional assertion failure in plugin test")
}
`
	_ = os.WriteFile(filepath.Join(mockPluginDir, "broken_test.go"), []byte(brokenTestGo), 0644)

	targetPluginsDir := filepath.Join(tmpDir, "plugins")
	_ = os.MkdirAll(filepath.Join(targetPluginsDir, "all"), 0755)
	_ = os.WriteFile(filepath.Join(targetPluginsDir, "all", "all.go"), []byte("package all\n\nimport (\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module github.com/routewarden/cli/proxy\n\ngo 1.22\n"), 0644)

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		NoBuild:    true,
	}

	res, err := plugins.InstallPlugin(mockPluginDir, opts)
	if err != nil {
		t.Fatalf("InstallPlugin returned unexpected error: %v", err)
	}

	if res.TestPassed {
		t.Errorf("expected tests to fail")
	}
	if res.Status != plugins.StatusDisabled {
		t.Errorf("expected status DISABLED for plugin with failing tests, got %v", res.Status)
	}

	entries, _ := plugins.GetInstalledRegistry(tmpDir)
	if len(entries) != 1 || entries[0].Status != plugins.StatusDisabled {
		t.Errorf("expected registered plugin to have DISABLED status, got %+v", entries)
	}
}

func TestSyncPluginFromSource_UsesCache(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-sync-cache-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockSourceDir := filepath.Join(tmpDir, "source_plugin")
	_ = os.MkdirAll(mockSourceDir, 0755)

	manifestContent := `name: cached_plugin
version: 2.0.0
description: A plugin testing cache retrieval
protocols:
  - cached_proto
`
	_ = os.WriteFile(filepath.Join(mockSourceDir, "plugin.yaml"), []byte(manifestContent), 0644)
	_ = os.WriteFile(filepath.Join(mockSourceDir, "test_test.go"), []byte("package cached_plugin\n\nimport \"testing\"\n\nfunc TestOk(t *testing.T){}\n"), 0644)

	targetPluginsDir := filepath.Join(tmpDir, "plugins")
	cacheDir := filepath.Join(tmpDir, "cache")
	_ = os.MkdirAll(filepath.Join(targetPluginsDir, "all"), 0755)
	_ = os.WriteFile(filepath.Join(targetPluginsDir, "all", "all.go"), []byte("package all\n\nimport (\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module github.com/routewarden/cli/proxy\n\ngo 1.22\n"), 0644)

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		CacheDir:   cacheDir,
		NoBuild:    true,
	}

	// First pull: should populate cache
	res1, err := plugins.SyncPluginFromSource("cached_plugin", mockSourceDir, opts)
	if err != nil {
		t.Fatalf("first sync failed: %v", err)
	}
	if !res1.TestPassed {
		t.Errorf("expected test to pass, got: %s", res1.TestOutput)
	}

	// Verify cached files exist
	cachedYaml := filepath.Join(cacheDir, "cached_plugin", "plugin.yaml")
	if _, err := os.Stat(cachedYaml); os.IsNotExist(err) {
		t.Fatalf("expected cached plugin.yaml to exist at %s", cachedYaml)
	}

	// Delete the source to prove second pull uses cache
	_ = os.RemoveAll(mockSourceDir)

	// Second pull: should succeed using cache even though source is gone!
	res2, err := plugins.SyncPluginFromSource("cached_plugin", mockSourceDir, opts)
	if err != nil {
		t.Fatalf("second sync using cache failed: %v", err)
	}
	if res2.Name != "cached_plugin" {
		t.Errorf("expected cached_plugin, got %s", res2.Name)
	}
}

func TestParseGitSource(t *testing.T) {
	tests := []struct {
		input       string
		expectedRepo string
		expectedSub  string
	}{
		{
			input:       "https://github.com/routewarden/plugins/postgres",
			expectedRepo: "https://github.com/routewarden/plugins.git",
			expectedSub:  "postgres",
		},
		{
			input:       "github.com/routewarden/plugins/tree/main/redis",
			expectedRepo: "https://github.com/routewarden/plugins.git",
			expectedSub:  "redis",
		},
		{
			input:       "https://github.com/routewarden/plugins",
			expectedRepo: "https://github.com/routewarden/plugins.git",
			expectedSub:  "",
		},
	}

	for _, tc := range tests {
		repo, sub := plugins.ParseGitSource(tc.input)
		if repo != tc.expectedRepo {
			t.Errorf("input %s: expected repo %s, got %s", tc.input, tc.expectedRepo, repo)
		}
		if sub != tc.expectedSub {
			t.Errorf("input %s: expected sub %s, got %s", tc.input, tc.expectedSub, sub)
		}
	}
}

func TestResolveProjectDir_EnvironmentVariable(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-src-dir-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origEnv := os.Getenv("ROUTEWARDEN_SRC_DIR")
	defer os.Setenv("ROUTEWARDEN_SRC_DIR", origEnv)

	os.Setenv("ROUTEWARDEN_SRC_DIR", tmpDir)
	resolved := plugins.ResolveProjectDir("")
	if resolved != tmpDir {
		t.Errorf("expected %s, got %s", tmpDir, resolved)
	}

	pluginsDir := plugins.ResolvePluginsDir("", resolved)
	expectedPlugins := filepath.Join(tmpDir, "plugins")
	if pluginsDir != expectedPlugins {
		t.Errorf("expected %s, got %s", expectedPlugins, pluginsDir)
	}
}

func TestInstallPlugin_MissingAllGoCreated(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-missing-allgo-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockPluginDir := filepath.Join(tmpDir, "simple_plugin")
	_ = os.MkdirAll(mockPluginDir, 0755)

	manifestContent := `name: simple_plugin
version: 1.0.0
protocols:
  - simple_proto
`
	_ = os.WriteFile(filepath.Join(mockPluginDir, "plugin.yaml"), []byte(manifestContent), 0644)
	_ = os.WriteFile(filepath.Join(mockPluginDir, "dummy_test.go"), []byte("package simple_plugin\n"), 0644)

	// Note: target plugins dir does NOT have all/all.go initially
	targetPluginsDir := filepath.Join(tmpDir, "plugins")

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		NoBuild:    true,
	}

	res, err := plugins.InstallPlugin(mockPluginDir, opts)
	if err != nil {
		t.Fatalf("InstallPlugin failed with missing all.go: %v", err)
	}

	if res.Name != "simple_plugin" {
		t.Errorf("expected simple_plugin, got %s", res.Name)
	}

	// Verify all.go was created and has import
	allGoPath := filepath.Join(targetPluginsDir, "all", "all.go")
	content, err := os.ReadFile(allGoPath)
	if err != nil {
		t.Fatalf("expected all.go to be created, err: %v", err)
	}
	if !strings.Contains(string(content), `"github.com/routewarden/cli/proxy/plugins/simple_plugin"`) {
		t.Errorf("expected import in all.go, got: %s", string(content))
	}
}

func TestEnsureBuildPrerequisites(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-prereq-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	yamlPath := filepath.Join(tmpDir, "tcp-warden.yaml")
	if _, err := os.Stat(yamlPath); err == nil {
		t.Fatalf("expected tcp-warden.yaml to not exist initially")
	}

	plugins.EnsureBuildPrerequisites(tmpDir)

	if _, err := os.Stat(yamlPath); err != nil {
		t.Fatalf("expected tcp-warden.yaml to be restored by EnsureBuildPrerequisites, got error: %v", err)
	}
}

func TestGetDefaultServiceForPlugin(t *testing.T) {
	ftpDef := plugins.GetDefaultServiceForPlugin("ftp", []string{"ftp"}, nil)
	if ftpDef == nil || ftpDef.Listen != ":2121" || ftpDef.Upstream != "127.0.0.1:21" {
		t.Fatalf("expected ftp default service to map to :2121 -> 127.0.0.1:21, got: %+v", ftpDef)
	}

	pgDef := plugins.GetDefaultServiceForPlugin("postgres", []string{"postgres"}, nil)
	if pgDef == nil || pgDef.Listen != ":5433" || pgDef.Upstream != "127.0.0.1:5432" {
		t.Fatalf("expected postgres default service to map to :5433 -> 127.0.0.1:5432, got: %+v", pgDef)
	}

	redisDef := plugins.GetDefaultServiceForPlugin("redis", []string{"redis"}, nil)
	if redisDef == nil || redisDef.Listen != ":6380" {
		t.Fatalf("expected redis default service to map to :6380, got: %+v", redisDef)
	}
	if len(redisDef.PluginConfig) == 0 {
		t.Fatalf("expected redis default service to include blocked_commands in PluginConfig")
	}

	customDef := plugins.GetDefaultServiceForPlugin("custom_proto", []string{"custom_proto"}, nil)
	if customDef == nil || customDef.ServiceName != "custom_proto" {
		t.Fatalf("expected custom plugin to generate fallback default service, got: %+v", customDef)
	}
}

func TestCreatePlugin(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-create-plugin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	targetDir := filepath.Join(tmpDir, "plugins", "foobar")
	res, err := plugins.CreatePlugin(plugins.CreatePluginOptions{
		Name:       "foobar",
		Protocol:   "foobar",
		Listen:     ":9999",
		Upstream:   "127.0.0.1:9998",
		TargetDir:  targetDir,
		ProjectDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("CreatePlugin failed: %v", err)
	}

	if res.Name != "foobar" {
		t.Errorf("expected foobar, got %s", res.Name)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "plugin.yaml")); err != nil {
		t.Errorf("expected plugin.yaml to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "plugin.go")); err != nil {
		t.Errorf("expected plugin.go to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "inspector.go")); err != nil {
		t.Errorf("expected inspector.go to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "foobar_test.go")); err != nil {
		t.Errorf("expected foobar_test.go to exist: %v", err)
	}
}

func TestInstallPlugin_CompilationFailureRejected(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-install-compile-fail-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockPluginDir := filepath.Join(tmpDir, "syntax_error_plugin")
	_ = os.MkdirAll(mockPluginDir, 0755)

	manifestContent := `name: syntax_error_plugin
version: 1.0.0
description: A plugin with compilation syntax errors
protocols:
  - syntax_err_proto
`
	_ = os.WriteFile(filepath.Join(mockPluginDir, "plugin.yaml"), []byte(manifestContent), 0644)

	// Invalid Go code that will fail compilation
	brokenGo := `package syntax_error_plugin

func BrokenSyntax() {
	this is not valid go code !!!
}
`
	_ = os.WriteFile(filepath.Join(mockPluginDir, "plugin.go"), []byte(brokenGo), 0644)

	targetPluginsDir := filepath.Join(tmpDir, "plugins")
	_ = os.MkdirAll(filepath.Join(targetPluginsDir, "all"), 0755)
	allGoPath := filepath.Join(targetPluginsDir, "all", "all.go")
	_ = os.WriteFile(allGoPath, []byte("package all\n\nimport (\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module github.com/routewarden/cli/proxy\n\ngo 1.22\n"), 0644)

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		NoBuild:    true,
	}

	_, err = plugins.InstallPlugin(mockPluginDir, opts)
	if err == nil {
		t.Fatalf("expected InstallPlugin to fail due to compilation error, but got nil")
	}

	// Verify all.go was NOT populated with the broken plugin
	allContent, _ := os.ReadFile(allGoPath)
	if strings.Contains(string(allContent), "syntax_error_plugin") {
		t.Errorf("uncompilable plugin must NOT be registered in all.go: %s", string(allContent))
	}

	// Verify targetDir was cleaned up
	installedTargetDir := filepath.Join(targetPluginsDir, "syntax_error_plugin")
	if _, statErr := os.Stat(installedTargetDir); !os.IsNotExist(statErr) {
		t.Errorf("expected target directory to be removed on compilation failure, but it exists")
	}
}

func TestUninstallPlugin_InvalidNameDoesNotWipeDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-uninstall-safe-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	targetPluginsDir := filepath.Join(tmpDir, "plugins")
	_ = os.MkdirAll(filepath.Join(targetPluginsDir, "important_plugin"), 0755)
	_ = os.WriteFile(filepath.Join(targetPluginsDir, "important_plugin", "plugin.go"), []byte("package p"), 0644)

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		NoBuild:    true,
	}

	// Empty or invalid names must return error and NOT wipe plugins dir
	for _, badName := range []string{"", "   ", ".", "/", ".."} {
		if err := plugins.UninstallPlugin(badName, opts); err == nil {
			t.Errorf("expected UninstallPlugin(%q) to return error, got nil", badName)
		}
	}

	// Important plugin must still exist
	if _, err := os.Stat(filepath.Join(targetPluginsDir, "important_plugin")); os.IsNotExist(err) {
		t.Fatal("Round 3 Bug #4 regression: UninstallPlugin with empty/invalid name wiped the plugins directory!")
	}
}

func TestCreatePlugin_UsesCloseWriteInTemplate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-create-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	res, err := plugins.CreatePlugin(plugins.CreatePluginOptions{
		Name:       "temptest",
		ProjectDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("CreatePlugin failed: %v", err)
	}

	inspectorPath := filepath.Join(res.Directory, "inspector.go")
	content, err := os.ReadFile(inspectorPath)
	if err != nil {
		t.Fatalf("failed reading generated inspector.go: %v", err)
	}

	// Must contain CloseWrite half-close instead of unconditional Close()
	if !strings.Contains(string(content), "CloseWrite") {
		t.Errorf("Round 3 Bug #5 regression: generated inspector.go template does not use CloseWrite()")
	}
	if strings.Contains(string(content), "_ = client.Close()") || strings.Contains(string(content), "_ = upstream.Close()") {
		t.Errorf("Round 3 Bug #5 regression: generated template still contains hard client.Close() or upstream.Close()")
	}
}

func TestInstallPlugin_WithExternalDependenciesAndNestedGoMod(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-ext-dep-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockPluginDir := filepath.Join(tmpDir, "source_ext_plugin")
	if err := os.MkdirAll(mockPluginDir, 0755); err != nil {
		t.Fatal(err)
	}

	manifestContent := `name: ext_plugin
version: 1.0.0
description: A plugin with external dependencies and its own go.mod
protocols:
  - ext_proto
`
	if err := os.WriteFile(filepath.Join(mockPluginDir, "plugin.yaml"), []byte(manifestContent), 0644); err != nil {
		t.Fatal(err)
	}

	nestedMod := `module example.com/ext_plugin

go 1.22

require gopkg.in/yaml.v3 v3.0.1
`
	if err := os.WriteFile(filepath.Join(mockPluginDir, "go.mod"), []byte(nestedMod), 0644); err != nil {
		t.Fatal(err)
	}

	pluginGo := `package ext_plugin

import (
	"gopkg.in/yaml.v3"
)

func EncodeConfig(data any) ([]byte, error) {
	return yaml.Marshal(data)
}
`
	if err := os.WriteFile(filepath.Join(mockPluginDir, "ext.go"), []byte(pluginGo), 0644); err != nil {
		t.Fatal(err)
	}

	pluginTestGo := `package ext_plugin

import "testing"

func TestEncodeConfig(t *testing.T) {
	out, err := EncodeConfig(map[string]string{"key": "val"})
	if err != nil || len(out) == 0 {
		t.Fatalf("EncodeConfig failed: %v", err)
	}
}
`
	if err := os.WriteFile(filepath.Join(mockPluginDir, "ext_test.go"), []byte(pluginTestGo), 0644); err != nil {
		t.Fatal(err)
	}

	targetPluginsDir := filepath.Join(tmpDir, "plugins")
	_ = os.MkdirAll(filepath.Join(targetPluginsDir, "all"), 0755)
	_ = os.WriteFile(filepath.Join(targetPluginsDir, "all", "all.go"), []byte("package all\n\nimport (\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module github.com/routewarden/cli/proxy\n\ngo 1.22\n"), 0644)

	opts := plugins.InstallOptions{
		PluginsDir: targetPluginsDir,
		ProjectDir: tmpDir,
		NoBuild:    true,
	}

	res, err := plugins.InstallPlugin(mockPluginDir, opts)
	if err != nil {
		t.Fatalf("InstallPlugin with external dependency failed: %v", err)
	}

	if res.Name != "ext_plugin" {
		t.Errorf("expected ext_plugin, got %s", res.Name)
	}
	if !res.TestPassed {
		t.Fatalf("expected tests to pass, output: %s", res.TestOutput)
	}
	if res.Status != plugins.StatusActive {
		t.Errorf("expected status ACTIVE, got %v", res.Status)
	}

	// 1. Verify nested go.mod was stripped in installed location
	installedMod := filepath.Join(targetPluginsDir, "ext_plugin", "go.mod")
	if _, err := os.Stat(installedMod); !os.IsNotExist(err) {
		t.Errorf("expected nested go.mod to be removed from %s", installedMod)
	}

	// 2. Verify project go.mod has yaml.v3 required
	hostModBytes, err := os.ReadFile(filepath.Join(tmpDir, "go.mod"))
	if err != nil {
		t.Fatalf("failed reading host go.mod: %v", err)
	}
	if !strings.Contains(string(hostModBytes), "gopkg.in/yaml.v3") {
		t.Errorf("expected host go.mod to contain gopkg.in/yaml.v3 requirement, got:\n%s", string(hostModBytes))
	}

	// 3. Uninstall plugin and verify dependency is tidied up
	if err := plugins.UninstallPlugin("ext_plugin", opts); err != nil {
		t.Fatalf("UninstallPlugin failed: %v", err)
	}

	hostModAfter, err := os.ReadFile(filepath.Join(tmpDir, "go.mod"))
	if err != nil {
		t.Fatalf("failed reading host go.mod after uninstall: %v", err)
	}
	if strings.Contains(string(hostModAfter), "gopkg.in/yaml.v3") {
		t.Errorf("expected gopkg.in/yaml.v3 to be tidied from host go.mod after uninstall, got:\n%s", string(hostModAfter))
	}
}

func TestPluginInstaller_SecurityBoundaries(t *testing.T) {
	t.Run("CreatePlugin_RejectsPathTraversalNames", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test-create-sec-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		maliciousNames := []string{
			"../../escaped",
			"../root",
			"foo/bar",
			"foo\\bar",
			"name:with:colons",
			"plugin;echo",
			"plugin spaces",
			"",
		}

		for _, badName := range maliciousNames {
			_, err := plugins.CreatePlugin(plugins.CreatePluginOptions{
				Name:       badName,
				ProjectDir: tmpDir,
			})
			if err == nil {
				t.Errorf("expected CreatePlugin to reject malicious name %q, got nil error", badName)
			}
		}
	})

	t.Run("UninstallPlugin_RejectsPathTraversalNames", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test-uninstall-sec-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		opts := plugins.InstallOptions{
			ProjectDir: tmpDir,
			PluginsDir: filepath.Join(tmpDir, "plugins"),
			NoBuild:    true,
		}

		badNames := []string{"../../etc", "../plugins", "a/b", "c\\d"}
		for _, badName := range badNames {
			if err := plugins.UninstallPlugin(badName, opts); err == nil {
				t.Errorf("expected UninstallPlugin to reject %q, got nil error", badName)
			}
		}
	})

	t.Run("SyncPluginFromSource_RejectsPathTraversalNames", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test-sync-sec-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		opts := plugins.InstallOptions{
			ProjectDir: tmpDir,
			CacheDir:   filepath.Join(tmpDir, "cache"),
			NoBuild:    true,
		}

		_, err = plugins.SyncPluginFromSource("../../evil", "https://github.com/routewarden/plugins/test", opts)
		if err == nil {
			t.Errorf("expected SyncPluginFromSource to reject path traversal in name")
		}
	})
}


