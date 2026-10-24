package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/routewarden/cli/proxy/config"
	"github.com/routewarden/cli/proxy/core"
	"github.com/routewarden/cli/proxy/plugins"
	_ "github.com/routewarden/cli/proxy/plugins/all"
)

//go:embed tcp-warden.yaml
var defaultConfigFile []byte

var (
	version = "5.3.3"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		runDaemon("")
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "run":
		handleRun(args)
	case "validate":
		handleValidate(args)
	case "status":
		handleStatus(args)
	case "plugins":
		handlePlugins(args)
	case "banlist":
		handleBanlist(args)
	case "unban":
		handleUnban(args)
	case "ban":
		handleBan(args)
	case "version", "--version", "-v":
		fmt.Printf("tcp-warden version %s (commit: %s, date: %s)\n", version, commit, date)
	case "help", "--help", "-h":
		printUsage()
	default:
		if strings.HasPrefix(cmd, "-") {
			handleRun(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`TCP Warden - Protocol-Aware L4 Security Proxy

Usage:
  tcp-warden [command] [flags]

Commands:
  run         Start the TCP security proxy daemon (default)
  validate    Verify YAML configuration syntax and rules
  plugins     Manage and test modular protocol plugins
  status      Query health and metrics from running daemon
  banlist     Display active IP bans
  unban       Remove an active IP ban
  ban         Manually ban an IP address
  version     Display version information
  help        Show this help message

Run Flags:
  --config, -c   Path to YAML config file (default: tcp-warden.yaml)

Examples:
  tcp-warden run --config tcp-warden.yaml
  tcp-warden validate --config tcp-warden.yaml
  tcp-warden plugins list
  tcp-warden plugins test
  tcp-warden status --api http://127.0.0.1:9091
  tcp-warden banlist --api http://127.0.0.1:9091
  tcp-warden unban 192.0.2.1 --api http://127.0.0.1:9091
  tcp-warden ban 198.51.100.42 --duration 2h --reason "brute_force" --api http://127.0.0.1:9091
`)
}

func handleRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to YAML config file")
	fs.StringVar(configPath, "c", "", "Path to YAML config file")
	_ = fs.Parse(normalizeArgs(args))

	runDaemon(*configPath)
}

func resolveConfigPath(customPath string) string {
	if customPath != "" {
		return customPath
	}
	if env := os.Getenv("ROUTEWARDEN_CONFIG"); env != "" {
		return env
	}
	// In containerized environments (where ROUTEWARDEN_SRC_DIR is set) or when /etc/routewarden is mounted:
	// prioritize the mounted /etc/routewarden volume over local source tree copies
	if os.Getenv("ROUTEWARDEN_SRC_DIR") != "" {
		if _, err := os.Stat("/etc/routewarden/tcp-warden.yaml"); err == nil {
			return "/etc/routewarden/tcp-warden.yaml"
		}
		if _, err := os.Stat("/etc/routewarden/tcp-warden.yml"); err == nil {
			return "/etc/routewarden/tcp-warden.yml"
		}
		if fi, err := os.Stat("/etc/routewarden"); err == nil && fi.IsDir() {
			return "/etc/routewarden/tcp-warden.yaml"
		}
	}
	if _, err := os.Stat("/etc/routewarden/tcp-warden.yaml"); err == nil {
		return "/etc/routewarden/tcp-warden.yaml"
	}
	if _, err := os.Stat("/etc/routewarden/tcp-warden.yml"); err == nil {
		return "/etc/routewarden/tcp-warden.yml"
	}
	if _, err := os.Stat("tcp-warden.yaml"); err == nil {
		return "tcp-warden.yaml"
	}
	if _, err := os.Stat("tcp-warden.yml"); err == nil {
		return "tcp-warden.yml"
	}
	if fi, err := os.Stat("/etc/routewarden"); err == nil && fi.IsDir() {
		return "/etc/routewarden/tcp-warden.yaml"
	}
	return "tcp-warden.yaml"
}

func ensureConfigFile(configPath string) error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("ℹ️ [FIRST RUN] Configuration file not found at %s. Creating default template...\n", configPath)
		dir := filepath.Dir(configPath)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("creating directory %s: %w", dir, err)
			}
		}
		if err := os.WriteFile(configPath, defaultConfigFile, 0644); err != nil {
			return fmt.Errorf("creating default config file %s: %w", configPath, err)
		}
		fmt.Printf("✓ Default configuration created at %s\n", configPath)
	}
	return nil
}

func runDaemon(configPath string) {
	configPath = resolveConfigPath(configPath)
	if err := ensureConfigFile(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed initializing configuration %s: %v\n", configPath, err)
		os.Exit(1)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error loading configuration %s: %v\n", configPath, err)
		os.Exit(1)
	}

	for _, w := range cfg.Warnings {
		fmt.Fprintf(os.Stderr, "⚠️  [CONFIG WARN] %s\n", w)
	}

	d, err := core.NewDaemon(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error initializing daemon: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("🛡️  Starting TCP Warden...")
	fmt.Printf("   Config: %s\n", configPath)
	fmt.Printf("   Services (%d):\n", len(cfg.Services))
	for name, svc := range cfg.Services {
		status := "enabled"
		if !svc.IsEnabled() {
			status = "disabled"
		} else if !isStandardProtocol(svc.Protocol) && !plugins.IsActive(svc.Protocol) {
			status = "plugin unavailable"
		}
		fmt.Printf("     • %-12s [%s]  %s -> %s (%s)\n", name, svc.Protocol, svc.Listen, svc.Upstream, status)
	}

	if cfg.API.Enabled {
		fmt.Printf("   API listen: %s\n", cfg.API.Listen)
	}
	if cfg.CrowdSec.Enabled {
		fmt.Printf("   CrowdSec:   %s (sync every %s)\n", cfg.CrowdSec.LAPIURL, cfg.CrowdSec.UpdateFrequency.Duration())
	}
	if cfg.Global.LogFile != "" {
		fmt.Printf("   Log file:   %s\n", cfg.Global.LogFile)
	}
	fmt.Printf("   Log level:  %s\n", cfg.Global.LogLevel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n🛑 Shutting down TCP Warden...")
		cancel()
		<-sigCh
		fmt.Println("\n🛑 Forcefully terminating TCP Warden...")
		os.Exit(1)
	}()

	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Daemon error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ TCP Warden shut down gracefully.")
}

func handleValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "tcp-warden.yaml", "Path to YAML config file")
	fs.StringVar(configPath, "c", "tcp-warden.yaml", "Path to YAML config file")
	_ = fs.Parse(args)

	cfgPath := resolveConfigPath(*configPath)
	if err := ensureConfigFile(cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed initializing configuration %s: %v\n", cfgPath, err)
		os.Exit(1)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Validation failed: %v\n", err)
		os.Exit(1)
	}

	for _, w := range cfg.Warnings {
		fmt.Printf("⚠️  [CONFIG WARN] %s\n", w)
	}

	var activeCount int
	for _, svc := range cfg.Services {
		if svc.IsEnabled() {
			activeCount++
		}
	}

	if len(cfg.Warnings) > 0 {
		fmt.Printf("✓ Configuration %s is VALID (with %d warning(s)).\n", *configPath, len(cfg.Warnings))
	} else {
		fmt.Printf("✓ Configuration %s is VALID.\n", *configPath)
	}
	fmt.Printf("  - Version: %s\n", cfg.Version)
	fmt.Printf("  - Active services: %d (Total defined: %d)\n", activeCount, len(cfg.Services))
	for name, svc := range cfg.Services {
		status := "enabled"
		if !svc.IsEnabled() {
			status = "disabled"
		}
		fmt.Printf("    • %-14s [%-11s]  %s -> %s (%s)\n", name, svc.Protocol, svc.Listen, svc.Upstream, status)
	}
	fmt.Printf("  - Management API: %t (%s)\n", cfg.API.Enabled, cfg.API.Listen)
	fmt.Printf("  - CrowdSec bouncer: %t\n", cfg.CrowdSec.Enabled)
	fmt.Printf("  - SIEM log file: %s\n", cfg.Global.LogFile)
}

func makeAPIRequest(method, url, token string, body io.Reader) (*http.Response, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token == "" {
		token = os.Getenv("ROUTEWARDEN_TOKEN")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return client.Do(req)
}

func handleStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	apiAddr := fs.String("api", "http://127.0.0.1:9091", "TCP Warden API URL")
	token := fs.String("token", "", "API authentication token")
	_ = fs.Parse(normalizeArgs(args))

	url := strings.TrimRight(*apiAddr, "/") + "/health"
	resp, err := makeAPIRequest(http.MethodGet, url, *token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to TCP Warden daemon at %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "❌ API returned HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}

	body, _ := io.ReadAll(resp.Body)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(body))
	}
}

func handleBanlist(args []string) {
	fs := flag.NewFlagSet("banlist", flag.ExitOnError)
	apiAddr := fs.String("api", "http://127.0.0.1:9091", "TCP Warden API URL")
	token := fs.String("token", "", "API authentication token")
	_ = fs.Parse(normalizeArgs(args))

	url := strings.TrimRight(*apiAddr, "/") + "/api/banlist"
	resp, err := makeAPIRequest(http.MethodGet, url, *token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to TCP Warden daemon: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "❌ API returned HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}

	var bans []core.BanEntry
	if err := json.NewDecoder(resp.Body).Decode(&bans); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to decode banlist: %v\n", err)
		os.Exit(1)
	}

	if len(bans) == 0 {
		fmt.Println("No active bans.")
		return
	}

	fmt.Printf("%-18s %-20s %-12s %-22s %s\n", "IP", "REASON", "SERVICE", "BANNED AT", "EXPIRES IN")
	fmt.Println(strings.Repeat("-", 85))
	for _, b := range bans {
		expiresIn := "permanent"
		if !b.Permanent {
			rem := time.Until(b.ExpiresAt).Round(time.Second)
			if rem > 0 {
				expiresIn = rem.String()
			} else {
				expiresIn = "expired"
			}
		}
		fmt.Printf("%-18s %-20s %-12s %-22s %s\n",
			b.IP,
			truncate(b.Reason, 20),
			b.Service,
			b.BannedAt.Format("2006-01-02 15:04:05"),
			expiresIn,
		)
	}
}

func handleUnban(args []string) {
	fs := flag.NewFlagSet("unban", flag.ExitOnError)
	apiAddr := fs.String("api", "http://127.0.0.1:9091", "TCP Warden API URL")
	token := fs.String("token", "", "API authentication token")
	_ = fs.Parse(normalizeArgs(args))

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tcp-warden unban <ip> [--token <token>] [--api <url>]")
		os.Exit(1)
	}
	ip := fs.Args()[0]

	url := strings.TrimRight(*apiAddr, "/") + "/api/unban"
	bodyBytes, _ := json.Marshal(map[string]string{"ip": ip})
	resp, err := makeAPIRequest(http.MethodPost, url, *token, bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to TCP Warden daemon: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "❌ API returned HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}

	var result struct {
		Unbanned bool   `json:"unbanned"`
		IP       string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to decode response: %v\n", err)
		os.Exit(1)
	}
	if result.Unbanned {
		fmt.Printf("✓ Successfully unbanned %s\n", ip)
	} else {
		fmt.Printf("ℹ IP %s was not in the active banlist\n", ip)
	}
}

func handleBan(args []string) {
	fs := flag.NewFlagSet("ban", flag.ExitOnError)
	apiAddr := fs.String("api", "http://127.0.0.1:9091", "TCP Warden API URL")
	reason := fs.String("reason", "manual_admin_ban", "Reason for the ban")
	duration := fs.String("duration", "1h", "Duration of the ban (e.g. '1h', '30m')")
	token := fs.String("token", "", "API authentication token")
	_ = fs.Parse(normalizeArgs(args))

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tcp-warden ban <ip> [--duration 1h] [--reason \"...\"] [--token <token>] [--api <url>]")
		os.Exit(1)
	}
	ip := fs.Args()[0]

	url := strings.TrimRight(*apiAddr, "/") + "/api/ban"
	bodyBytes, _ := json.Marshal(map[string]string{
		"ip":       ip,
		"reason":   *reason,
		"duration": *duration,
	})
	resp, err := makeAPIRequest(http.MethodPost, url, *token, bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to TCP Warden daemon: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("✓ Successfully banned %s for %s (%s)\n", ip, *duration, *reason)
	} else {
		fmt.Fprintf(os.Stderr, "❌ Ban failed with status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}

// truncate shortens s to at most maxLen Unicode codepoints.
// If truncated, the last codepoint is replaced by a single '…' (ellipsis),
// preserving column-alignment in table output.
func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen == 1 {
		return "…"
	}
	return string(runes[:maxLen-1]) + "…"
}

// normalizeArgs moves leading non-flag arguments to the end so flag.FlagSet can parse
// flags even when positional arguments precede flags (e.g. `tcp-warden ban 1.2.3.4 --duration 2h`).
func normalizeArgs(args []string) []string {
	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagName := strings.TrimLeft(arg, "-")
				switch flagName {
				case "force", "no-build", "no-service", "v", "version", "help", "h":
					// boolean flags — do not consume the next token as a value
				default:
					i++
					flags = append(flags, args[i])
				}
			}
		} else {
			positionals = append(positionals, arg)
		}
	}
	return append(flags, positionals...)
}

func handlePlugins(args []string) {
	if len(args) == 0 {
		printPluginsUsage()
		return
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "list":
		handlePluginsList(subargs)
	case "test":
		handlePluginsTest(subargs)
	case "enable":
		handlePluginsEnable(subargs)
	case "disable":
		handlePluginsDisable(subargs)
	case "install":
		handlePluginsInstall(subargs)
	case "create", "init", "new":
		handlePluginsCreate(subargs)
	case "uninstall", "remove":
		handlePluginsUninstall(subargs)
	case "help", "--help", "-h":
		printPluginsUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown plugins subcommand: %s\n\n", subcmd)
		printPluginsUsage()
		os.Exit(1)
	}
}

func printPluginsUsage() {
	fmt.Print(`TCP Warden - Modular Protocol Plugins

Usage:
  tcp-warden plugins [command] [flags]

Commands:
  list                      List all registered plugins and their enabled/health status
  create <name>             Scaffold a new plugin with boilerplate and default service
  enable <name>             Enable a plugin and update config file
  disable <name>            Disable a plugin and update config file
  test [name]               Execute synthetic self-tests on registered plugins
  install <url-or-path>     Install a plugin from a GitHub URL or local repository path
  uninstall <name>          Remove an installed plugin

Flags (enable / disable):
  --config, -c  Path to YAML config file to update (default: tcp-warden.yaml)

Flags (install):
  --config, -c  Path to YAML config file to update (default: tcp-warden.yaml)
  --force       Overwrite existing plugin and cache directory
  --no-build    Skip rebuilding tcp-warden binary after installation
  --cache-dir   Path to plugin cache directory (default: $ROUTEWARDEN_PLUGINS_CACHE)

Examples:
  tcp-warden plugins list
  tcp-warden plugins enable postgres
  tcp-warden plugins disable redis
  tcp-warden plugins enable mysql --config /etc/routewarden/tcp-warden.yaml
  tcp-warden plugins test
  tcp-warden plugins install https://github.com/routewarden/plugins/postgres
  tcp-warden plugins install ../plugins/redis
  tcp-warden plugins install ./my-local-plugin
  tcp-warden plugins uninstall postgres
`)
}

func handlePluginsInstall(args []string) {
	fs := flag.NewFlagSet("plugins install", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to YAML config file to update")
	fs.StringVar(configPath, "c", "", "Path to YAML config file to update")
	force := fs.Bool("force", false, "Overwrite existing plugin and cache directory")
	noBuild := fs.Bool("no-build", false, "Skip rebuilding tcp-warden binary")
	cacheDir := fs.String("cache-dir", "", "Path to plugin cache directory")
	_ = fs.Parse(normalizeArgs(args))

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tcp-warden plugins install <github-url-or-local-path> [--config <path>] [--force] [--no-build] [--cache-dir <dir>]")
		os.Exit(1)
	}
	source := fs.Args()[0]

	fmt.Printf("📦 Installing plugin from: %s\n", source)
	res, err := plugins.SyncPluginFromSource("", source, plugins.InstallOptions{
		PluginsDir: "plugins",
		ProjectDir: ".",
		CacheDir:   *cacheDir,
		Force:      *force,
		NoBuild:    *noBuild,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Plugin installation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	if res.TestPassed {
		// Auto-activate plugin in runtime registry and plugins.json
		_ = plugins.SavePluginEnablement(plugins.ResolveProjectDir(""), res.Name, true)
		_ = plugins.Global().Enable(res.Name)

		// Auto-activate plugin in YAML configuration
		cfgPath := resolveConfigPath(*configPath)
		_ = ensureConfigFile(cfgPath)
		if _, err := os.Stat(cfgPath); err == nil {
			if err := config.UpdatePluginEnablement(cfgPath, res.Name, true); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️ Failed to update configuration file %s: %v\n", cfgPath, err)
			} else {
				fmt.Printf("✓ Updated configuration in %s (plugins.%s.enabled: true)\n", cfgPath, res.Name)
			}

			// Auto-add default service definition if not already present
			if added, svcName, err := config.AddDefaultPluginService(cfgPath, res.Name, res.DefaultService); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️ Failed to add default service to %s: %v\n", cfgPath, err)
			} else if added {
				fmt.Printf("✓ Auto-added default service %q in %s (%s -> %s, protocol: %s)\n",
					svcName, cfgPath, res.DefaultService.Listen, res.DefaultService.Upstream, res.DefaultService.Protocol)
			}
		}

		fmt.Printf("✓ Plugin %q [%s] installed and ACTIVATED successfully!\n", res.Name, res.Version)
		fmt.Printf("  • Status:     ACTIVE (enabled)\n")
		fmt.Printf("  • Protocols:  %s\n", strings.Join(res.Protocols, ", "))
		fmt.Printf("  • Pre-Tests:  PASSED\n")
		if res.Rebuilt {
			fmt.Printf("  • Binary:     rebuilt successfully with new plugin\n")
			fmt.Printf("\n💡 Note: If tcp-warden daemon is running, restart it to load the updated binary:\n")
			fmt.Printf("   docker restart tcp-warden   (or: docker compose restart tcp-warden)\n")
		}
	} else {
		_ = plugins.SavePluginEnablement(plugins.ResolveProjectDir(""), res.Name, false)
		cfgPath := resolveConfigPath(*configPath)
		if _, err := os.Stat(cfgPath); err == nil {
			_ = config.UpdatePluginEnablement(cfgPath, res.Name, false)
		}

		fmt.Printf("⚠️ Plugin %q [%s] was installed but DISABLED due to test failure:\n", res.Name, res.Version)
		fmt.Printf("  • Status:     DISABLED\n")
		fmt.Printf("  • Pre-Tests:  FAILED\n")
		if res.TestOutput != "" {
			fmt.Println("--- Test Output ---")
			fmt.Println(res.TestOutput)
			fmt.Println("-------------------")
		}
	}
}

func handlePluginsUninstall(args []string) {
	fs := flag.NewFlagSet("plugins uninstall", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to YAML config file to update")
	fs.StringVar(configPath, "c", "", "Path to YAML config file to update")
	noBuild := fs.Bool("no-build", false, "Skip rebuilding tcp-warden binary")
	_ = fs.Parse(normalizeArgs(args))

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tcp-warden plugins uninstall <plugin-name> [--config <path>] [--no-build]")
		os.Exit(1)
	}
	name := strings.ToLower(strings.TrimSpace(fs.Args()[0]))

	fmt.Printf("🗑️  Uninstalling plugin: %s\n", name)
	if err := plugins.UninstallPlugin(name, plugins.InstallOptions{
		PluginsDir: "plugins",
		ProjectDir: ".",
		NoBuild:    *noBuild,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed uninstalling plugin: %v\n", err)
		os.Exit(1)
	}

	// Also ensure configuration disables the uninstalled plugin
	cfgPath := resolveConfigPath(*configPath)
	if _, err := os.Stat(cfgPath); err == nil {
		if err := config.UpdatePluginEnablement(cfgPath, name, false); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️ Failed to update configuration file %s: %v\n", cfgPath, err)
		} else {
			fmt.Printf("✓ Updated configuration in %s (plugins.%s.enabled: false)\n", cfgPath, name)
		}
	}

	fmt.Printf("✓ Plugin %q uninstalled successfully.\n", name)
}

func handlePluginsCreate(args []string) {
	fs := flag.NewFlagSet("plugins create", flag.ExitOnError)
	proto := fs.String("protocol", "", "Protocol identifier (default: plugin name)")
	listen := fs.String("listen", "", "Default service listen address (e.g. :9000)")
	upstream := fs.String("upstream", "", "Default service upstream target (e.g. 127.0.0.1:9001)")
	dir := fs.String("dir", "", "Target directory to generate plugin scaffold")
	noService := fs.Bool("no-service", false, "Do not auto-add default service to configuration")
	configPath := fs.String("config", "", "Path to YAML config file")
	fs.StringVar(configPath, "c", "", "Path to YAML config file")
	_ = fs.Parse(normalizeArgs(args))

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tcp-warden plugins create <plugin-name> [--protocol <proto>] [--listen <port>] [--upstream <target>] [--dir <path>] [--no-service]")
		os.Exit(1)
	}
	name := strings.ToLower(strings.TrimSpace(fs.Args()[0]))

	fmt.Printf("🛠️  Scaffolding modular plugin: %s\n", name)
	res, err := plugins.CreatePlugin(plugins.CreatePluginOptions{
		Name:       name,
		Protocol:   *proto,
		Listen:     *listen,
		Upstream:   *upstream,
		TargetDir:  *dir,
		ProjectDir: ".",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed creating plugin: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✨ Created plugin %q successfully!\n", res.Name)
	fmt.Printf("  • Directory:      %s\n", res.Directory)
	fmt.Printf("  • Manifest:       %s\n", res.ManifestPath)
	fmt.Printf("  • Registered:     plugins/all/all.go\n")

	if !*noService {
		cfgPath := resolveConfigPath(*configPath)
		_ = ensureConfigFile(cfgPath)
		if _, err := os.Stat(cfgPath); err == nil {
			_ = config.UpdatePluginEnablement(cfgPath, res.Name, true)
			if added, svcName, err := config.AddDefaultPluginService(cfgPath, res.Name, res.DefaultService); err == nil && added {
				fmt.Printf("✓ Auto-added default service %q in %s (%s -> %s, protocol: %s)\n",
					svcName, cfgPath, res.DefaultService.Listen, res.DefaultService.Upstream, res.DefaultService.Protocol)
			}
		}
	}
}

func handlePluginsEnable(args []string) {
	fs := flag.NewFlagSet("plugins enable", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to YAML config file")
	fs.StringVar(configPath, "c", "", "Path to YAML config file")
	_ = fs.Parse(normalizeArgs(args))

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tcp-warden plugins enable <plugin-name> [--config <path>]")
		os.Exit(1)
	}
	name := strings.ToLower(strings.TrimSpace(fs.Args()[0]))

	fmt.Printf("🧪 Running pre-flight self-test for plugin %q...\n", name)
	if err := plugins.Global().Enable(name); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to enable plugin %q: %v\n", name, err)
		os.Exit(1)
	}

	_ = plugins.SavePluginEnablement(plugins.ResolveProjectDir(""), name, true)
	fmt.Printf("✓ Plugin %q is now ENABLED and ACTIVE.\n", name)

	cfgPath := resolveConfigPath(*configPath)
	_ = ensureConfigFile(cfgPath)
	if _, err := os.Stat(cfgPath); err == nil {
		if err := config.UpdatePluginEnablement(cfgPath, name, true); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️ Failed to update configuration file %s: %v\n", cfgPath, err)
		} else {
			fmt.Printf("✓ Updated configuration in %s (plugins.%s.enabled: true)\n", cfgPath, name)
		}
		if added, svcName, err := config.AddDefaultPluginService(cfgPath, name, nil); err == nil && added {
			fmt.Printf("✓ Auto-added default service %q in %s\n", svcName, cfgPath)
		}
	}
}

func handlePluginsDisable(args []string) {
	fs := flag.NewFlagSet("plugins disable", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to YAML config file")
	fs.StringVar(configPath, "c", "", "Path to YAML config file")
	_ = fs.Parse(normalizeArgs(args))

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tcp-warden plugins disable <plugin-name> [--config <path>]")
		os.Exit(1)
	}
	name := strings.ToLower(strings.TrimSpace(fs.Args()[0]))

	if err := plugins.Global().Disable(name, "disabled by user"); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to disable plugin %q: %v\n", name, err)
		os.Exit(1)
	}

	_ = plugins.SavePluginEnablement(plugins.ResolveProjectDir(""), name, false)
	fmt.Printf("✓ Plugin %q is now DISABLED.\n", name)

	cfgPath := resolveConfigPath(*configPath)
	_ = ensureConfigFile(cfgPath)
	if _, err := os.Stat(cfgPath); err == nil {
		if err := config.UpdatePluginEnablement(cfgPath, name, false); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️ Failed to update configuration file %s: %v\n", cfgPath, err)
		} else {
			fmt.Printf("✓ Updated configuration in %s (plugins.%s.enabled: false)\n", cfgPath, name)
		}
	}
}

func handlePluginsList(args []string) {
	fs := flag.NewFlagSet("plugins list", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to YAML config file")
	fs.StringVar(configPath, "c", "", "Path to YAML config file")
	_ = fs.Parse(normalizeArgs(args))

	var enabledList []string
	var disabledList []string

	cfgPath := resolveConfigPath(*configPath)

	var cfg *config.Config
	// 1. Sync base enablement from configuration if file exists
	if loadedCfg, err := config.Load(cfgPath); err == nil {
		cfg = loadedCfg
		enabledList = append(enabledList, cfg.Plugins.Enabled...)
		disabledList = append(disabledList, cfg.Plugins.Disabled...)
	}

	// 2. Sync runtime overrides from plugins.json if present (only for plugins not explicitly defined in YAML)
	if pEnabled, pDisabled, err := plugins.GetPluginEnablement(plugins.ResolveProjectDir("")); err == nil {
		for _, pe := range pEnabled {
			if cfg == nil || !isPluginInEntries(cfg, pe) {
				disabledList = removeFromList(disabledList, pe)
				if !contains(enabledList, pe) {
					enabledList = append(enabledList, pe)
				}
			}
		}
		for _, pd := range pDisabled {
			if cfg == nil || !isPluginInEntries(cfg, pd) {
				enabledList = removeFromList(enabledList, pd)
				if !contains(disabledList, pd) {
					disabledList = append(disabledList, pd)
				}
			}
		}
	}

	plugins.ApplyConfiguration(enabledList, disabledList)

	list := plugins.List()
	if len(list) == 0 {
		fmt.Println("No modular plugins currently installed.")
		fmt.Println()
		fmt.Println("To install a plugin from a Git repository or local directory, run:")
		fmt.Println("  tcp-warden plugins install <github-url-or-local-path>")
		fmt.Println()
		fmt.Println("Available plugins in routewarden/plugins repository:")
		fmt.Println("  • ssh:          tcp-warden plugins install https://github.com/routewarden/plugins/ssh")
		fmt.Println("  • smtp:         tcp-warden plugins install https://github.com/routewarden/plugins/smtp")
		fmt.Println("  • pop3:         tcp-warden plugins install https://github.com/routewarden/plugins/pop3")
		fmt.Println("  • imap:         tcp-warden plugins install https://github.com/routewarden/plugins/imap")
		fmt.Println("  • postgres:     tcp-warden plugins install https://github.com/routewarden/plugins/postgres")
		fmt.Println("  • mysql:        tcp-warden plugins install https://github.com/routewarden/plugins/mysql")
		fmt.Println("  • redis:        tcp-warden plugins install https://github.com/routewarden/plugins/redis")
		fmt.Println("  • mongodb:      tcp-warden plugins install https://github.com/routewarden/plugins/mongodb")
		fmt.Println("  • memcached:    tcp-warden plugins install https://github.com/routewarden/plugins/memcached")
		fmt.Println("  • amqp:         tcp-warden plugins install https://github.com/routewarden/plugins/amqp")
		fmt.Println("  • http:         tcp-warden plugins install https://github.com/routewarden/plugins/http")
		fmt.Println("  • ldap:         tcp-warden plugins install https://github.com/routewarden/plugins/ldap")
		fmt.Println("  • vnc:          tcp-warden plugins install https://github.com/routewarden/plugins/vnc")
		fmt.Println("  • ftp:          tcp-warden plugins install https://github.com/routewarden/plugins/ftp")
		fmt.Println("  • tls-sni:      tcp-warden plugins install https://github.com/routewarden/plugins/tls_sni")
		fmt.Println("  • mqtt:         tcp-warden plugins install https://github.com/routewarden/plugins/mqtt")
		fmt.Println("  • minecraft:    tcp-warden plugins install https://github.com/routewarden/plugins/minecraft")
		fmt.Println("  • dns:          tcp-warden plugins install https://github.com/routewarden/plugins/dns")
		fmt.Println("  • bittorrent:   tcp-warden plugins install https://github.com/routewarden/plugins/bittorrent")
		fmt.Println("  • echo-filter:  tcp-warden plugins install https://github.com/routewarden/plugins/echo_filter")
		return
	}

	fmt.Printf("%-14s %-9s %-14s %-22s %s\n", "PLUGIN", "VERSION", "STATUS", "PROTOCOLS", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 100))
	for _, p := range list {
		statusStr := "DISABLED"
		if p.Enabled && p.Status == plugins.StatusActive {
			statusStr = "✓ ACTIVE"
		} else if p.TestError != "" {
			statusStr = "✗ FAILED"
		} else if !p.Enabled {
			statusStr = "DISABLED"
		}

		desc := p.Description
		if !p.Enabled {
			desc += " (disabled by default)"
		}

		fmt.Printf("%-14s %-9s %-14s %-22s %s\n",
			p.Name,
			p.Version,
			statusStr,
			strings.Join(p.Protocols, ", "),
			truncate(desc, 38),
		)
	}
}

func handlePluginsTest(args []string) {
	fs := flag.NewFlagSet("plugins test", flag.ExitOnError)
	_ = fs.Parse(args)

	fmt.Println("🧪 Executing RouteWarden Plugin Self-Tests...")
	target := ""
	if len(fs.Args()) > 0 {
		target = fs.Args()[0]
	}

	if target != "" {
		res, err := plugins.Global().RunSelfTest(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error testing plugin %q: %v\n", target, err)
			os.Exit(1)
		}
		if res.Passed {
			fmt.Printf("✓ %-14s - PASSED (%v)\n", res.PluginName, res.Duration)
		} else {
			fmt.Printf("✗ %-14s - FAILED (%v): %v\n", res.PluginName, res.Duration, res.Error)
			os.Exit(1)
		}
		return
	}

	results := plugins.RunSelfTests()
	var names []string
	for k := range results {
		names = append(names, k)
	}
	sort.Strings(names)

	passedCount := 0
	failedCount := 0

	for _, name := range names {
		res := results[name]
		if res.Passed {
			passedCount++
			fmt.Printf("  ✓ %-14s - PASSED (%v)\n", res.PluginName, res.Duration)
		} else {
			failedCount++
			fmt.Printf("  ✗ %-14s - FAILED (%v): %v\n", res.PluginName, res.Duration, res.Error)
		}
	}

	fmt.Println()
	if failedCount > 0 {
		fmt.Printf("⚠️ Results: %d passed, %d failed. Failed plugins have been automatically disabled.\n", passedCount, failedCount)
		os.Exit(1)
	} else {
		fmt.Printf("✓ Results: %d/%d passed. All registered plugins healthy and active.\n", passedCount, passedCount)
	}
}

func contains(list []string, item string) bool {
	for _, s := range list {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func removeFromList(list []string, item string) []string {
	var res []string
	for _, s := range list {
		if !strings.EqualFold(s, item) {
			res = append(res, s)
		}
	}
	return res
}

func isPluginInEntries(cfg *config.Config, name string) bool {
	if cfg == nil || cfg.Plugins.Entries == nil {
		return false
	}
	_, ok := cfg.Plugins.Entries[strings.ToLower(name)]
	return ok
}

func isStandardProtocol(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "tcp", "udp", "generic", "":
		return true
	default:
		return false
	}
}


