package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/routewarden/cli/proxy"
	"github.com/routewarden/cli/proxy/config"
	"github.com/routewarden/cli/proxy/plugins"
	_ "github.com/routewarden/cli/proxy/plugins/all"
)

func handleTCP(args []string) {
	subcmd := "up"
	var remainingArgs []string

	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		subcmd = strings.ToLower(args[0])
		remainingArgs = args[1:]
	} else {
		remainingArgs = args
	}

	switch subcmd {
	case "help":
		fmt.Println(`RouteWarden TCP Proxy — Protocol-Aware Layer 4 Security Proxy

Usage:
  rwarden tcp [command] [flags]

Commands:
  up, start, run   Start the TCP security proxy (default)
  down, stop       Stop the running background TCP proxy daemon
  status, ps       Check running status of TCP proxy daemon
  reload           Send SIGHUP reload signal to running proxy
  validate         Validate YAML configuration file syntax and rules
  plugins          Manage and test modular protocol plugins
  version          Show TCP proxy version

Flags for up:
  --config, -c     Path to YAML config file (default: tcp-warden.yaml)
  --detach, -d     Run proxy in background (detached) mode
  --verbose, -v    Enable verbose logging`)
		return

	case "version", "--version", "-v":
		fmt.Printf("RouteWarden TCP Proxy (%s)\n", version)
		return

	case "down", "stop":
		_, _ = stopDaemon("tcp", "RouteWarden TCP Proxy")

	case "status", "ps":
		checkDaemonStatus("tcp", "RouteWarden TCP Proxy")

	case "reload":
		pid, err := readPID("tcp")
		if err != nil || pid <= 0 || !checkProcessAlive(pid) {
			fmt.Fprintln(os.Stderr, "❌ RouteWarden TCP Proxy is not currently running.")
			os.Exit(1)
		}
		if err := signalProcess(pid, syscall.SIGHUP); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to send SIGHUP reload signal to PID %d: %v\n", pid, err)
			os.Exit(1)
		}
		fmt.Printf("✓ Sent reload signal (SIGHUP) to RouteWarden TCP Proxy (PID: %d)\n", pid)

	case "validate":
		fs := flag.NewFlagSet("tcp validate", flag.ExitOnError)
		configPath := fs.String("config", "", "Path to YAML config file")
		fs.StringVar(configPath, "c", "", "Alias for --config")
		_ = parseFlagsLenient(fs, remainingArgs)
		if *configPath == "" && fs.NArg() > 0 && !strings.HasPrefix(fs.Arg(0), "-") {
			*configPath = fs.Arg(0)
		}
		if *configPath == "" {
			*configPath = resolveTCPConfigPath("")
		}

		cfg, err := config.Load(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Validation failed: %v\n", err)
			os.Exit(1)
		}
		for _, w := range cfg.Warnings {
			fmt.Printf("⚠️  [CONFIG WARN] %s\n", w)
		}
		fmt.Printf("✓ Configuration is valid: %s (%d services configured)\n", *configPath, len(cfg.Services))

	case "plugins":
		handleTCPPlugins(remainingArgs)

	case "up", "start", "run":
		fs := flag.NewFlagSet("tcp", flag.ExitOnError)
		configPath := fs.String("config", "", "Path to YAML config file (default: tcp-warden.yaml)")
		fs.StringVar(configPath, "c", "", "Alias for --config")
		detach := fs.Bool("detach", false, "Run TCP proxy in background (detached) mode")
		fs.BoolVar(detach, "d", false, "Alias for --detach")
		verbose := fs.Bool("verbose", false, "Enable verbose logging")
		fs.BoolVar(verbose, "v", false, "Alias for --verbose")
		_ = parseFlagsLenient(fs, remainingArgs)

		if *configPath == "" && fs.NArg() > 0 && !strings.HasPrefix(fs.Arg(0), "-") {
			*configPath = fs.Arg(0)
		}

		resolvedPath := resolveTCPConfigPath(*configPath)

		if *detach && os.Getenv("_RW_DETACHED") != "1" {
			_ = spawnDetached("tcp", "RouteWarden TCP Proxy", append([]string{"tcp", "up"}, remainingArgs...), 0, "")
			return
		}

		if os.Getenv("_RW_DETACHED") == "1" {
			defer removePID("tcp")
		}

		cfg, err := proxy.LoadConfig(resolvedPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error loading config %s: %v\n", resolvedPath, err)
			os.Exit(1)
		}

		for _, w := range cfg.Warnings {
			fmt.Fprintf(os.Stderr, "⚠️  [CONFIG WARN] %s\n", w)
		}

		fmt.Println("🛡️  Starting RouteWarden Layer 4 Security Proxy...")
		fmt.Printf("   Config: %s\n", resolvedPath)
		fmt.Printf("   Services (%d):\n", len(cfg.Services))
		for name, svc := range cfg.Services {
			status := "enabled"
			if !svc.IsEnabled() {
				status = "disabled"
			}
			fmt.Printf("     • %-14s [%s]  %s -> %s (%s)\n", name, svc.Protocol, svc.Listen, svc.Upstream, status)
		}

		srv, err := proxy.NewServer(cfg, proxy.ServerOptions{
			Verbose: *verbose,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error initializing proxy server: %v\n", err)
			os.Exit(1)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 2)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println("\n🛑 Shutting down RouteWarden TCP Proxy...")
			cancel()
			<-sigCh
			os.Exit(1)
		}()

		hupCh := make(chan os.Signal, 1)
		signal.Notify(hupCh, syscall.SIGHUP)
		go func() {
			for range hupCh {
				fmt.Println("\n🔄 Reloading RouteWarden TCP Proxy configuration...")
				newCfg, err := proxy.LoadConfig(resolvedPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "❌ Configuration reload failed: %v\n", err)
					continue
				}
				if err := srv.Reload(newCfg); err != nil {
					fmt.Fprintf(os.Stderr, "❌ Server reload failed: %v\n", err)
					continue
				}
				fmt.Println("✓ Configuration reloaded successfully.")
			}
		}()

		if err := srv.Start(ctx); err != nil && err != context.Canceled {
			fmt.Fprintf(os.Stderr, "❌ Proxy server error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ RouteWarden TCP Proxy shut down gracefully.")

	default:
		if strings.HasPrefix(subcmd, "-") {
			handleTCP(append([]string{"up"}, args...))
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown tcp subcommand: %q\n\n", subcmd)
		fmt.Fprintln(os.Stderr, "Usage: rwarden tcp [up|down|status|reload|plugins|validate] [flags]")
		os.Exit(1)
	}
}

func resolveTCPConfigPath(customPath string) string {
	if customPath != "" {
		return customPath
	}
	if env := os.Getenv("ROUTEWARDEN_CONFIG"); env != "" {
		return env
	}
	if _, err := os.Stat("tcp-warden.yaml"); err == nil {
		return "tcp-warden.yaml"
	}
	if _, err := os.Stat("tcp-warden.yml"); err == nil {
		return "tcp-warden.yml"
	}
	if _, err := os.Stat("/etc/routewarden/tcp-warden.yaml"); err == nil {
		return "/etc/routewarden/tcp-warden.yaml"
	}
	if _, err := os.Stat("/etc/routewarden/tcp-warden.yml"); err == nil {
		return "/etc/routewarden/tcp-warden.yml"
	}
	home, err := os.UserHomeDir()
	if err == nil {
		p := filepath.Join(home, ".routewarden", "tcp-warden.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		pYml := filepath.Join(home, ".routewarden", "tcp-warden.yml")
		if _, err := os.Stat(pYml); err == nil {
			return pYml
		}
	}
	return "tcp-warden.yaml"
}

func handleTCPPlugins(args []string) {
	subcmd := "list"
	var subargs []string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		subcmd = strings.ToLower(args[0])
		subargs = args[1:]
	} else {
		subargs = args
	}

	switch subcmd {
	case "list":
		list := plugins.List()
		if len(list) == 0 {
			fmt.Println("No modular plugins currently installed.")
			return
		}
		fmt.Printf("%-14s %-9s %-14s %-22s %s\n", "PLUGIN", "VERSION", "STATUS", "PROTOCOLS", "DESCRIPTION")
		fmt.Println(strings.Repeat("-", 90))
		for _, p := range list {
			statusStr := "DISABLED"
			if p.Enabled && p.Status == plugins.StatusActive {
				statusStr = "✓ ACTIVE"
			} else if p.TestError != "" {
				statusStr = "✗ FAILED"
			}
			fmt.Printf("%-14s %-9s %-14s %-22s %s\n",
				p.Name,
				p.Version,
				statusStr,
				strings.Join(p.Protocols, ", "),
				p.Description,
			)
		}

	case "test":
		results := plugins.RunSelfTests()
		fmt.Printf("Executed self-tests on %d plugin(s):\n", len(results))
		allPassed := true
		for name, r := range results {
			if r.Error == nil {
				fmt.Printf("  ✓ %-14s PASS (%s)\n", name, r.Duration)
			} else {
				fmt.Printf("  ✗ %-14s FAIL: %v\n", name, r.Error)
				allPassed = false
			}
		}
		if !allPassed {
			os.Exit(1)
		}

	case "enable":
		if len(subargs) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: rwarden tcp plugins enable <plugin-name>")
			os.Exit(1)
		}
		name := subargs[0]
		if err := plugins.Global().Enable(name); err != nil {
			fmt.Fprintf(os.Stderr, "Error enabling plugin %s: %v\n", name, err)
			os.Exit(1)
		}
		fmt.Printf("✓ Plugin %s is now enabled.\n", name)

	case "disable":
		if len(subargs) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: rwarden tcp plugins disable <plugin-name>")
			os.Exit(1)
		}
		name := subargs[0]
		if err := plugins.Global().Disable(name, "disabled by user"); err != nil {
			fmt.Fprintf(os.Stderr, "Error disabling plugin %s: %v\n", name, err)
			os.Exit(1)
		}
		fmt.Printf("✓ Plugin %s is now disabled.\n", name)

	case "install":
		if len(subargs) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: rwarden tcp plugins install <github-url-or-local-path>")
			os.Exit(1)
		}
		source := subargs[0]
		fmt.Printf("📦 Installing plugin from: %s\n", source)
		res, err := plugins.SyncPluginFromSource("", source, plugins.InstallOptions{
			PluginsDir: "plugins",
			ProjectDir: ".",
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Plugin installation failed: %v\n", err)
			os.Exit(1)
		}
		if res.TestPassed {
			_ = plugins.SavePluginEnablement(plugins.ResolveProjectDir(""), res.Name, true)
			_ = plugins.Global().Enable(res.Name)
			fmt.Printf("✓ Plugin %q [%s] installed and ACTIVATED successfully!\n", res.Name, res.Version)
		} else {
			_ = plugins.SavePluginEnablement(plugins.ResolveProjectDir(""), res.Name, false)
			fmt.Printf("⚠️ Plugin %q [%s] was installed but DISABLED due to test failure.\n", res.Name, res.Version)
		}

	default:
		fmt.Fprintln(os.Stderr, "Usage: rwarden tcp plugins [list|test|enable|disable|install]")
		os.Exit(1)
	}
}
