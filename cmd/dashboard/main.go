package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/routewarden/cli/daemon"
	"github.com/routewarden/cli/observability"
	"github.com/routewarden/cli/shipper"
)

var version = "5.3.1"

func printUsage() {
	fmt.Println(`RouteWarden Dashboard (` + version + `) — Standalone Real-Time SOC Security Dashboard

Usage:
  rwarden [command] [options]

Commands:
  up          Launch SOC dashboard web server (default command)
                e.g. rwarden up --port 7890
                e.g. rwarden -d
                e.g. rwarden --auth admin:secret
  status      Check status of running dashboard
                e.g. rwarden status
  stop        Stop running background dashboard daemon
                e.g. rwarden stop
  keys        Manage API keys for distributed log shipping
                e.g. rwarden keys create edge-01
                e.g. rwarden keys list
                e.g. rwarden keys revoke <id>
  export      Export standalone Docker Compose stack
                e.g. rwarden export ./dashboard
  version     Show dashboard version

Flags for up:
  --port, -p           Port for dashboard UI (default: 7890)
  --host               Host IP interface to bind (default: all interfaces)
  --auth, -a           HTTP Basic Auth credentials ('user:password')
  --no-open            Do not automatically open browser
  -d, --detach         Run in detached background mode
  --file, -f           Log file to monitor
  --container, -c      Tail a specific Docker container
  --dir                Directory to store configs (default: ~/.routewarden/dashboard)
  --verbose, -v        Enable verbose event-level logging
  --retention          Data retention window (e.g. '30d', '7d', '48h', or '0' for unlimited)
  --max-events         Maximum event row count capacity (default: 100000, 0 = unlimited)
  --prune-interval     Automated background pruning frequency (default: '1h')
  --max-log-size       Maximum access.log size before rotation (default: '50MB')
`)
}

func main() {
	if len(os.Args) < 2 {
		handleDashboardUp([]string{})
		return
	}

	command := os.Args[1]
	switch strings.ToLower(command) {
	case "up", "start":
		handleDashboardUp(os.Args[2:])
	case "status", "ps":
		daemon.Status("dashboard", "RouteWarden Dashboard")
	case "stop", "down":
		_, _ = daemon.Stop("dashboard", "RouteWarden Dashboard")
	case "keys":
		handleDashboardKeys(os.Args[2:])
	case "export":
		handleDashboardExport(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("rwarden-dashboard version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		// If command starts with "-", pass all arguments directly to dashboard up
		if strings.HasPrefix(command, "-") {
			handleDashboardUp(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func handleDashboardUp(args []string) {
	defaultPort := 7890
	if pStr := os.Getenv("PORT"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
			defaultPort = p
		}
	}
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	port := fs.Int("port", defaultPort, "Port for SOC dashboard UI (default: 7890 or PORT env var)")
	dir := fs.String("dir", "", "Directory to store dashboard configs (default: ~/.routewarden/dashboard)")
	file := fs.String("file", "", "Log file to monitor")
	fs.StringVar(file, "f", "", "Alias for --file")
	container := fs.String("container", "", "Tail a specific Docker container by name or ID")
	fs.StringVar(container, "c", "", "Alias for --container")
	label := fs.String("label", "", "Docker label to filter containers (default: routewarden=true)")
	fs.StringVar(label, "l", "", "Alias for --label")
	noOpen := fs.Bool("no-open", false, "Do not automatically open the browser")
	detach := fs.Bool("detach", false, "Run dashboard in background (detached) mode")
	fs.BoolVar(detach, "d", false, "Alias for --detach")
	exportOnly := fs.Bool("export", false, "Export dashboard files without starting")
	geoipDB := fs.String("geoip-db", "", "Path to MaxMind database")
	fs.StringVar(geoipDB, "maxmind", "", "Alias for --geoip-db")
	auth := fs.String("auth", "", "Optional HTTP Basic Auth credentials ('user:password')")
	fs.StringVar(auth, "a", "", "Alias for --auth")
	user := fs.String("user", "", "Optional HTTP Basic Auth username")
	pass := fs.String("password", "", "Optional HTTP Basic Auth password")
	host := fs.String("host", "", "Host IP interface to bind")
	verbose := fs.Bool("verbose", false, "Enable verbose event-level logging")
	fs.BoolVar(verbose, "v", false, "Alias for --verbose")
	retention := fs.String("retention", "30d", "Data retention window (e.g. '30d', '7d', '48h', or '0' for unlimited)")
	maxEvents := fs.Int("max-events", 100000, "Maximum event row count capacity before pruning (default: 100000, 0 = unlimited)")
	pruneInterval := fs.String("prune-interval", "1h", "Automated background pruning frequency (e.g. '1h', '30m')")
	maxLogSize := fs.String("max-log-size", "50MB", "Maximum size of access.log before rotation (e.g. '50MB', '100MB')")
	_ = shipper.ParseFlagsLenient(fs, args)

	if *host == "" {
		if envHost := os.Getenv("RW_DASHBOARD_HOST"); envHost != "" {
			*host = envHost
		}
	}

	if *detach && os.Getenv("_RW_DETACHED") != "1" {
		bindHost := *host
		if bindHost == "" {
			bindHost = "127.0.0.1"
		}
		targetURL := fmt.Sprintf("http://%s:%d", bindHost, *port)
		_ = daemon.SpawnDetached("dashboard", "RouteWarden Dashboard", append([]string{"up"}, args...), *port, targetURL)
		return
	}

	if os.Getenv("_RW_DETACHED") == "1" {
		defer daemon.RemovePID("dashboard")
	}

	if *file == "" && fs.NArg() > 0 && !strings.HasPrefix(fs.Arg(0), "-") {
		*file = fs.Arg(0)
	}

	if *geoipDB != "" {
		if err := observability.InitMaxMind(*geoipDB); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: Failed to load specified MaxMind database (%s): %v\n", *geoipDB, err)
		}
	}

	if *exportOnly {
		target := *dir
		if target == "" {
			target = "./dashboard"
		}
		if err := observability.Export(target); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting dashboard assets: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Exported dashboard configuration to %s\n", target)
		return
	}

	authStr := *auth
	if authStr == "" && *user != "" {
		authStr = *user + ":" + *pass
	}

	verboseStr := "false"
	if *verbose {
		verboseStr = "true"
	}

	ctx := context.Background()
	if err := observability.Up(ctx, *dir, *port, *noOpen, *file, *container, *label, authStr, *host, verboseStr, *retention, strconv.Itoa(*maxEvents), *pruneInterval, *maxLogSize); err != nil {
		fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
		os.Exit(1)
	}
}

func handleDashboardExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	dirFlag := fs.String("dir", "", "Directory to export dashboard stack files")
	_ = shipper.ParseFlagsLenient(fs, args)

	targetDir := "./dashboard"
	if *dirFlag != "" {
		targetDir = *dirFlag
	} else if fs.NArg() > 0 {
		targetDir = fs.Arg(0)
	}
	if err := observability.Export(targetDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting dashboard stack: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Exported RouteWarden Security Dashboard to %q\n", targetDir)
}

func handleDashboardKeys(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: rwarden keys <create|list|revoke> [args]")
		return
	}

	subcmd := args[0]
	switch subcmd {
	case "create", "new", "add":
		fs := flag.NewFlagSet("keys create", flag.ExitOnError)
		dir := fs.String("dir", "", "Dashboard storage directory")
		_ = shipper.ParseFlagsLenient(fs, args[1:])

		remaining := fs.Args()
		if len(remaining) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: rwarden keys create <agent-name>")
			os.Exit(1)
		}
		name := remaining[0]

		_, _, err := observability.EnsureServerKeypair(*dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to initialize server keypair: %v\n", err)
			os.Exit(1)
		}

		rawToken, key, err := observability.CreateAgentKey(name, *dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error creating agent key: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("🔑 Agent Key Created Successfully!")
		fmt.Println("─────────────────────────────────────────────────────────────")
		fmt.Printf("  Agent Name:   %s\n", key.Name)
		fmt.Printf("  Agent ID:     %s\n", key.ID)
		fmt.Printf("  Token:        %s\n", rawToken)
		fmt.Println("─────────────────────────────────────────────────────────────")
		fmt.Println("💡 To connect a remote server, run this on the remote host:")
		fmt.Printf("   rwarden register --url http://<dashboard-ip>:7890 --key %s\n\n", rawToken)
		fmt.Println("   rwarden push")

	case "list", "ls":
		fs := flag.NewFlagSet("keys list", flag.ExitOnError)
		dir := fs.String("dir", "", "Dashboard storage directory")
		_ = shipper.ParseFlagsLenient(fs, args[1:])

		keys, err := observability.ListAgentKeys(*dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error listing keys: %v\n", err)
			os.Exit(1)
		}

		if len(keys) == 0 {
			fmt.Println("ℹ️  No remote agent keys created yet.")
			return
		}

		fmt.Printf("🔑 Registered Remote Agents (%d):\n", len(keys))
		fmt.Printf("%-18s %-20s %-16s %-10s %s\n", "ID", "NAME", "TOKEN PREFIX", "STATUS", "LAST SEEN")
		fmt.Println(strings.Repeat("─", 80))
		for _, k := range keys {
			status := "ACTIVE"
			if k.Revoked {
				status = "REVOKED"
			}
			lastSeen := k.LastSeenAt
			if lastSeen == "" {
				lastSeen = "never"
			}
			fmt.Printf("%-18s %-20s %-16s %-10s %s\n", k.ID, k.Name, k.Prefix, status, lastSeen)
		}

	case "revoke", "rm", "delete":
		fs := flag.NewFlagSet("keys revoke", flag.ExitOnError)
		dir := fs.String("dir", "", "Dashboard storage directory")
		_ = shipper.ParseFlagsLenient(fs, args[1:])

		remaining := fs.Args()
		if len(remaining) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: rwarden keys revoke <id-or-name>")
			os.Exit(1)
		}
		target := remaining[0]

		if err := observability.RevokeAgentKey(target, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to revoke key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Revoked key %q\n", target)
	}
}
