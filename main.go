package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/routewarden/cli/engine"
	"github.com/routewarden/cli/observability"
)

//go:embed config.schema.json
var embeddedSchemaJSON string

//go:embed tcp-warden.schema.json
var embeddedTCPSchemaJSON string

var version = "4.3.0"

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func printUsage() {
	fmt.Println(`RouteWarden CLI (` + version + `) — Security inspection & configuration tool

Usage:
  rwarden <command> [arguments] [options]

Commands:
  test        Simulate request path and query inspection against patterns
                e.g. rwarden test /.env
                e.g. rwarden test -X POST -H "User-Agent: badbot" /.env
  validate    Validate a RouteWarden configuration file (JSON)
                e.g. rwarden validate [routewarden.json]
  generate    Generate gateway configuration (traefik-yaml, traefik-toml, traefik-labels, caddy, nginx, tcp-warden)
                e.g. rwarden generate caddy [routewarden.json]
                e.g. rwarden generate tcp-warden [routewarden.json]
  sandbox     Spin up an ephemeral gateway container (Traefik, Caddy, NGINX) to test live
                e.g. rwarden sandbox caddy [Caddyfile]
                e.g. rwarden sandbox traefik --test
  dashboard   Launch or manage the Grafana + Loki + Alloy security dashboard
                e.g. rwarden dashboard
                e.g. rwarden dashboard up --port 3000
                e.g. rwarden dashboard up --enable-alerting
                e.g. rwarden dashboard down
                e.g. rwarden dashboard status
                e.g. rwarden dashboard export ./observability
  cleanup     Stop and remove any running RouteWarden sandbox containers
  schema      Output the official RouteWarden JSON Schema
  version     Show CLI version

Run 'rwarden <command> --help' for command-specific flags and options.`)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "version", "--version", "-v":
		fmt.Printf("rwarden version %s\n", version)

	case "schema":
		handleSchema(os.Args[2:])

	case "validate":
		handleValidate(os.Args[2:])

	case "generate":
		handleGenerate(os.Args[2:])

	case "sandbox":
		handleSandbox(os.Args[2:])

	case "dashboard":
		handleDashboard(os.Args[2:])

	case "cleanup":
		handleCleanup(os.Args[2:])

	case "test":
		handleTest(os.Args[2:])

	case "help", "--help", "-h":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func handleDashboard(args []string) {
	subcmd := "up"
	var remainingArgs []string

	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		subcmd = args[0]
		remainingArgs = args[1:]
	} else {
		remainingArgs = args
	}

	ctx := context.Background()

	switch subcmd {
	case "export":
		fs := flag.NewFlagSet("dashboard export", flag.ExitOnError)
		dirFlag := fs.String("dir", "", "Directory to export observability stack files")
		_ = fs.Parse(remainingArgs)

		targetDir := "./observability"
		if *dirFlag != "" {
			targetDir = *dirFlag
		} else if fs.NArg() > 0 {
			targetDir = fs.Arg(0)
		}
		if err := observability.Export(targetDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting observability stack: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Exported RouteWarden Observability Stack to %q\n", targetDir)
		fmt.Println("   Includes: docker-compose.yml, config.alloy, loki-config.yaml, and grafana dashboards")
		fmt.Printf("   Run: cd %s && docker compose up -d\n", targetDir)

	case "down", "stop":
		fs := flag.NewFlagSet("dashboard down", flag.ExitOnError)
		dir := fs.String("dir", "", "Directory containing observability stack (default: ~/.routewarden/observability)")
		_ = fs.Parse(remainingArgs)

		if err := observability.Down(ctx, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping observability stack: %v\n", err)
			os.Exit(1)
		}

	case "status", "ps":
		fs := flag.NewFlagSet("dashboard status", flag.ExitOnError)
		dir := fs.String("dir", "", "Directory containing observability stack (default: ~/.routewarden/observability)")
		_ = fs.Parse(remainingArgs)

		if err := observability.Status(ctx, *dir); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking status: %v\n", err)
			os.Exit(1)
		}

	case "up", "start":
		fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
		port := fs.Int("port", 3000, "Port for Grafana dashboard UI (default: 3000)")
		lokiPort := fs.Int("loki-port", 3100, "Port for Loki log engine (default: 3100)")
		dir := fs.String("dir", "", "Directory to store observability configs (default: ~/.routewarden/observability)")
		noOpen := fs.Bool("no-open", false, "Do not automatically open the browser")
		exportOnly := fs.Bool("export", false, "Export observability files without starting containers")
		enableAlerting := fs.Bool("enable-alerting", false, "Enable pre-configured Grafana threat alert rules and notification channels")
		fs.BoolVar(enableAlerting, "alerting", false, "Alias for --enable-alerting")
		var envList stringSlice
		fs.Var(&envList, "env", "Environment variable to pass to dashboard stack (repeatable, e.g. --env GF_SECURITY_ADMIN_PASSWORD=secret)")
		fs.Var(&envList, "e", "Alias for --env (repeatable)")
		_ = fs.Parse(remainingArgs)

		if *exportOnly {
			target := *dir
			if target == "" {
				target = "./observability"
			}
			if err := observability.Export(target); err != nil {
				fmt.Fprintf(os.Stderr, "Error exporting observability assets: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("✅ Exported observability configuration to %s\n", target)
			return
		}

		if err := observability.Up(ctx, *dir, *port, *lokiPort, *noOpen, *enableAlerting, envList...); err != nil {
			fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
			fmt.Fprintln(os.Stderr, "\nTip: To export and run manually, run: rwarden dashboard export ./observability")
			os.Exit(1)
		}

	default:
		// Unknown subcommand — if it looks like a flag, try running 'up' with all args;
		// otherwise error clearly to avoid silently launching the stack.
		if strings.HasPrefix(subcmd, "-") {
			// subcmd was actually a flag, not a subcommand — re-parse as 'up' with all original args
			handleDashboard(append([]string{"up"}, args...))
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown dashboard subcommand: %q\n\n", subcmd)
		fmt.Fprintln(os.Stderr, "Usage: rwarden dashboard [up|down|status|export] [flags]")
		os.Exit(1)
	}
}

// openBrowser opens the given URL in the default system browser.
func openBrowser(url string) {
	var cmd string
	var cmdArgs []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		cmdArgs = []string{url}
	case "windows":
		cmd = "rundll32"
		cmdArgs = []string{"url.dll,FileProtocolHandler", url}
	default: // linux, freebsd, etc.
		cmd = "xdg-open"
		cmdArgs = []string{url}
	}
	_ = exec.Command(cmd, cmdArgs...).Start()
}

func handleCleanup(args []string) {
	fmt.Println("🧹 Cleaning up RouteWarden sandbox containers...")
	removed, err := engine.CleanupSandboxes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error cleaning up sandboxes: %v\n", err)
		os.Exit(1)
	}

	if len(removed) == 0 {
		fmt.Println("No active RouteWarden sandbox containers found.")
		return
	}

	fmt.Printf("Successfully removed %d sandbox container(s):\n", len(removed))
	for _, name := range removed {
		fmt.Printf("  • %s\n", name)
	}
}

// parseFlagsLenient rearranges arguments so flags can appear before or after positional arguments.
func parseFlagsLenient(fs *flag.FlagSet, args []string) error {
	var flags []string
	var posArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			posArgs = append(posArgs, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flagName := strings.TrimLeft(arg, "-")
			if found := strings.Contains(flagName, "="); found {
				flags = append(flags, arg)
				continue
			}
			// --help / -h are handled internally by flag.FlagSet and never appear
			// in fs.Lookup(); treat them as boolean flags so they don't swallow
			// the next positional argument.
			if flagName == "help" || flagName == "h" {
				flags = append(flags, arg)
				continue
			}
			f := fs.Lookup(flagName)
			if f != nil {
				type boolFlag interface {
					IsBoolFlag() bool
				}
				if bf, ok := f.Value.(boolFlag); ok && bf.IsBoolFlag() {
					flags = append(flags, arg)
					continue
				}
			}
			flags = append(flags, arg)
			if i+1 < len(args) && (!strings.HasPrefix(args[i+1], "-") || args[i+1] == "-") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	return fs.Parse(append(flags, posArgs...))
}

func handleGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	target := fs.String("target", "", "Target gateway format: traefik-yaml, traefik-toml, traefik-labels, caddy, nginx, tcp-warden")
	shortTarget := fs.String("t", "", "Alias for --target")
	configPath := fs.String("config", "", "Path to RouteWarden JSON config file (or '-' for stdin)")
	shortConfig := fs.String("c", "", "Alias for --config")
	_ = parseFlagsLenient(fs, args)

	if *shortTarget != "" && *target == "" {
		*target = *shortTarget
	}
	if *shortConfig != "" && *configPath == "" {
		*configPath = *shortConfig
	}

	for _, arg := range fs.Args() {
		if *target == "" {
			*target = arg
		} else if *configPath == "" {
			*configPath = arg
		}
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target <traefik-yaml|traefik-toml|traefik-labels|caddy|nginx|tcp-warden> is required")
		os.Exit(1)
	}

	if *configPath == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			*configPath = "-"
		} else if _, err := os.Stat("routewarden.json"); err == nil {
			*configPath = "routewarden.json"
		}
	}

	var data []byte
	var err error

	if *configPath == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config from stdin: %v\n", err)
			os.Exit(1)
		}
	} else if *configPath != "" {
		data, err = os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file %s: %v\n", *configPath, err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: --config <filepath> or stdin is required")
		os.Exit(1)
	}

	cfg := engine.CreateConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON configuration: %v\n", err)
		os.Exit(1)
	}

	out, err := cfg.Generate(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(out)
}

func handleSandbox(args []string) {
	if len(args) > 0 && (args[0] == "cleanup" || args[0] == "--cleanup") {
		handleCleanup(args[1:])
		return
	}
	fs := flag.NewFlagSet("sandbox", flag.ExitOnError)
	target := fs.String("target", "", "Target gateway to run: traefik, caddy, nginx (optional if inferrable from config)")
	shortTarget := fs.String("t", "", "Alias for --target")
	configPath := fs.String("config", "", "Path to gateway config (traefik.toml, traefik.yaml, docker-compose.yaml, Caddyfile, nginx.conf, or routewarden.json, or '-' for stdin)")
	shortConfig := fs.String("c", "", "Alias for --config")
	formatFlag := fs.String("format", "", "Explicit config format: json, traefik-toml, traefik-yaml, traefik-labels, caddy, nginx")
	labelsFlag := fs.String("labels", "", "Direct Traefik Docker labels string (e.g. 'traefik.http.middlewares.warden...')")
	probePathFlag := fs.String("probe-path", "", "Additional custom endpoint path to probe during live test")
	probeIPFlag := fs.String("probe-ip", "", "Client IP to simulate for allowlist verification during live test")
	port := fs.Int("port", 8080, "Local host port to bind gateway (default: 8080)")
	ver := fs.String("version", "", "Target gateway version tag (e.g. v3.3, 2.11.4, alpine)")
	pluginVer := fs.String("plugin-version", "", "RouteWarden plugin version/tag/branch (e.g. v1.2.0, v1.1.0, main)")
	pluginPath := fs.String("plugin-path", "", "Local path to RouteWarden plugin directory to mount for development")
	imgOverride := fs.String("image", "", "Custom container image override")
	printConfig := fs.Bool("print-config", false, "Print generated gateway configuration before starting container")
	shortPrint := fs.Bool("p", false, "Alias for --print-config")
	dryRun := fs.Bool("dry-run", false, "Generate config and print docker command without running container")
	shortDryRun := fs.Bool("n", false, "Alias for --dry-run")
	runTest := fs.Bool("test", false, "Run automated live HTTP test assertions against container then teardown")
	detach := fs.Bool("detach", false, "Run container in background mode")
	shortDetach := fs.Bool("d", false, "Alias for --detach")
	_ = parseFlagsLenient(fs, args)

	if *shortTarget != "" && *target == "" {
		*target = *shortTarget
	}
	if *shortConfig != "" && *configPath == "" {
		*configPath = *shortConfig
	}
	for _, arg := range fs.Args() {
		argLower := strings.ToLower(arg)
		if argLower == "traefik" || argLower == "caddy" || argLower == "nginx" {
			if *target == "" {
				*target = argLower
			}
		} else if *configPath == "" {
			*configPath = arg
		}
	}

	shouldPrint := *printConfig || *shortPrint
	shouldDetach := *detach || *shortDetach
	isDryRun := *dryRun || *shortDryRun

	// Determine target
	normTarget := strings.ToLower(strings.TrimSpace(*target))

	// Resolve config content and format
	resolvedConfig := *configPath
	var rawData []byte
	var err error

	if *labelsFlag != "" {
		rawData = []byte(*labelsFlag)
	} else {
		if resolvedConfig == "" {
			// Check default filenames
			candidates := []string{"routewarden.json", "traefik.toml", "traefik.yaml", "traefik.yml", "docker-compose.yaml", "docker-compose.yml", "Caddyfile", "nginx.conf"}
			for _, c := range candidates {
				if _, err := os.Stat(c); err == nil {
					resolvedConfig = c
					break
				}
			}
			if resolvedConfig == "" {
				stat, _ := os.Stdin.Stat()
				if (stat.Mode() & os.ModeCharDevice) == 0 {
					resolvedConfig = "-"
				}
			}
		}

		if resolvedConfig != "" {
			rawData, err = engine.ReadConfigContent(resolvedConfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Determine format
	var format engine.ConfigFormat
	if *formatFlag != "" {
		format = engine.ConfigFormat(strings.ToLower(strings.TrimSpace(*formatFlag)))
	} else if *labelsFlag != "" {
		format = engine.FormatTraefikLabels
	} else {
		format = engine.DetectConfigFormat(resolvedConfig, rawData)
	}

	if normTarget == "" {
		normTarget = engine.InferredTargetFromFormat(format)
	}
	if normTarget == "" {
		fmt.Fprintln(os.Stderr, "Error: --target <traefik|caddy|nginx> is required")
		os.Exit(1)
	}

	if normTarget != "traefik" && normTarget != "caddy" && normTarget != "nginx" {
		fmt.Fprintf(os.Stderr, "Error: unsupported target %q. Must be 'traefik', 'caddy', or 'nginx'\n", normTarget)
		os.Exit(1)
	}

	// Check if Docker is installed & running early (unless in dry-run mode)
	if !isDryRun {
		if err := engine.CheckDockerInstalled(); err != nil {
			fmt.Fprintf(os.Stderr, "Docker error: %v\n", err)
			os.Exit(1)
		}
	}

	cfg := engine.CreateConfig()
	var sandboxConfig string
	expectedStatusCode := 403

	switch format {
	case engine.FormatJSON:
		if len(rawData) > 0 {
			if err := json.Unmarshal(rawData, cfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSON configuration: %v\n", err)
				os.Exit(1)
			}
		}
		sandboxConfig, err = engine.GenerateSandboxConfig(normTarget, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating sandbox configuration: %v\n", err)
			os.Exit(1)
		}
		_, status, _ := cfg.ResolveResponse()
		expectedStatusCode = status

	case engine.FormatTraefikLabels:
		var labels []engine.TraefikLabel
		if *labelsFlag != "" {
			labels = engine.ParseTraefikLabels(string(rawData))
		} else {
			labels = engine.ExtractLabelsFromCompose(string(rawData))
		}
		sandboxConfig, err = engine.ConvertLabelsToTraefikDynamicYAML(labels)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error converting labels to sandbox configuration: %v\n", err)
			os.Exit(1)
		}
		// Detect custom statusCode from labels if present
		for _, l := range labels {
			if strings.HasSuffix(l.Key, ".response.statusCode") {
				if s, err := strconv.Atoi(l.Value); err == nil && s > 0 {
					expectedStatusCode = s
				}
			}
		}

	case engine.FormatTraefikTOML, engine.FormatTraefikYAML, engine.FormatCaddyfile, engine.FormatNginx:
		sandboxConfig = engine.PrepareActualGatewayConfig(normTarget, format, string(rawData))
		// Check if config has custom status code configured
		strContent := string(rawData)
		if strings.Contains(strContent, "statusCode") || strings.Contains(strContent, "status_code") || strings.Contains(strContent, "status ") || strings.Contains(strContent, "block_status") {
			re := regexp.MustCompile(`(?:statusCode|status_code|block_status|status)\s*[:=]?\s*([45]\d{2})`)
			if m := re.FindStringSubmatch(strContent); len(m) == 2 {
				if s, err := strconv.Atoi(m[1]); err == nil && s > 0 {
					expectedStatusCode = s
				}
			}
		}

	default:
		// Fallback to synthetic config from JSON
		if len(rawData) > 0 {
			_ = json.Unmarshal(rawData, cfg)
		}
		sandboxConfig, err = engine.GenerateSandboxConfig(normTarget, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating sandbox configuration: %v\n", err)
			os.Exit(1)
		}
	}

	// If --print-config was requested, print it now
	if shouldPrint {
		fmt.Printf("\n--- [%s Configuration Generated by RouteWarden] (%s) ---\n", strings.ToUpper(normTarget), format)
		fmt.Println(sandboxConfig)
		fmt.Println("-----------------------------------------------------")
	}

	containerName := fmt.Sprintf("rwarden-sandbox-%s-%d", normTarget, time.Now().Unix()%10000)
	opts := engine.SandboxOptions{
		Target:             normTarget,
		Config:             cfg,
		Format:             format,
		ConfigFile:         resolvedConfig,
		RawConfigContent:   sandboxConfig,
		ExpectedStatusCode: expectedStatusCode,
		ProbeIP:            *probeIPFlag,
		Port:               *port,
		Version:            *ver,
		PluginVersion:      *pluginVer,
		PluginPath:         *pluginPath,
		Image:              *imgOverride,
		PrintConfig:        shouldPrint,
		DryRun:             isDryRun,
		RunTest:            *runTest,
		Detach:             shouldDetach || *runTest,
	}
	if *probePathFlag != "" {
		opts.ProbePaths = append(opts.ProbePaths, *probePathFlag)
	}

	// Prepare temporary mounted configuration file
	cfgPath, cleanup, err := engine.PrepareSandboxTempFileWithFormat(normTarget, sandboxConfig, format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error preparing sandbox config: %v\n", err)
		os.Exit(1)
	}
	keepContainer := false
	defer func() {
		if !keepContainer {
			cleanup()
		}
	}()

	imgName, dockerArgs := engine.BuildDockerRunCommand(opts, cfgPath, containerName)

	if isDryRun {
		fmt.Printf("🔍 [Dry Run] Docker command for %s:\n", normTarget)
		fmt.Printf("docker %s\n", strings.Join(dockerArgs, " "))
		return
	}

	fmt.Printf("\n🚀 Launching RouteWarden Sandbox...\n")
	fmt.Printf("  • Target Gateway:  %s (%s)\n", strings.ToUpper(normTarget), imgName)
	fmt.Printf("  • Config Format:   %s\n", format)
	fmt.Printf("  • Bound Port:      http://localhost:%d\n", *port)
	fmt.Printf("  • Expected Block:  HTTP %d\n", expectedStatusCode)
	fmt.Printf("  • Container:       %s\n\n", containerName)

	// Clean up container on exit
	stopContainer := func() {
		if !keepContainer {
			_ = exec.Command("docker", "rm", "-f", containerName).Run()
		}
	}
	defer stopContainer()

	// Capture interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n🛑 Stopping and removing sandbox container...")
		stopContainer()
		cleanup()
		os.Exit(0)
	}()

	// Start docker container in background if testing or detached
	if *runTest || shouldDetach {
		runCmd := exec.Command("docker", dockerArgs...)
		runOut, err := runCmd.CombinedOutput()
		if err != nil {
			stopContainer()
			fmt.Fprintf(os.Stderr, "Failed to start container: %v\nOutput: %s\n", err, string(runOut))
			os.Exit(1)
		}

		if shouldDetach && !*runTest {
			keepContainer = true
			fmt.Printf("✓ Sandbox container %s is running in background!\n", containerName)
			fmt.Printf("  Endpoint: http://localhost:%d\n", *port)
			fmt.Printf("  Stop it with: docker rm -f %s\n", containerName)
			return
		}

		if *runTest {
			passed, total, summary := engine.LiveProbeTestWithOptions(*port, expectedStatusCode, opts.ProbePaths, opts.ProbeIP)
			fmt.Print(summary)
			if passed == total {
				fmt.Printf("\n✨ All %d live tests PASSED successfully against %s sandbox!\n", total, strings.ToUpper(normTarget))
				return
			}
			stopContainer()
			fmt.Fprintf(os.Stderr, "\n❌ Probe tests failed: %d/%d passed.\n", passed, total)
			os.Exit(1)
		}
	} else {
		// Interactive foreground mode
		fmt.Println("Interactive sandbox started. You can test live with:")
		fmt.Printf("  curl -i http://localhost:%d/.env\n", *port)
		fmt.Printf("  curl -i http://localhost:%d/robots.txt\n\n", *port)
		fmt.Println("Press Ctrl+C to terminate the sandbox.")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_ = engine.StreamCommandOutput(ctx, "docker", dockerArgs...)
	}
}

func handleSchema(args []string) {
	fs := flag.NewFlagSet("schema", flag.ExitOnError)
	tcp := fs.Bool("tcp", false, "Output Layer 4 TCP Warden schema (tcp-warden.yaml)")
	fs.BoolVar(tcp, "t", false, "Alias for --tcp")
	_ = parseFlagsLenient(fs, args)

	if *tcp {
		fmt.Print(embeddedTCPSchemaJSON)
		return
	}
	fmt.Print(embeddedSchemaJSON)
}

func handleValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to RouteWarden JSON config file (or '-' for stdin)")
	shortConfig := fs.String("c", "", "Alias for --config")
	_ = parseFlagsLenient(fs, args)

	if *shortConfig != "" && *configPath == "" {
		*configPath = *shortConfig
	}
	if *configPath == "" && len(fs.Args()) > 0 {
		*configPath = fs.Args()[0]
	}

	if *configPath == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			*configPath = "-"
		} else if _, err := os.Stat("routewarden.json"); err == nil {
			*configPath = "routewarden.json"
		}
	}

	var data []byte
	var err error
	targetName := *configPath

	if *configPath == "-" {
		targetName = "stdin"
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config from stdin: %v\n", err)
			os.Exit(1)
		}
	} else if *configPath != "" {
		data, err = os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file %s: %v\n", *configPath, err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: --config <filepath> or stdin is required")
		os.Exit(1)
	}

	// Detect TCP Warden YAML format: must have both `services:` and a yaml/yml extension.
	// We deliberately avoid the broad `version:` heuristic which can falsely match any JSON
	// config that happens to contain a version field in nested data.
	isTCPWardenYAML := strings.Contains(string(data), "services:") &&
		(strings.HasSuffix(targetName, ".yaml") || strings.HasSuffix(targetName, ".yml") ||
			strings.HasPrefix(strings.TrimSpace(string(data)), "version:"))
	if isTCPWardenYAML {
		fmt.Printf("✓ Configuration %s is VALID (TCP Warden YAML format).\n", targetName)
		fmt.Println("  - Target: RouteWarden TCP Warden (tcp-warden)")
		return
	}

	cfg := engine.CreateConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON configuration: %v\n", err)
		os.Exit(1)
	}

	_, err = engine.NewEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Validation FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Configuration %s is VALID.\n", targetName)
	fmt.Printf("  - Enabled: %t\n", cfg.Enabled)
	fmt.Printf("  - Default patterns enabled: %t\n", cfg.EnableDefaultPatterns)
	fmt.Printf("  - Default allow patterns enabled: %t\n", cfg.EnableDefaultAllowPatterns)
	fmt.Printf("  - Methods: %v\n", cfg.Methods)
	customBlockCount := len(cfg.BlockPatterns)
	if customBlockCount > 0 {
		fmt.Printf("  - Custom block patterns: %d\n", customBlockCount)
	}
	if len(cfg.AllowPatterns) > 0 {
		fmt.Printf("  - Custom allow patterns: %d\n", len(cfg.AllowPatterns))
	}
	if len(cfg.AllowedIPs) > 0 {
		fmt.Printf("  - Allowed IPs/CIDRs: %v\n", cfg.AllowedIPs)
	}
	if len(cfg.TrustedProxies) > 0 {
		fmt.Printf("  - Trusted Proxies: %v\n", cfg.TrustedProxies)
	}
	if len(cfg.CheckHeaders) > 0 {
		fmt.Printf("  - Monitored headers: %v\n", cfg.CheckHeaders)
	}
	if cfg.CheckBody || len(cfg.CheckBodyPatterns) > 0 {
		fmt.Printf("  - Body inspection enabled: maxBytes=%d, patterns=%d\n", cfg.CheckBodyMaxBytes, len(cfg.CheckBodyPatterns))
	}
}

func handleTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	testPath := fs.String("path", "", "Request path to evaluate (e.g. /.env or /api/v1)")
	testQuery := fs.String("query", "", "Request query string to evaluate (optional)")
	shortQuery := fs.String("q", "", "Alias for --query")
	testBody := fs.String("body", "", "Request body payload to evaluate (optional)")
	shortBody := fs.String("b", "", "Alias for --body")
	testMethod := fs.String("method", "GET", "HTTP method (default: GET)")
	shortMethodX := fs.String("X", "", "Alias for --method (HTTP method)")
	shortMethodM := fs.String("m", "", "Alias for --method (HTTP method)")
	testIP := fs.String("ip", "", "Client IP address to evaluate against allowedIps (optional)")
	configPath := fs.String("config", "", "Optional path to RouteWarden JSON config file (or '-' for stdin)")
	shortConfig := fs.String("c", "", "Alias for --config")
	checkQuery := fs.Bool("check-query", true, "Enable query string inspection")
	checkBody := fs.Bool("check-body", false, "Enable request body inspection")

	var headerList stringSlice
	fs.Var(&headerList, "header", "Header in Key:Value format to test (repeatable)")
	fs.Var(&headerList, "H", "Alias for --header (repeatable)")
	_ = parseFlagsLenient(fs, args)

	if *shortMethodX != "" {
		*testMethod = *shortMethodX
	} else if *shortMethodM != "" {
		*testMethod = *shortMethodM
	}
	if *shortQuery != "" && *testQuery == "" {
		*testQuery = *shortQuery
	}
	if *shortBody != "" && *testBody == "" {
		*testBody = *shortBody
	}
	if *shortConfig != "" && *configPath == "" {
		*configPath = *shortConfig
	}
	if *testPath == "" && len(fs.Args()) > 0 {
		*testPath = fs.Args()[0]
	}

	if *testPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --path <url-path> is required")
		os.Exit(1)
	}

	if strings.HasPrefix(*testPath, "http://") || strings.HasPrefix(*testPath, "https://") {
		if u, err := url.Parse(*testPath); err == nil {
			if *testQuery == "" && u.RawQuery != "" {
				*testQuery = u.RawQuery
			}
			if u.Path != "" {
				*testPath = u.Path
			} else {
				*testPath = "/"
			}
		}
	} else if *testQuery == "" && strings.Contains(*testPath, "?") {
		parts := strings.SplitN(*testPath, "?", 2)
		*testPath = parts[0]
		*testQuery = parts[1]
	}

	cfg := engine.CreateConfig()
	cfg.CheckQuery = *checkQuery
	cfg.CheckBody = *checkBody
	if *configPath != "" {
		var data []byte
		var err error
		if *configPath == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(*configPath)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file %s: %v\n", *configPath, err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing JSON configuration: %v\n", err)
			os.Exit(1)
		}
		// When --config is used, only override checkQuery/checkBody if explicitly specified on CLI
		queryFlagPassed := false
		bodyFlagPassed := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "check-query" {
				queryFlagPassed = true
			}
			if f.Name == "check-body" {
				bodyFlagPassed = true
			}
		})
		if queryFlagPassed {
			cfg.CheckQuery = *checkQuery
		}
		if bodyFlagPassed {
			cfg.CheckBody = *checkBody
		}
	} else {
		cfg.CheckQuery = *checkQuery
		cfg.CheckBody = *checkBody
	}

	if *testBody != "" && !cfg.CheckBody && len(cfg.CheckBodyPatterns) == 0 {
		cfg.CheckBody = true
	}

	headers := make(map[string]string)
	for _, h := range headerList {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			hdrKey := strings.TrimSpace(parts[0])
			hdrVal := strings.TrimSpace(parts[1])
			headers[hdrKey] = hdrVal
			cfg.CheckHeaders = append(cfg.CheckHeaders, hdrKey)
		}
	}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing inspection engine: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🔍 Testing: %s %s", strings.ToUpper(*testMethod), *testPath)
	if *testQuery != "" {
		fmt.Printf("?%s", *testQuery)
	}
	if *testIP != "" {
		fmt.Printf(" (client IP: %s)", *testIP)
	}
	fmt.Println()

	eval := eng.EvaluateWithBody(*testMethod, *testPath, *testQuery, headers, *testIP, *testBody)

	fmt.Printf("  Candidate paths extracted (%d):\n", len(eval.CandidatePaths))
	for _, c := range eval.CandidatePaths {
		fmt.Printf("    - %s\n", c)
	}

	if eval.Blocked {
		mode, statusCode, _ := cfg.ResolveResponse()
		if mode != "" && !strings.EqualFold(mode, "text") {
			fmt.Printf("\nResult: 🛑 BLOCKED (HTTP Status %d, Mode: %s)\n", statusCode, mode)
		} else {
			fmt.Printf("\nResult: 🛑 BLOCKED (HTTP Status %d)\n", statusCode)
		}
		fmt.Printf("  Reason:  %s\n", eval.Reason)
		fmt.Printf("  Target:  %s\n", eval.MatchedTarget)
		fmt.Printf("  Pattern: %s\n", eval.MatchedPattern)
	} else if eval.Bypassed {
		fmt.Printf("\nResult: ⏭️ BYPASSED (%s)\n", eval.Reason)
	} else {
		fmt.Println("\nResult: ✅ ALLOWED (Passes inspection)")
		if eval.Reason == "ip_whitelisted" {
			fmt.Printf("  Reason:  %s (Whitelisted client IP)\n", eval.Reason)
		} else if eval.MatchedPattern != "" {
			fmt.Printf("  Allowlist Override: %s\n", eval.MatchedPattern)
		}
	}
}
