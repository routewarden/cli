package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/routewarden/cli/engine"
)

//go:embed config.schema.json
var embeddedSchemaJSON string

var version = "2.1.0"

func printUsage() {
	fmt.Println(`RouteWarden CLI (` + version + `) — Security inspection & configuration tool

Usage:
  rwarden <command> [options]

Commands:
  test        Simulate request path and query inspection against patterns
  validate    Validate a RouteWarden configuration file (JSON)
  generate    Generate gateway configuration (traefik-yaml, traefik-toml, traefik-labels, caddy, nginx)
  sandbox     Spin up an ephemeral gateway container (Traefik, Caddy, NGINX) to test live
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
		handleSchema()

	case "validate":
		handleValidate(os.Args[2:])

	case "generate":
		handleGenerate(os.Args[2:])

	case "sandbox":
		handleSandbox(os.Args[2:])

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

func handleGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	target := fs.String("target", "", "Target gateway format: traefik-yaml, traefik-toml, traefik-labels, caddy, nginx")
	configPath := fs.String("config", "", "Path to RouteWarden JSON config file (or '-' for stdin)")
	_ = fs.Parse(args)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target <traefik-yaml|traefik-toml|traefik-labels|caddy|nginx> is required")
		os.Exit(1)
	}

	var data []byte
	var err error

	if *configPath == "-" || *configPath == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 || *configPath == "-" {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading config from stdin: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "Error: --config <filepath> or stdin is required")
			os.Exit(1)
		}
	} else {
		data, err = os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file %s: %v\n", *configPath, err)
			os.Exit(1)
		}
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
	configPath := fs.String("config", "", "Path to gateway config (traefik.toml, traefik.yaml, docker-compose.yaml, Caddyfile, nginx.conf, or routewarden.json, or '-' for stdin)")
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
	runTest := fs.Bool("test", false, "Run automated live HTTP test assertions against container then teardown")
	detach := fs.Bool("detach", false, "Run container in background mode")
	shortDetach := fs.Bool("d", false, "Alias for --detach")
	_ = fs.Parse(args)

	shouldPrint := *printConfig || *shortPrint
	shouldDetach := *detach || *shortDetach

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
	if !*dryRun {
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
		if strings.Contains(strContent, "statusCode") || strings.Contains(strContent, "status_code") || strings.Contains(strContent, "status ") {
			re := regexp.MustCompile(`(?:statusCode|status_code|status)\s*[:=]?\s*(\d{3})`)
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
		DryRun:             *dryRun,
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

	if *dryRun {
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

func handleSchema() {
	fmt.Print(embeddedSchemaJSON)
}

func handleValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to RouteWarden JSON config file (or '-' for stdin)")
	_ = fs.Parse(args)

	var data []byte
	var err error
	targetName := *configPath

	if *configPath == "-" || *configPath == "" {
		// Check if input is being piped via stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 || *configPath == "-" {
			targetName = "stdin"
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading config from stdin: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "Error: --config <filepath> or stdin is required")
			os.Exit(1)
		}
	} else {
		data, err = os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file %s: %v\n", *configPath, err)
			os.Exit(1)
		}
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
	if len(cfg.BlockPatterns) > 0 {
		fmt.Printf("  - Custom block patterns: %d\n", len(cfg.BlockPatterns))
	}
	if len(cfg.AllowPatterns) > 0 {
		fmt.Printf("  - Custom allow patterns: %d\n", len(cfg.AllowPatterns))
	}
	if len(cfg.CheckHeaders) > 0 {
		fmt.Printf("  - Monitored headers: %v\n", cfg.CheckHeaders)
	}
}

func handleTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	testPath := fs.String("path", "", "Request path to evaluate (e.g. /.env or /api/v1)")
	testQuery := fs.String("query", "", "Request query string to evaluate (optional)")
	testMethod := fs.String("method", "GET", "HTTP method (default: GET)")
	testIP := fs.String("ip", "", "Client IP address to evaluate against allowedIps (optional)")
	configPath := fs.String("config", "", "Optional path to RouteWarden JSON config file (or '-' for stdin)")
	checkQuery := fs.Bool("check-query", true, "Enable query string inspection")
	headerVal := fs.String("header", "", "Header in Key:Value format to test (optional)")
	_ = fs.Parse(args)

	if *testPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --path <url-path> is required")
		os.Exit(1)
	}

	cfg := engine.CreateConfig()
	cfg.CheckQuery = *checkQuery
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
		// When --config is used, only override checkQuery if explicitly specified on CLI
		queryFlagPassed := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "check-query" {
				queryFlagPassed = true
			}
		})
		if queryFlagPassed {
			cfg.CheckQuery = *checkQuery
		}
	} else {
		cfg.CheckQuery = *checkQuery
	}

	headers := make(map[string]string)
	if *headerVal != "" {
		parts := strings.SplitN(*headerVal, ":", 2)
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

	eval := eng.EvaluateWithClientIP(*testMethod, *testPath, *testQuery, headers, *testIP)

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
