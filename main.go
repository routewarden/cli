package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/routewarden/cli/engine"
)

//go:embed config.schema.json
var embeddedSchemaJSON string

var version = "1.0.0"

func printUsage() {
	fmt.Println(`RouteWarden CLI (` + version + `) — Security inspection & configuration tool

Usage:
  rwarden <command> [options]

Commands:
  test        Simulate request path and query inspection against patterns
  validate    Validate a RouteWarden configuration file (JSON)
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
	checkQuery := fs.Bool("check-query", true, "Enable query string inspection")
	headerVal := fs.String("header", "", "Header in Key:Value format to test (optional)")
	_ = fs.Parse(args)

	if *testPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --path <url-path> is required")
		os.Exit(1)
	}

	cfg := engine.CreateConfig()
	cfg.CheckQuery = *checkQuery

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
	fmt.Println()

	eval := eng.Evaluate(*testMethod, *testPath, *testQuery, headers)

	fmt.Printf("  Candidate paths extracted (%d):\n", len(eval.CandidatePaths))
	for _, c := range eval.CandidatePaths {
		fmt.Printf("    - %s\n", c)
	}

	if eval.Blocked {
		fmt.Printf("\nResult: 🛑 BLOCKED (HTTP Status %d)\n", cfg.StatusCode)
		fmt.Printf("  Reason:  %s\n", eval.Reason)
		fmt.Printf("  Target:  %s\n", eval.MatchedTarget)
		fmt.Printf("  Pattern: %s\n", eval.MatchedPattern)
	} else if eval.Bypassed {
		fmt.Printf("\nResult: ⏭️ BYPASSED (%s)\n", eval.Reason)
	} else {
		fmt.Println("\nResult: ✅ ALLOWED (Passes inspection)")
		if eval.MatchedPattern != "" {
			fmt.Printf("  Allowlist Override: %s\n", eval.MatchedPattern)
		}
	}
}
