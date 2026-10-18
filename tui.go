package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/routewarden/cli/engine"
)

func handleTUI(args []string) {
	configPath := "routewarden.json"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		configPath = args[0]
	}

	cfg := engine.CreateConfig()
	cfg.CheckQuery = true
	cfg.CheckBody = true

	loadedConfigName := "defaults (built-in patterns enabled)"
	if data, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(data, cfg); err == nil {
			loadedConfigName = configPath
		}
	}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing RouteWarden engine: %v\n", err)
		os.Exit(1)
	}

	activeMethod := "GET"
	activeIP := "127.0.0.1"
	activeQuery := ""
	activeBody := ""
	activeHeaders := make(map[string]string)

	printTUIBanner(loadedConfigName, cfg)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("rwarden> ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" || line == ":exit" || line == ":quit" || line == ":q" {
			fmt.Println("👋 Exiting RouteWarden interactive simulator.")
			break
		}

		if line == "help" || line == ":help" || line == ":h" {
			printTUIHelp()
			continue
		}

		if line == "clear" || line == ":clear" {
			fmt.Print("\033[H\033[2J")
			printTUIBanner(loadedConfigName, cfg)
			continue
		}

		if strings.HasPrefix(line, ":status") {
			printTUIStatus(loadedConfigName, activeMethod, activeIP, activeQuery, activeBody, activeHeaders, cfg)
			continue
		}

		if strings.HasPrefix(line, ":load ") || strings.HasPrefix(line, ":config ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				file := parts[1]
				data, err := os.ReadFile(file)
				if err != nil {
					fmt.Printf("❌ Failed to read %s: %v\n", file, err)
					continue
				}
				newCfg := engine.CreateConfig()
				if err := json.Unmarshal(data, newCfg); err != nil {
					fmt.Printf("❌ Failed to parse %s: %v\n", file, err)
					continue
				}
				newEng, err := engine.NewEngine(newCfg)
				if err != nil {
					fmt.Printf("❌ Invalid engine config %s: %v\n", file, err)
					continue
				}
				cfg = newCfg
				eng = newEng
				loadedConfigName = file
				fmt.Printf("✅ Loaded policy configuration from %s\n", file)
			}
			continue
		}

		if strings.HasPrefix(line, ":method ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				activeMethod = strings.ToUpper(parts[1])
				fmt.Printf("✓ Active HTTP method set to: %s\n", activeMethod)
			}
			continue
		}

		if strings.HasPrefix(line, ":ip ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				activeIP = parts[1]
				fmt.Printf("✓ Active client IP set to: %s\n", activeIP)
			}
			continue
		}

		if strings.HasPrefix(line, ":query ") {
			activeQuery = strings.TrimSpace(strings.TrimPrefix(line, ":query "))
			fmt.Printf("✓ Active query string set to: %q\n", activeQuery)
			continue
		}

		if strings.HasPrefix(line, ":body ") {
			activeBody = strings.TrimSpace(strings.TrimPrefix(line, ":body "))
			fmt.Printf("✓ Active request body set to: %q\n", activeBody)
			continue
		}

		if strings.HasPrefix(line, ":header ") {
			hdr := strings.TrimSpace(strings.TrimPrefix(line, ":header "))
			parts := strings.SplitN(hdr, ":", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v := strings.TrimSpace(parts[1])
				activeHeaders[k] = v
				fmt.Printf("✓ Header set: %s: %s\n", k, v)
			} else {
				fmt.Println("❌ Format: :header Key: Value")
			}
			continue
		}

		if line == ":clear-headers" {
			activeHeaders = make(map[string]string)
			fmt.Println("✓ Cleared all custom request headers.")
			continue
		}

		// Otherwise, evaluate as request path
		testPath := line
		queryToUse := activeQuery
		if strings.Contains(testPath, "?") {
			parts := strings.SplitN(testPath, "?", 2)
			testPath = parts[0]
			queryToUse = parts[1]
		}

		statusCode := cfg.StatusCode
		if statusCode == 0 {
			statusCode = 403
		}
		result := eng.EvaluateWithBody(activeMethod, testPath, queryToUse, activeHeaders, activeIP, activeBody)
		renderEvaluationResult(testPath, activeMethod, activeIP, queryToUse, activeBody, statusCode, result)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}
}

func printTUIBanner(configName string, cfg *engine.Config) {
	fmt.Println("╔═════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║               🛡️  RouteWarden Interactive Security Simulator                 ║")
	fmt.Println("╚═════════════════════════════════════════════════════════════════════════════╝")
	fmt.Printf(" Configuration: %s | Default Rules: %t | Custom Rules: %d\n",
		configName, cfg.EnableDefaultPatterns, len(cfg.BlockPatterns))
	fmt.Println(" Type any path to test (e.g. /.env, /admin;p=1/config, /static/%252e%252e/.env)")
	fmt.Println(" Type ':help' for commands, or 'exit' to quit.")
	fmt.Println()
}

func printTUIHelp() {
	fmt.Println("Available Interactive Commands:")
	fmt.Println("  <path>                 Evaluate path (e.g. /.env or /api/v1/health?token=abc)")
	fmt.Println("  :method <METHOD>       Switch active HTTP method (GET, POST, PUT, DELETE, etc.)")
	fmt.Println("  :ip <address>          Set client IP for allowlist / trusted proxy checks")
	fmt.Println("  :query <querystring>   Set default query string")
	fmt.Println("  :body <payload>        Set request body for body inspection tests")
	fmt.Println("  :header Key: Value     Set or add custom request header")
	fmt.Println("  :clear-headers         Clear all custom headers")
	fmt.Println("  :load <file.json>      Load a custom routewarden.json policy")
	fmt.Println("  :status                Display current test environment state")
	fmt.Println("  :clear                 Clear screen")
	fmt.Println("  :exit / quit           Exit interactive mode")
	fmt.Println()
}

func printTUIStatus(configName, method, ip, query, body string, headers map[string]string, cfg *engine.Config) {
	fmt.Println("📋 Current Interactive Environment:")
	fmt.Printf("  • Config File:        %s\n", configName)
	fmt.Printf("  • Default Patterns:   %t\n", cfg.EnableDefaultPatterns)
	fmt.Printf("  • Custom Patterns:    %d block, %d allow\n", len(cfg.BlockPatterns), len(cfg.AllowPatterns))
	fmt.Printf("  • Active Method:      %s\n", method)
	fmt.Printf("  • Active Client IP:   %s\n", ip)
	fmt.Printf("  • Active Query:       %q\n", query)
	fmt.Printf("  • Active Body:        %q\n", body)
	fmt.Printf("  • Active Headers:     %d headers configured\n", len(headers))
	for k, v := range headers {
		fmt.Printf("      - %s: %s\n", k, v)
	}
	fmt.Println()
}

func renderEvaluationResult(path, method, ip, query, body string, statusCode int, res *engine.EvaluationResult) {
	fmt.Println()
	if res.Blocked {
		fmt.Printf("  Result: 🛑 BLOCKED (HTTP Status %d)\n", statusCode)
		fmt.Printf("  Reason:  %s\n", res.Reason)
		if res.MatchedPattern != "" {
			fmt.Printf("  Pattern: %s\n", res.MatchedPattern)
		}
		if res.MatchedTarget != "" {
			fmt.Printf("  Target:  %s\n", res.MatchedTarget)
		}
	} else {
		fmt.Println("  Result: ✅ ALLOWED (Request permitted to backend)")
		fmt.Printf("  Reason:  %s\n", res.Reason)
	}

	if len(res.CandidatePaths) > 0 {
		fmt.Printf("  Candidate Paths Extracted (%d):\n", len(res.CandidatePaths))
		for _, cp := range res.CandidatePaths {
			fmt.Printf("    • %s\n", cp)
		}
	}
	fmt.Println()
}
