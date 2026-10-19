package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/routewarden/cli/engine"
)

func handleAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	format := fs.String("format", "text", "Output format: text, json, sarif")
	fs.StringVar(format, "f", "text", "Alias for --format")
	strict := fs.Bool("strict", false, "Strict mode: fail on warnings as well as critical issues")
	fs.BoolVar(strict, "s", false, "Alias for --strict")
	_ = parseFlagsLenient(fs, args)

	filename := "routewarden.json"
	for _, arg := range fs.Args() {
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			filename = arg
			break
		}
	}

	var data []byte
	var err error
	if filename == "-" {
		data, err = io.ReadAll(os.Stdin)
		filename = "stdin"
	} else {
		data, err = os.ReadFile(filename)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading configuration from %s: %v\n", filename, err)
		os.Exit(1)
	}

	cfg := engine.CreateConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON configuration %s: %v\n", filename, err)
		os.Exit(1)
	}

	report := engine.AuditConfig(cfg, filename)

	switch strings.ToLower(*format) {
	case "json":
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error serializing JSON report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))

	case "sarif":
		sarifBytes, err := report.ToSARIF()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating SARIF output: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(sarifBytes))

	default: // text
		printAuditTextReport(report, *strict)
	}

	if report.CriticalCount > 0 || (*strict && report.WarningCount > 0) {
		os.Exit(1)
	}
}

func printAuditTextReport(report *engine.AuditReport, strict bool) {
	fmt.Printf("🔍 RouteWarden Security Policy Linter (%s)\n", report.ConfigFile)
	fmt.Println(strings.Repeat("─", 65))

	if len(report.Issues) == 0 {
		fmt.Println("✅ No issues found. Configuration is hardened and follows best practices.")
		fmt.Println("   Security Score: 100/100 (EXCELLENT)")
		fmt.Println(strings.Repeat("─", 65))
		return
	}

	for i, issue := range report.Issues {
		badge := "ℹ️  INFO"
		switch issue.Severity {
		case engine.SeverityCritical:
			badge = "🛑 CRITICAL"
		case engine.SeverityWarning:
			badge = "⚠️  WARNING "
		}

		fmt.Printf("[%d] %s: %s (%s)\n", i+1, badge, issue.Title, issue.Code)
		fmt.Printf("    Message:     %s\n", issue.Message)
		if issue.Pattern != "" {
			fmt.Printf("    Pattern:     %s\n", issue.Pattern)
		}
		if issue.Field != "" {
			fmt.Printf("    Field:       %s\n", issue.Field)
		}
		fmt.Printf("    Remediation: %s\n\n", issue.Remediation)
	}

	fmt.Println(strings.Repeat("─", 65))
	fmt.Printf("Summary: %d Total Issues | %d Critical | %d Warnings | %d Info\n",
		report.TotalIssues, report.CriticalCount, report.WarningCount, report.InfoCount)

	grade := "POOR"
	if report.SecurityScore >= 90 {
		grade = "EXCELLENT"
	} else if report.SecurityScore >= 75 {
		grade = "GOOD"
	} else if report.SecurityScore >= 50 {
		grade = "MODERATE"
	}
	fmt.Printf("Security Score: %d/100 (%s)\n", report.SecurityScore, grade)

	if report.CriticalCount > 0 {
		fmt.Println("Result: ❌ FAILED (Critical security vulnerabilities or invalid rules detected)")
	} else if strict && report.WarningCount > 0 {
		fmt.Println("Result: ❌ FAILED (Strict mode enabled: warnings present)")
	} else {
		fmt.Println("Result: ✅ PASSED (No critical vulnerabilities detected)")
	}
	fmt.Println(strings.Repeat("─", 65))
}
