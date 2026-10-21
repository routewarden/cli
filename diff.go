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

func handleDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	format := fs.String("format", "text", "Output format: text, json")
	fs.StringVar(format, "f", "text", "Alias for --format")
	exitCode := fs.Bool("exit-code", false, "Exit with status 1 if diff exists, 2 if security posture is relaxed")
	_ = parseFlagsLenient(fs, args)

	var files []string
	for _, arg := range fs.Args() {
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			files = append(files, arg)
		}
	}

	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: 'rwarden diff' requires two configuration files to compare.")
		fmt.Fprintln(os.Stderr, "\nUsage:")
		fmt.Fprintln(os.Stderr, "  rwarden diff <base.json> <candidate.json> [flags]")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		fmt.Fprintln(os.Stderr, "  -f, --format     Output format: text (default) or json")
		fmt.Fprintln(os.Stderr, "      --exit-code  Exit with code 1 if differences exist, 2 if posture is relaxed")
		os.Exit(1)
	}

	baseFile := files[0]
	candidateFile := files[1]

	if baseFile == "-" && candidateFile == "-" {
		fmt.Fprintln(os.Stderr, "Error: only one file can be read from stdin (-)")
		os.Exit(1)
	}

	readFile := func(path string) ([]byte, error) {
		if path == "-" {
			return io.ReadAll(os.Stdin)
		}
		return os.ReadFile(path)
	}

	baseData, err := readFile(baseFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading base file %s: %v\n", baseFile, err)
		os.Exit(1)
	}

	candidateData, err := readFile(candidateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading candidate file %s: %v\n", candidateFile, err)
		os.Exit(1)
	}

	baseCfg := engine.CreateConfig()
	candidateCfg := engine.CreateConfig()
	if err := json.Unmarshal(baseData, baseCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing base JSON %s: %v\n", baseFile, err)
		os.Exit(1)
	}
	if err := json.Unmarshal(candidateData, candidateCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing candidate JSON %s: %v\n", candidateFile, err)
		os.Exit(1)
	}

	diff := engine.DiffConfigs(baseCfg, candidateCfg, baseFile, candidateFile)

	if strings.ToLower(*format) == "json" {
		out, err := json.MarshalIndent(diff, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON diff: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
	} else {
		printDiffTextReport(diff)
	}

	if *exitCode && diff.HasDifferences {
		if diff.Impact == engine.DiffImpactRelaxed {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func printDiffTextReport(diff *engine.PolicyDiff) {
	fmt.Printf("⚖️  RouteWarden Policy Diff: %s ➔ %s\n", diff.BaseFile, diff.CandidateFile)
	fmt.Println(strings.Repeat("─", 65))

	if !diff.HasDifferences {
		fmt.Println("✅ No differences found. Both configurations are identical in security policy.")
		fmt.Println(strings.Repeat("─", 65))
		return
	}

	// Security Impact Banner
	switch diff.Impact {
	case engine.DiffImpactRelaxed:
		fmt.Println("⚠️  SECURITY POSTURE IMPACT: RELAXED (Protections were removed or weakened!)")
	case engine.DiffImpactHardened:
		fmt.Println("🛡️  SECURITY POSTURE IMPACT: HARDENED (Protections were strengthened)")
	default:
		fmt.Println("ℹ️  SECURITY POSTURE IMPACT: NEUTRAL")
	}

	if len(diff.ImpactReasons) > 0 {
		fmt.Println("\nImpact Highlights:")
		for _, reason := range diff.ImpactReasons {
			fmt.Printf("  • %s\n", reason)
		}
	}

	// Block Patterns
	if len(diff.BlockPatterns.Added) > 0 || len(diff.BlockPatterns.Removed) > 0 {
		fmt.Println("\nBlock Patterns:")
		for _, p := range diff.BlockPatterns.Removed {
			fmt.Printf("  - %s (removed)\n", p)
		}
		for _, p := range diff.BlockPatterns.Added {
			fmt.Printf("  + %s (added)\n", p)
		}
	}

	// Allow Patterns
	if len(diff.AllowPatterns.Added) > 0 || len(diff.AllowPatterns.Removed) > 0 {
		fmt.Println("\nAllow Patterns:")
		for _, p := range diff.AllowPatterns.Removed {
			fmt.Printf("  - %s (removed)\n", p)
		}
		for _, p := range diff.AllowPatterns.Added {
			fmt.Printf("  + %s (added)\n", p)
		}
	}

	// Allowed IPs
	if len(diff.AllowedIPs.Added) > 0 || len(diff.AllowedIPs.Removed) > 0 {
		fmt.Println("\nAllowed IPs / CIDRs:")
		for _, ip := range diff.AllowedIPs.Removed {
			fmt.Printf("  - %s (removed)\n", ip)
		}
		for _, ip := range diff.AllowedIPs.Added {
			fmt.Printf("  + %s (added)\n", ip)
		}
	}

	// Trusted Proxies
	if len(diff.TrustedProxies.Added) > 0 || len(diff.TrustedProxies.Removed) > 0 {
		fmt.Println("\nTrusted Proxies:")
		for _, ip := range diff.TrustedProxies.Removed {
			fmt.Printf("  - %s (removed)\n", ip)
		}
		for _, ip := range diff.TrustedProxies.Added {
			fmt.Printf("  + %s (added)\n", ip)
		}
	}

	// Properties
	if len(diff.Properties) > 0 {
		fmt.Println("\nConfiguration Properties:")
		for k, v := range diff.Properties {
			fmt.Printf("  ~ %s: %v ➔ %v\n", k, v.Old, v.New)
		}
	}

	fmt.Println(strings.Repeat("─", 65))
}
