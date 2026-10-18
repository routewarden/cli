package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/routewarden/cli/observability"
)

func handleKeys(args []string) {
	if len(args) == 0 {
		printKeysUsage()
		return
	}

	subcmd := args[0]
	switch subcmd {
	case "create", "new", "add":
		fs := flag.NewFlagSet("keys create", flag.ExitOnError)
		dir := fs.String("dir", "", "Dashboard storage directory (default: ~/.routewarden/dashboard)")
		_ = parseFlagsLenient(fs, args[1:])

		remaining := fs.Args()
		if len(remaining) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: rwarden keys create <agent-name>")
			os.Exit(1)
		}
		name := remaining[0]

		// Ensure server keypair exists
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
		_ = parseFlagsLenient(fs, args[1:])

		keys, err := observability.ListAgentKeys(*dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error listing keys: %v\n", err)
			os.Exit(1)
		}

		if len(keys) == 0 {
			fmt.Println("ℹ️  No remote agent keys created yet.")
			fmt.Println("   Run 'rwarden keys create <name>' to create an agent key.")
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
		_ = parseFlagsLenient(fs, args[1:])

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
		fmt.Printf("✅ Agent key %q has been revoked.\n", target)

	default:
		printKeysUsage()
	}
}

func printKeysUsage() {
	fmt.Print(`Usage: rwarden keys <subcommand> [options]

Manage API authentication keys for remote server log shipping.

Subcommands:
  create <name>   Generate a new remote agent authentication key
  list            List all registered agent keys and their status
  revoke <id>     Revoke access for a specific agent key

Options:
  --dir           Dashboard storage directory (default: ~/.routewarden/dashboard)
`)
}
