package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/routewarden/cli/daemon"
	"github.com/routewarden/cli/shipper"
)

var version = "5.2.2"

func printUsage() {
	fmt.Println(`RouteWarden Shipper (` + version + `) — Lightweight Remote Security Log Shipper

Usage:
  rwarden [command] [options]

Commands:
  push        Stream encrypted logs to the central dashboard (default command)
                e.g. rwarden push
                e.g. rwarden -d
                e.g. rwarden --docker
                e.g. rwarden -c edge-proxy -d
                e.g. rwarden -f /var/log/nginx/access.log
                e.g. rwarden push -e '{"client_ip":"198.51.100.1","path":"/.env","verdict":"BLOCK"}'
                e.g. cat events.log | rwarden push --stdin
  register    Enroll this node with a central RouteWarden dashboard
                e.g. rwarden register --url http://198.51.100.10:7890 --key <token>
  status      Check running status of background shipper
                e.g. rwarden status
  stop        Stop running background shipper daemon
                e.g. rwarden stop
  version     Show shipper version

Flags for push:
  -docker              Auto-discover Docker containers with 'routewarden=true'
  -c, --container      Tail specific Docker container(s)
  -f, --file           Log file(s) to monitor and push (use '-' for STDIN)
  -e, --event          Push one or more specific event strings directly (repeatable)
  --stdin              Read and push events line-by-line from STDIN
  -d, --detach         Run in detached background mode
  -u, --url            RouteWarden dashboard URL
  -k, --key            Remote agent authentication key
  -batch-size          Max events to buffer (default 50)
  -flush-interval      Max duration before flush (default 1s)
`)
}

func main() {
	if len(os.Args) < 2 {
		// Default to auto-discovery push if no arguments given
		shipper.HandlePush([]string{"--docker"}, version)
		return
	}

	command := os.Args[1]
	switch strings.ToLower(command) {
	case "push":
		shipper.HandlePush(os.Args[2:], version)
	case "register":
		shipper.HandleRegister(os.Args[2:])
	case "status", "ps":
		daemon.Status("push", "RouteWarden Remote Shipper")
	case "stop", "down":
		_, _ = daemon.Stop("push", "RouteWarden Remote Shipper")
	case "version", "--version", "-v":
		fmt.Printf("rwarden-shipper version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		// If command starts with "-", pass all arguments directly to push
		if strings.HasPrefix(command, "-") {
			shipper.HandlePush(os.Args[1:], version)
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}
