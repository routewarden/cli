package main

import (
	"flag"
	"fmt"
	"os"
)

// GenerateManPage generates a roff-formatted troff manual page for rwarden(1).
func GenerateManPage(ver string) string {
	return `.TH RWARDEN 1 "October 2026" "rwarden ` + ver + `" "RouteWarden Manual"
.SH NAME
rwarden \- unified edge & L4 protocol security suite CLI
.SH SYNOPSIS
\fBrwarden\fR [\fIcommand\fR] [\fIarguments\fR] [\fIoptions\fR]
.SH DESCRIPTION
\fBrwarden\fR is the official developer CLI, policy compiler, configuration validator, and real-time observability dashboard for the RouteWarden security suite.
It enables security and platform teams to evaluate path rules offline, validate configurations against official JSON schemas, compile universal policies for Traefik, Caddy, NGINX, and TCP Warden, audit policy configurations for ReDoS vulnerabilities, and monitor live threat telemetry.
.SH COMMANDS
.TP
\fBtest\fR [\fIpath\fR] [\fIoptions\fR]
Simulate multi-layer URL decoding, query parameter inspection, backslash normalization, semicolon parameter stripping, body payload evaluation, and IP allowlist evaluation without running any reverse proxy.
.TP
\fBvalidate\fR [\fIfile\fR]
Validate \fIroutewarden.json\fR (HTTP gateways) or \fItcp-warden.yaml\fR (L4 daemon) against their formal JSON schemas with clear diagnostics for syntax errors, regex mistakes, and invalid CIDR notations.
.TP
\fBgenerate\fR \fItarget\fR [\fIconfig\fR]
Compile a universal \fIroutewarden.json\fR security policy into target-specific configurations. Supported targets: \fBtraefik-yaml\fR, \fBtraefik-toml\fR, \fBtraefik-labels\fR, \fBcaddy\fR, \fBnginx\fR, \fBtcp-warden\fR.
.TP
\fBaudit\fR [\fIconfig\fR] [\fIoptions\fR]
Perform deep static analysis and security linting on a policy file. Detects universal wildcard traps, unescaped dots, ReDoS catastrophic backtracking vulnerabilities, duplicate rules, and header spoofing risks. Supports \fB--format sarif\fR for GitHub Code Scanning.
.TP
\fBdiff\fR \fIbase.json\fR \fIcandidate.json\fR
Compare two RouteWarden policy files and evaluate the security posture delta (e.g. relaxed, hardened, or neutral).
.TP
\fBmonitor\fR [\fIoptions\fR]
Tail and colorize live security events and blocked requests from reverse proxy logs or standard input.
.TP
\fBtui\fR
Launch an interactive terminal UI REPL for real-time path testing and rule simulation.
.TP
\fBcompletion\fR \fIshell\fR
Generate shell autocompletion script for \fBbash\fR, \fBzsh\fR, \fBfish\fR, or \fBpowershell\fR.
.TP
\fBman\fR [\fIoptions\fR]
Emit system roff/troff manual page.
.TP
\fBsandbox\fR \fItarget\fR [\fIconfig\fR]
Spin up an ephemeral, isolated Traefik, Caddy, or NGINX container in Docker to test live request traffic against policies.
.TP
\fBdashboard\fR [\fIup\fR|\fIdown\fR|\fIstatus\fR|\fIstop\fR|\fIexport\fR]
Launch and manage the real-time SOC security dashboard (supports \fB--detach\fR / \fB-d\fR).
.TP
\fBkeys\fR [\fIcreate\fR|\fIlist\fR|\fIrevoke\fR]
Manage agent authentication keys and tokens for distributed remote log streaming.
.TP
\fBregister\fR [\fI--url\fR] [\fI--key\fR]
Enroll a remote edge server with a central RouteWarden dashboard.
.TP
\fBpush\fR [\fIoptions\fR]
Stream encrypted reverse proxy logs to the central dashboard (supports \fB--docker\fR, \fB--detach\fR / \fB-d\fR, \fBstatus\fR, \fBstop\fR).
.TP
\fBstatus\fR [\fIdashboard\fR|\fIpush\fR]
Display running status, PID, and log path of background dashboard and shipper daemons.
.TP
\fBstop\fR [\fIdashboard\fR|\fIpush\fR|\fIall\fR]
Stop running background dashboard and/or shipper daemons.
.TP
\fBcleanup\fR
Stop and remove all running RouteWarden ephemeral sandbox containers.
.TP
\fBschema\fR [\fI--tcp\fR]
Output the official embedded JSON Schema for IDE autocomplete and CI linting.
.TP
\fBversion\fR
Display the CLI version, commit, and build runtime.
.SH OPTIONS
.TP
\fB-c\fR, \fB--config\fR \fIpath\fR
Path to RouteWarden JSON configuration file (or '-' for standard input).
.TP
\fB-f\fR, \fB--format\fR \fIformat\fR
Output format (\fBtext\fR, \fBjson\fR, \fBsarif\fR).
.TP
\fB-h\fR, \fB--help\fR
Display help and command syntax.
.SH EXAMPLES
.PP
Simulate inspection on double-encoded path traversal:
.RS
.nf
rwarden test "/static/%252e%252e/.env"
.fi
.RE
.PP
Audit a configuration file for ReDoS and linting issues:
.RS
.nf
rwarden audit routewarden.json --format sarif > results.sarif
.fi
.RE
.PP
Compare two configurations before deployment:
.RS
.nf
rwarden diff prod.json candidate.json
.fi
.RE
.PP
Launch interactive terminal simulator:
.RS
.nf
rwarden tui
.fi
.RE
.PP
Stream and monitor live Docker proxy logs:
.RS
.nf
docker logs -f traefik | rwarden monitor
.fi
.RE
.SH FILES
.TP
\fIroutewarden.json\fR
Primary HTTP reverse proxy security policy definition.
.TP
\fItcp-warden.yaml\fR
Layer 4 TCP Warden security daemon configuration.
.SH EXIT STATUS
.TP
\fB0\fR
Success / clean audit / allowed test path.
.TP
\fB1\fR
Evaluation error / blocked request / critical audit flaw / diff change.
.SH SEE ALSO
Documentation: \fBhttps://routewarden.github.io\fR
.br
Source Code: \fBhttps://github.com/routewarden/cli\fR
.SH AUTHORS
RouteWarden Contributors.
`
}

func handleMan(args []string) {
	fs := flag.NewFlagSet("man", flag.ExitOnError)
	outFile := fs.String("output", "", "Optional file path to write manual page (default: stdout)")
	fs.StringVar(outFile, "o", "", "Alias for --output")
	_ = fs.Parse(args)

	manContent := GenerateManPage(version)

	if *outFile != "" {
		err := os.WriteFile(*outFile, []byte(manContent), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing manpage to %s: %v\n", *outFile, err)
			os.Exit(1)
		}
		fmt.Printf("✓ Manual page generated at %s\n", *outFile)
		fmt.Printf("Tip: Test with: man -l %s\n", *outFile)
		return
	}

	fmt.Print(manContent)
}
