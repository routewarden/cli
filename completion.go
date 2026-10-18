package main

import (
	"fmt"
	"os"
	"strings"
)

func handleCompletion(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rwarden completion <bash|zsh|fish|powershell>")
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  source <(rwarden completion bash)")
		fmt.Fprintln(os.Stderr, "  rwarden completion zsh > ~/.zsh/completion/_rwarden")
		fmt.Fprintln(os.Stderr, "  rwarden completion fish | source")
		fmt.Fprintln(os.Stderr, "  rwarden completion powershell | Out-String | Invoke-Expression")
		os.Exit(1)
	}

	shell := strings.ToLower(strings.TrimSpace(args[0]))
	switch shell {
	case "bash":
		fmt.Print(generateBashCompletion())
	case "zsh":
		fmt.Print(generateZshCompletion())
	case "fish":
		fmt.Print(generateFishCompletion())
	case "powershell", "ps", "pwsh":
		fmt.Print(generatePowerShellCompletion())
	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell %q. Supported shells: bash, zsh, fish, powershell\n", shell)
		os.Exit(1)
	}
}

func generateBashCompletion() string {
	return `#!/usr/bin/env bash
# Bash autocompletion for RouteWarden CLI (rwarden)
# Load by running: source <(rwarden completion bash)

_rwarden_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="test validate generate audit diff sandbox dashboard keys register push monitor tui status stop completion man cleanup schema version help"
    local generate_targets="traefik-yaml traefik-toml traefik-labels caddy nginx tcp-warden"
    local dashboard_cmds="up down status stop export"
    local push_cmds="status stop"
    local formats="text json sarif"
    local methods="GET POST PUT DELETE PATCH HEAD OPTIONS"

    if [ "$cword" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    local command="${words[1]}"
    case "$command" in
        generate)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$generate_targets" -- "$cur") )
                return 0
            else
                _filedir
                return 0
            fi
            ;;
        sandbox)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "traefik caddy nginx" -- "$cur") )
                return 0
            else
                _filedir
                return 0
            fi
            ;;
        dashboard)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$dashboard_cmds" -- "$cur") )
                return 0
            fi
            case "$prev" in
                --port)
                    return 0
                    ;;
                -f|--file)
                    _filedir
                    return 0
                    ;;
                export)
                    _filedir -d
                    return 0
                    ;;
            esac
            COMPREPLY=( $(compgen -W "--port --file -f --container -c --label -l --no-open --detach -d" -- "$cur") )
            return 0
            ;;
        push)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$push_cmds" -- "$cur") )
                return 0
            fi
            COMPREPLY=( $(compgen -W "--url -u --key -k --config --docker --container -c --file -f --label -l --tail --batch-size --flush-interval --detach -d" -- "$cur") )
            return 0
            ;;
        audit)
            case "$prev" in
                -f|--format)
                    COMPREPLY=( $(compgen -W "$formats" -- "$cur") )
                    return 0
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--format -f --strict -s --help -h" -- "$cur") )
                return 0
            fi
            _filedir json
            return 0
            ;;
        diff)
            _filedir json
            return 0
            ;;
        test)
            case "$prev" in
                -X|-m|--method)
                    COMPREPLY=( $(compgen -W "$methods" -- "$cur") )
                    return 0
                    ;;
                -c|--config)
                    _filedir json
                    return 0
                    ;;
                -H|--header|-q|--query|-b|--body|--ip)
                    return 0
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--config -c --method -X -m --query -q --body -b --header -H --ip --check-query --check-body --help -h" -- "$cur") )
                return 0
            fi
            ;;
        completion)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "$cur") )
                return 0
            fi
            ;;
        validate)
            _filedir
            return 0
            ;;
        monitor)
            case "$prev" in
                -f|--file|-o|--out)
                    _filedir
                    return 0
                    ;;
                --verdict)
                    COMPREPLY=( $(compgen -W "BLOCK ALLOW TARPIT" -- "$cur") )
                    return 0
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--file -f --out -o --wait -w --raw --docker --container -c --label -l --verdict --ip --path --help -h" -- "$cur") )
                return 0
            fi
            ;;
    esac
}

complete -F _rwarden_completions rwarden
`
}

func generateZshCompletion() string {
	return `#compdef rwarden
# Zsh autocompletion for RouteWarden CLI (rwarden)
# Install by saving to a directory in $fpath (e.g. ~/.zsh/completion/_rwarden)

_rwarden() {
    local -a commands
    commands=(
        'test:Simulate request path and anti-evasion inspection'
        'validate:Validate a RouteWarden configuration file against JSON schema'
        'generate:Generate gateway configuration snippet'
        'audit:Perform static analysis and linting on policy file'
        'diff:Compare two policies and evaluate security posture impact'
        'sandbox:Spin up ephemeral Traefik, Caddy, or NGINX container'
        'dashboard:Launch or manage the real-time SOC security dashboard'
        'keys:Manage API authentication keys for remote log streaming'
        'register:Enroll remote server with a central RouteWarden dashboard'
        'push:Stream encrypted logs from a remote node to central dashboard'
        'monitor:Tail and colorize live reverse proxy security events'
        'tui:Launch interactive terminal simulator'
        'status:Show running status of background dashboard and shipper daemons'
        'stop:Stop running background dashboard and/or shipper daemons'
        'completion:Output shell autocompletion code'
        'man:Generate roff manual page'
        'cleanup:Stop and remove sandbox containers'
        'schema:Output official RouteWarden JSON Schema'
        'version:Show CLI version'
    )

    _arguments -C \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'rwarden commands' commands
            ;;
        args)
            case $words[1] in
                generate)
                    _arguments \
                        '1:target:(traefik-yaml traefik-toml traefik-labels caddy nginx tcp-warden)' \
                        '2:config file:_files -g "*.json"'
                    ;;
                sandbox)
                    _arguments \
                        '1:target:(traefik caddy nginx)' \
                        '2:config file:_files'
                    ;;
                audit)
                    _arguments \
                        '(-f --format)'{-f,--format}'[Output format]:format:(text json sarif)' \
                        '(-s --strict)'{-s,--strict}'[Fail on warnings as well as critical errors]' \
                        '1:config file:_files -g "*.json"'
                    ;;
                diff)
                    _arguments \
                        '1:base config:_files -g "*.json"' \
                        '2:candidate config:_files -g "*.json"'
                    ;;
                dashboard)
                    _arguments \
                        '1:subcommand:(up down status stop export)' \
                        '--port[SOC dashboard HTTP port]:port:' \
                        '(-f --file)'{-f,--file}'[Log file to monitor]:file:_files' \
                        '(-c --container)'{-c,--container}'[Target container name]:container:' \
                        '(-l --label)'{-l,--label}'[Docker label filter]:label:' \
                        '--no-open[Do not auto-open browser]' \
                        '(-d --detach)'{-d,--detach}'[Run in background detached mode]'
                    ;;
                push)
                    _arguments \
                        '1:subcommand:(status stop)' \
                        '(-u --url)'{-u,--url}'[Dashboard URL]:url:' \
                        '(-k --key)'{-k,--key}'[Agent key]:key:' \
                        '--config[Config file path]:file:_files -g "*.json"' \
                        '--docker[Auto-discover Docker containers]' \
                        '(-c --container)'{-c,--container}'[Target container name]:container:' \
                        '(-f --file)'{-f,--file}'[Log file to tail]:file:_files' \
                        '(-l --label)'{-l,--label}'[Docker label filter]:label:' \
                        '(-d --detach)'{-d,--detach}'[Run in background detached mode]'
                    ;;
                completion)
                    _arguments '1:shell:(bash zsh fish powershell)'
                    ;;
                test)
                    _arguments \
                        '(-c --config)'{-c,--config}'[Config file path]:file:_files -g "*.json"' \
                        '(-X -m --method)'{-X,-m,--method}'[HTTP method]:method:(GET POST PUT DELETE PATCH HEAD OPTIONS)' \
                        '(-q --query)'{-q,--query}'[Query string]:query:' \
                        '(-b --body)'{-b,--body}'[Request body payload]:body:' \
                        '--ip[Client IP address]:ip:' \
                        '1:path to test:'
                    ;;
                monitor)
                    _arguments \
                        '(-f --file)'{-f,--file}'[Log file to tail]:file:_files' \
                        '(-o --out)'{-o,--out}'[Output file to append logs to]:file:_files' \
                        '(-w --wait)'{-w,--wait}'[Wait and retry for running containers]' \
                        '--raw[Output raw/Combined log lines]' \
                        '(-c --container)'{-c,--container}'[Target container name]:container:' \
                        '(-l --label)'{-l,--label}'[Docker label filter]:label:' \
                        '--verdict[Filter by verdict]:verdict:(BLOCK ALLOW TARPIT)' \
                        '--ip[Filter by IP]:ip:' \
                        '--path[Filter by path]:path:'
                    ;;
                validate)
                    _arguments '1:config file:_files'
                    ;;
            esac
            ;;
    esac
}

_rwarden "$@"
`
}

func generateFishCompletion() string {
	return `# Fish autocompletion for RouteWarden CLI (rwarden)
# Install by placing in ~/.config/fish/completions/rwarden.fish

# Disable file completion by default
complete -c rwarden -f

# Main commands
complete -c rwarden -n "__fish_use_subcommand" -a test -d "Simulate path and query anti-evasion evaluation"
complete -c rwarden -n "__fish_use_subcommand" -a validate -d "Validate configuration against JSON schema"
complete -c rwarden -n "__fish_use_subcommand" -a generate -d "Compile policy into gateway config"
complete -c rwarden -n "__fish_use_subcommand" -a audit -d "Lint configuration and check ReDoS vulnerabilities"
complete -c rwarden -n "__fish_use_subcommand" -a diff -d "Compare two policies and evaluate security impact"
complete -c rwarden -n "__fish_use_subcommand" -a sandbox -d "Launch ephemeral gateway Docker container"
complete -c rwarden -n "__fish_use_subcommand" -a dashboard -d "Launch real-time SOC security dashboard"
complete -c rwarden -n "__fish_use_subcommand" -a keys -d "Manage API keys for remote log streaming"
complete -c rwarden -n "__fish_use_subcommand" -a register -d "Enroll remote server with central dashboard"
complete -c rwarden -n "__fish_use_subcommand" -a push -d "Stream encrypted logs to central dashboard"
complete -c rwarden -n "__fish_use_subcommand" -a monitor -d "Stream and colorize reverse proxy security events"
complete -c rwarden -n "__fish_use_subcommand" -a tui -d "Interactive terminal path testing REPL"
complete -c rwarden -n "__fish_use_subcommand" -a status -d "Show running status of background daemons"
complete -c rwarden -n "__fish_use_subcommand" -a stop -d "Stop running background daemons"
complete -c rwarden -n "__fish_use_subcommand" -a completion -d "Generate shell completion script"
complete -c rwarden -n "__fish_use_subcommand" -a man -d "Generate roff manual page"
complete -c rwarden -n "__fish_use_subcommand" -a cleanup -d "Remove running sandbox containers"
complete -c rwarden -n "__fish_use_subcommand" -a schema -d "Output official JSON Schema"
complete -c rwarden -n "__fish_use_subcommand" -a version -d "Show CLI version"

# Targets for generate
complete -c rwarden -n "__fish_seen_subcommand_from generate" -a "traefik-yaml traefik-toml traefik-labels caddy nginx tcp-warden"

# Formats for audit
complete -c rwarden -n "__fish_seen_subcommand_from audit" -s f -l format -a "text json sarif" -d "Output format"
complete -c rwarden -n "__fish_seen_subcommand_from audit" -s s -l strict -d "Fail on warnings"

# Subcommands for dashboard
complete -c rwarden -n "__fish_seen_subcommand_from dashboard" -a "up down status stop export"
complete -c rwarden -n "__fish_seen_subcommand_from push" -a "status stop"

# Completion shells
complete -c rwarden -n "__fish_seen_subcommand_from completion" -a "bash zsh fish powershell"
`
}

func generatePowerShellCompletion() string {
	return `# PowerShell completion for RouteWarden CLI (rwarden)
# Load by running: rwarden completion powershell | Out-String | Invoke-Expression

Register-ArgumentCompleter -Native -CommandName rwarden -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commands = @('test', 'validate', 'generate', 'audit', 'diff', 'sandbox', 'dashboard', 'keys', 'register', 'push', 'monitor', 'tui', 'status', 'stop', 'completion', 'man', 'cleanup', 'schema', 'version')
    $elements = $commandAst.Elements

    if ($elements.Count -eq 2) {
        $commands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        return
    }

    $subCommand = $elements[1].Value
    switch ($subCommand) {
        'generate' {
            @('traefik-yaml', 'traefik-toml', 'traefik-labels', 'caddy', 'nginx', 'tcp-warden') |
                Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
        }
        'dashboard' {
            @('up', 'down', 'status', 'stop', 'export') |
                Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
        }
        'push' {
            @('status', 'stop') |
                Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
        }
        'completion' {
            @('bash', 'zsh', 'fish', 'powershell') |
                Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
        }
        'audit' {
            if ($wordToComplete -like '-*') {
                @('--format', '-f', '--strict', '-s') |
                    Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
            }
        }
    }
}
`
}
