package main

import (
	"reflect"
	"testing"
	"time"
)

func TestPushOptions_AllFlagsAndAliases(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		opts, err := parsePushOptions([]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.TailLines != "50" {
			t.Errorf("expected default TailLines=50, got %s", opts.TailLines)
		}
		if opts.BatchSize != 50 {
			t.Errorf("expected default BatchSize=50, got %d", opts.BatchSize)
		}
		if opts.FlushInterval != 1*time.Second {
			t.Errorf("expected default FlushInterval=1s, got %v", opts.FlushInterval)
		}
		if opts.MaxQueueSize != 10000 {
			t.Errorf("expected default MaxQueueSize=10000, got %d", opts.MaxQueueSize)
		}
		if opts.DisconnectTimeout != 5*time.Minute {
			t.Errorf("expected default DisconnectTimeout=5m, got %v", opts.DisconnectTimeout)
		}
		if opts.PingInterval != 10*time.Second {
			t.Errorf("expected default PingInterval=10s, got %v", opts.PingInterval)
		}
		if opts.DockerMode || opts.DetachMode || opts.StdinMode || opts.AllTraffic || opts.AllLogs || opts.Verbose || opts.IncludeFailed {
			t.Errorf("expected all boolean flags to default to false: %+v", opts)
		}
	})

	t.Run("url and key flags and aliases", func(t *testing.T) {
		opts1, err := parsePushOptions([]string{"--url", "http://soc.internal:7890", "--key", "rw_sec_long_key"})
		if err != nil || opts1.URL != "http://soc.internal:7890" || opts1.Key != "rw_sec_long_key" {
			t.Errorf("failed long flags: url=%s, key=%s, err=%v", opts1.URL, opts1.Key, err)
		}

		opts2, err := parsePushOptions([]string{"-u", "http://soc.short:7890", "-k", "rw_sec_short_key"})
		if err != nil || opts2.URL != "http://soc.short:7890" || opts2.Key != "rw_sec_short_key" {
			t.Errorf("failed short aliases: url=%s, key=%s, err=%v", opts2.URL, opts2.Key, err)
		}
	})

	t.Run("config flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--config", "/etc/routewarden/custom.json"})
		if err != nil || opts.ConfigPath != "/etc/routewarden/custom.json" {
			t.Errorf("failed config flag: %s, err=%v", opts.ConfigPath, err)
		}
	})

	t.Run("docker flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--docker"})
		if err != nil || !opts.DockerMode {
			t.Errorf("failed docker flag: %v, err=%v", opts.DockerMode, err)
		}
	})

	t.Run("detach flag and alias", func(t *testing.T) {
		opts1, err := parsePushOptions([]string{"--detach"})
		if err != nil || !opts1.DetachMode {
			t.Errorf("failed --detach: %v", opts1.DetachMode)
		}
		opts2, err := parsePushOptions([]string{"-d"})
		if err != nil || !opts2.DetachMode {
			t.Errorf("failed -d: %v", opts2.DetachMode)
		}
	})

	t.Run("container flag, alias, repeatable and comma-separated", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"-c", "traefik", "--container", "caddy,nginx", "-c", "envoy"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []string{"traefik", "caddy,nginx", "envoy"}
		if !reflect.DeepEqual(opts.ContainerFlags, expected) {
			t.Errorf("expected container flags %v, got %v", expected, opts.ContainerFlags)
		}
	})

	t.Run("file flag, alias, repeatable and comma-separated", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"-f", "/var/log/caddy.log", "--file", "/var/log/nginx.log,/var/log/traefik.log"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []string{"/var/log/caddy.log", "/var/log/nginx.log,/var/log/traefik.log"}
		if !reflect.DeepEqual(opts.FileFlags, expected) {
			t.Errorf("expected file flags %v, got %v", expected, opts.FileFlags)
		}
	})

	t.Run("event flag, alias, repeatable", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"-e", `{"event":"1"}`, "--event", `{"event":"2"}`})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []string{`{"event":"1"}`, `{"event":"2"}`}
		if !reflect.DeepEqual(opts.EventFlags, expected) {
			t.Errorf("expected event flags %v, got %v", expected, opts.EventFlags)
		}
	})

	t.Run("stdin flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--stdin"})
		if err != nil || !opts.StdinMode {
			t.Errorf("failed stdin flag: %v", opts.StdinMode)
		}
	})

	t.Run("status code flags and aliases", func(t *testing.T) {
		cases := []struct {
			flag  string
			val   string
			alias string
		}{
			{"--status", "400-599, 301", "status"},
			{"-s", "4xx, 5xx", "s"},
			{"--status-codes", "500-504", "status-codes"},
			{"--include-status", "301, 302", "include-status"},
		}
		for _, tc := range cases {
			opts, err := parsePushOptions([]string{tc.flag, tc.val})
			if err != nil || opts.StatusCodesFlag != tc.val {
				t.Errorf("alias %s failed: got %q, expected %q, err=%v", tc.alias, opts.StatusCodesFlag, tc.val, err)
			}
		}
	})

	t.Run("include-failed flag and alias", func(t *testing.T) {
		opts1, err := parsePushOptions([]string{"--include-failed"})
		if err != nil || !opts1.IncludeFailed || opts1.StatusCodesFlag != "400-599" {
			t.Errorf("failed --include-failed: failed=%v, status=%s", opts1.IncludeFailed, opts1.StatusCodesFlag)
		}
		opts2, err := parsePushOptions([]string{"-F"})
		if err != nil || !opts2.IncludeFailed || opts2.StatusCodesFlag != "400-599" {
			t.Errorf("failed -F alias: failed=%v, status=%s", opts2.IncludeFailed, opts2.StatusCodesFlag)
		}
	})

	t.Run("all-traffic flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--all-traffic"})
		if err != nil || !opts.AllTraffic {
			t.Errorf("failed all-traffic flag: %v", opts.AllTraffic)
		}
	})

	t.Run("all-logs flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--all-logs"})
		if err != nil || !opts.AllLogs {
			t.Errorf("failed all-logs flag: %v", opts.AllLogs)
		}
	})

	t.Run("label flag and alias", func(t *testing.T) {
		opts1, err := parsePushOptions([]string{"--label", "com.docker.stack=waf"})
		if err != nil || opts1.CustomLabel != "com.docker.stack=waf" {
			t.Errorf("failed --label: %s", opts1.CustomLabel)
		}
		opts2, err := parsePushOptions([]string{"-l", "env=prod"})
		if err != nil || opts2.CustomLabel != "env=prod" {
			t.Errorf("failed -l alias: %s", opts2.CustomLabel)
		}
	})

	t.Run("tail flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--tail", "500"})
		if err != nil || opts.TailLines != "500" {
			t.Errorf("failed tail flag: %s", opts.TailLines)
		}
	})

	t.Run("batch-size flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--batch-size", "100"})
		if err != nil || opts.BatchSize != 100 {
			t.Errorf("failed batch-size flag: %d", opts.BatchSize)
		}
	})

	t.Run("flush-interval flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--flush-interval", "2500ms"})
		if err != nil || opts.FlushInterval != 2500*time.Millisecond {
			t.Errorf("failed flush-interval flag: %v", opts.FlushInterval)
		}
	})

	t.Run("queue-size flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--queue-size", "25000"})
		if err != nil || opts.MaxQueueSize != 25000 {
			t.Errorf("failed queue-size flag: %d", opts.MaxQueueSize)
		}
	})

	t.Run("disconnect-timeout flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--disconnect-timeout", "15m"})
		if err != nil || opts.DisconnectTimeout != 15*time.Minute {
			t.Errorf("failed disconnect-timeout flag: %v", opts.DisconnectTimeout)
		}
	})

	t.Run("ping-interval flag", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--ping-interval", "45s"})
		if err != nil || opts.PingInterval != 45*time.Second {
			t.Errorf("failed ping-interval flag: %v", opts.PingInterval)
		}
	})

	t.Run("verbose flag and alias", func(t *testing.T) {
		opts1, err := parsePushOptions([]string{"--verbose"})
		if err != nil || !opts1.Verbose {
			t.Errorf("failed --verbose: %v", opts1.Verbose)
		}
		opts2, err := parsePushOptions([]string{"-v"})
		if err != nil || !opts2.Verbose {
			t.Errorf("failed -v alias: %v", opts2.Verbose)
		}
	})

	t.Run("subcommand prefixes up, start, run", func(t *testing.T) {
		for _, sub := range []string{"up", "start", "run"} {
			opts, err := parsePushOptions([]string{sub, "--docker", "-d"})
			if err != nil {
				t.Fatalf("subcommand %s error: %v", sub, err)
			}
			if !opts.DockerMode || !opts.DetachMode {
				t.Errorf("subcommand %s failed to parse flags: docker=%v, detach=%v", sub, opts.DockerMode, opts.DetachMode)
			}
		}
	})

	t.Run("combined space-separated flags in single argument string", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"-docker --all-traffic -d -v"})
		if err != nil {
			t.Fatalf("unexpected error parsing combined flags: %v", err)
		}
		if !opts.DockerMode || !opts.AllTraffic || !opts.DetachMode || !opts.Verbose {
			t.Errorf("combined flags not set properly: docker=%v, allTraffic=%v, detach=%v, verbose=%v",
				opts.DockerMode, opts.AllTraffic, opts.DetachMode, opts.Verbose)
		}
	})

	t.Run("positional arguments preserved after flags", func(t *testing.T) {
		opts, err := parsePushOptions([]string{"--docker", "/var/log/pos1.log", "/var/log/pos2.log"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(opts.PositionalArgs, []string{"/var/log/pos1.log", "/var/log/pos2.log"}) {
			t.Errorf("expected positional args [/var/log/pos1.log /var/log/pos2.log], got %v", opts.PositionalArgs)
		}
	})
}

func TestPushOptions_AllEnvironmentVariables(t *testing.T) {
	t.Run("RW_DASHBOARD_URL and fallback RW_URL", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "http://soc.primary:7890")
		t.Setenv("RW_URL", "http://soc.fallback:7890")
		opts, _ := parsePushOptions([]string{})
		if opts.URL != "http://soc.primary:7890" {
			t.Errorf("expected primary RW_DASHBOARD_URL, got %s", opts.URL)
		}

		t.Setenv("RW_DASHBOARD_URL", "")
		optsFallback, _ := parsePushOptions([]string{})
		if optsFallback.URL != "http://soc.fallback:7890" {
			t.Errorf("expected fallback RW_URL, got %s", optsFallback.URL)
		}
	})

	t.Run("RW_AGENT_KEY and fallback RW_KEY", func(t *testing.T) {
		t.Setenv("RW_AGENT_KEY", "rw_sec_primary")
		t.Setenv("RW_KEY", "rw_sec_fallback")
		opts, _ := parsePushOptions([]string{})
		if opts.Key != "rw_sec_primary" {
			t.Errorf("expected primary RW_AGENT_KEY, got %s", opts.Key)
		}

		t.Setenv("RW_AGENT_KEY", "")
		optsFallback, _ := parsePushOptions([]string{})
		if optsFallback.Key != "rw_sec_fallback" {
			t.Errorf("expected fallback RW_KEY, got %s", optsFallback.Key)
		}
	})

	t.Run("RW_CONFIG", func(t *testing.T) {
		t.Setenv("RW_CONFIG", "/custom/path/agent.json")
		opts, _ := parsePushOptions([]string{})
		if opts.ConfigPath != "/custom/path/agent.json" {
			t.Errorf("expected RW_CONFIG=/custom/path/agent.json, got %s", opts.ConfigPath)
		}
	})

	t.Run("RW_DOCKER", func(t *testing.T) {
		for _, val := range []string{"1", "true", "True", "TRUE"} {
			t.Setenv("RW_DOCKER", val)
			opts, _ := parsePushOptions([]string{})
			if !opts.DockerMode {
				t.Errorf("expected DockerMode=true for RW_DOCKER=%s", val)
			}
		}
	})

	t.Run("RW_LABEL", func(t *testing.T) {
		t.Setenv("RW_LABEL", "com.docker.stack=security")
		opts, _ := parsePushOptions([]string{})
		if opts.CustomLabel != "com.docker.stack=security" {
			t.Errorf("expected RW_LABEL=com.docker.stack=security, got %s", opts.CustomLabel)
		}
	})

	t.Run("RW_TAIL", func(t *testing.T) {
		t.Setenv("RW_TAIL", "250")
		opts, _ := parsePushOptions([]string{})
		if opts.TailLines != "250" {
			t.Errorf("expected RW_TAIL=250, got %s", opts.TailLines)
		}
	})

	t.Run("RW_BATCH_SIZE", func(t *testing.T) {
		t.Setenv("RW_BATCH_SIZE", "120")
		opts, _ := parsePushOptions([]string{})
		if opts.BatchSize != 120 {
			t.Errorf("expected RW_BATCH_SIZE=120, got %d", opts.BatchSize)
		}

		// Invalid values ignored and default preserved
		t.Setenv("RW_BATCH_SIZE", "invalid-number")
		optsDefault, _ := parsePushOptions([]string{})
		if optsDefault.BatchSize != 50 {
			t.Errorf("expected default BatchSize=50 on invalid string, got %d", optsDefault.BatchSize)
		}
	})

	t.Run("RW_FLUSH_INTERVAL", func(t *testing.T) {
		t.Setenv("RW_FLUSH_INTERVAL", "3500ms")
		opts, _ := parsePushOptions([]string{})
		if opts.FlushInterval != 3500*time.Millisecond {
			t.Errorf("expected RW_FLUSH_INTERVAL=3500ms, got %v", opts.FlushInterval)
		}

		t.Setenv("RW_FLUSH_INTERVAL", "bad-duration")
		optsDefault, _ := parsePushOptions([]string{})
		if optsDefault.FlushInterval != 1*time.Second {
			t.Errorf("expected default FlushInterval=1s on invalid duration, got %v", optsDefault.FlushInterval)
		}
	})

	t.Run("RW_QUEUE_SIZE", func(t *testing.T) {
		t.Setenv("RW_QUEUE_SIZE", "50000")
		opts, _ := parsePushOptions([]string{})
		if opts.MaxQueueSize != 50000 {
			t.Errorf("expected RW_QUEUE_SIZE=50000, got %d", opts.MaxQueueSize)
		}
	})

	t.Run("RW_DISCONNECT_TIMEOUT", func(t *testing.T) {
		t.Setenv("RW_DISCONNECT_TIMEOUT", "12m")
		opts, _ := parsePushOptions([]string{})
		if opts.DisconnectTimeout != 12*time.Minute {
			t.Errorf("expected RW_DISCONNECT_TIMEOUT=12m, got %v", opts.DisconnectTimeout)
		}
	})

	t.Run("RW_PING_INTERVAL", func(t *testing.T) {
		t.Setenv("RW_PING_INTERVAL", "25s")
		opts, _ := parsePushOptions([]string{})
		if opts.PingInterval != 25*time.Second {
			t.Errorf("expected RW_PING_INTERVAL=25s, got %v", opts.PingInterval)
		}
	})

	t.Run("RW_VERBOSE and RW_DEBUG fallback", func(t *testing.T) {
		t.Setenv("RW_VERBOSE", "1")
		opts1, _ := parsePushOptions([]string{})
		if !opts1.Verbose {
			t.Errorf("expected Verbose=true for RW_VERBOSE=1")
		}

		t.Setenv("RW_VERBOSE", "")
		t.Setenv("RW_DEBUG", "true")
		opts2, _ := parsePushOptions([]string{})
		if !opts2.Verbose {
			t.Errorf("expected Verbose=true for RW_DEBUG=true fallback")
		}
	})

	t.Run("RW_DETACH", func(t *testing.T) {
		for _, val := range []string{"1", "true", "True"} {
			t.Setenv("RW_DETACH", val)
			opts, _ := parsePushOptions([]string{})
			if !opts.DetachMode {
				t.Errorf("expected DetachMode=true for RW_DETACH=%s", val)
			}
		}
	})

	t.Run("RW_STATUS, RW_STATUS_CODES, RW_INCLUDE_STATUS", func(t *testing.T) {
		// 1. RW_STATUS
		t.Setenv("RW_STATUS", "400-599, 301")
		t.Setenv("RW_STATUS_CODES", "")
		t.Setenv("RW_INCLUDE_STATUS", "")
		opts1, _ := parsePushOptions([]string{})
		if opts1.StatusCodesFlag != "400-599, 301" {
			t.Errorf("expected RW_STATUS=400-599, 301, got %s", opts1.StatusCodesFlag)
		}

		// 2. RW_STATUS_CODES fallback
		t.Setenv("RW_STATUS", "")
		t.Setenv("RW_STATUS_CODES", "4xx, 5xx")
		opts2, _ := parsePushOptions([]string{})
		if opts2.StatusCodesFlag != "4xx, 5xx" {
			t.Errorf("expected RW_STATUS_CODES=4xx, 5xx, got %s", opts2.StatusCodesFlag)
		}

		// 3. RW_INCLUDE_STATUS fallback
		t.Setenv("RW_STATUS_CODES", "")
		t.Setenv("RW_INCLUDE_STATUS", "301, 302")
		opts3, _ := parsePushOptions([]string{})
		if opts3.StatusCodesFlag != "301, 302" {
			t.Errorf("expected RW_INCLUDE_STATUS=301, 302, got %s", opts3.StatusCodesFlag)
		}
	})

	t.Run("RW_INCLUDE_FAILED", func(t *testing.T) {
		t.Setenv("RW_INCLUDE_FAILED", "1")
		opts, _ := parsePushOptions([]string{})
		if !opts.IncludeFailed || opts.StatusCodesFlag != "400-599" {
			t.Errorf("expected IncludeFailed=true and StatusCodes=400-599, got failed=%v, status=%s",
				opts.IncludeFailed, opts.StatusCodesFlag)
		}
	})

	t.Run("RW_ALL_TRAFFIC", func(t *testing.T) {
		for _, val := range []string{"1", "true", "TRUE"} {
			t.Setenv("RW_ALL_TRAFFIC", val)
			opts, _ := parsePushOptions([]string{})
			if !opts.AllTraffic {
				t.Errorf("expected AllTraffic=true for RW_ALL_TRAFFIC=%s", val)
			}
		}
	})

	t.Run("RW_ALL_LOGS", func(t *testing.T) {
		for _, val := range []string{"1", "true", "TRUE"} {
			t.Setenv("RW_ALL_LOGS", val)
			opts, _ := parsePushOptions([]string{})
			if !opts.AllLogs {
				t.Errorf("expected AllLogs=true for RW_ALL_LOGS=%s", val)
			}
		}
	})
}

func TestPushOptions_FlagOverridesEnvironment(t *testing.T) {
	t.Setenv("RW_DASHBOARD_URL", "http://env-dashboard:7890")
	t.Setenv("RW_AGENT_KEY", "rw_sec_env_key")
	t.Setenv("RW_CONFIG", "/env/agent.json")
	t.Setenv("RW_LABEL", "env=staging")
	t.Setenv("RW_TAIL", "10")
	t.Setenv("RW_BATCH_SIZE", "20")
	t.Setenv("RW_FLUSH_INTERVAL", "10s")
	t.Setenv("RW_QUEUE_SIZE", "1000")
	t.Setenv("RW_DISCONNECT_TIMEOUT", "1m")
	t.Setenv("RW_PING_INTERVAL", "5s")
	t.Setenv("RW_STATUS", "5xx")

	args := []string{
		"--url", "http://cli-override:7890",
		"--key", "rw_sec_cli_key",
		"--config", "/cli/agent.json",
		"--label", "cli=prod",
		"--tail", "999",
		"--batch-size", "500",
		"--flush-interval", "100ms",
		"--queue-size", "99999",
		"--disconnect-timeout", "30m",
		"--ping-interval", "60s",
		"--status", "400-404",
	}

	opts, err := parsePushOptions(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.URL != "http://cli-override:7890" {
		t.Errorf("expected URL override, got %s", opts.URL)
	}
	if opts.Key != "rw_sec_cli_key" {
		t.Errorf("expected Key override, got %s", opts.Key)
	}
	if opts.ConfigPath != "/cli/agent.json" {
		t.Errorf("expected ConfigPath override, got %s", opts.ConfigPath)
	}
	if opts.CustomLabel != "cli=prod" {
		t.Errorf("expected CustomLabel override, got %s", opts.CustomLabel)
	}
	if opts.TailLines != "999" {
		t.Errorf("expected TailLines override, got %s", opts.TailLines)
	}
	if opts.BatchSize != 500 {
		t.Errorf("expected BatchSize override, got %d", opts.BatchSize)
	}
	if opts.FlushInterval != 100*time.Millisecond {
		t.Errorf("expected FlushInterval override, got %v", opts.FlushInterval)
	}
	if opts.MaxQueueSize != 99999 {
		t.Errorf("expected MaxQueueSize override, got %d", opts.MaxQueueSize)
	}
	if opts.DisconnectTimeout != 30*time.Minute {
		t.Errorf("expected DisconnectTimeout override, got %v", opts.DisconnectTimeout)
	}
	if opts.PingInterval != 60*time.Second {
		t.Errorf("expected PingInterval override, got %v", opts.PingInterval)
	}
	if opts.StatusCodesFlag != "400-404" {
		t.Errorf("expected StatusCodesFlag override, got %s", opts.StatusCodesFlag)
	}
}

func TestRegisterOptions_AllFlagsAndEnvVars(t *testing.T) {
	t.Run("flags and aliases", func(t *testing.T) {
		opts1, err := parseRegisterOptions([]string{
			"--url", "http://soc.internal:7890",
			"--key", "rw_sec_register_key",
			"--config", "/etc/routewarden/agent.json",
			"--status", "400-599, 301",
			"--all-traffic",
			"--all-logs",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts1.DashboardURL != "http://soc.internal:7890" || opts1.AgentToken != "rw_sec_register_key" {
			t.Errorf("failed register url/key: url=%s, token=%s", opts1.DashboardURL, opts1.AgentToken)
		}
		if opts1.ConfigPath != "/etc/routewarden/agent.json" {
			t.Errorf("failed register config: %s", opts1.ConfigPath)
		}
		if opts1.StatusCodesFlag != "400-599, 301" || !opts1.AllTraffic || !opts1.AllLogs {
			t.Errorf("failed register flags: status=%s, allTraffic=%v, allLogs=%v",
				opts1.StatusCodesFlag, opts1.AllTraffic, opts1.AllLogs)
		}

		// Aliases
		opts2, err := parseRegisterOptions([]string{
			"-u", "http://soc.alias:7890",
			"-k", "rw_sec_alias",
			"-s", "5xx",
			"-F",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts2.DashboardURL != "http://soc.alias:7890" || opts2.AgentToken != "rw_sec_alias" {
			t.Errorf("failed register aliases: url=%s, token=%s", opts2.DashboardURL, opts2.AgentToken)
		}
		if opts2.StatusCodesFlag != "5xx" || !opts2.IncludeFailed {
			t.Errorf("failed register status/failed aliases: status=%s, failed=%v", opts2.StatusCodesFlag, opts2.IncludeFailed)
		}
	})

	t.Run("environment variables", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "http://env-soc:7890")
		t.Setenv("RW_AGENT_KEY", "rw_sec_env_reg")
		t.Setenv("RW_STATUS", "400-599")
		t.Setenv("RW_ALL_TRAFFIC", "true")
		t.Setenv("RW_ALL_LOGS", "1")

		opts, err := parseRegisterOptions([]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.DashboardURL != "http://env-soc:7890" {
			t.Errorf("expected RW_DASHBOARD_URL=http://env-soc:7890, got %s", opts.DashboardURL)
		}
		if opts.AgentToken != "rw_sec_env_reg" {
			t.Errorf("expected RW_AGENT_KEY=rw_sec_env_reg, got %s", opts.AgentToken)
		}
		if opts.StatusCodesFlag != "400-599" {
			t.Errorf("expected RW_STATUS=400-599, got %s", opts.StatusCodesFlag)
		}
		if !opts.AllTraffic || !opts.AllLogs {
			t.Errorf("expected AllTraffic and AllLogs true from env: traffic=%v, logs=%v", opts.AllTraffic, opts.AllLogs)
		}

		// Fallback env vars
		t.Setenv("RW_DASHBOARD_URL", "")
		t.Setenv("RW_URL", "http://env-fallback:7890")
		t.Setenv("RW_AGENT_KEY", "")
		t.Setenv("RW_KEY", "rw_sec_fallback_key")
		optsFallback, _ := parseRegisterOptions([]string{})
		if optsFallback.DashboardURL != "http://env-fallback:7890" || optsFallback.AgentToken != "rw_sec_fallback_key" {
			t.Errorf("expected fallback env vars: url=%s, key=%s", optsFallback.DashboardURL, optsFallback.AgentToken)
		}
	})

	t.Run("flags override environment variables", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "http://env-url:7890")
		t.Setenv("RW_AGENT_KEY", "rw_sec_env")
		opts, err := parseRegisterOptions([]string{"-u", "http://cli-override:7890", "-k", "rw_sec_cli"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.DashboardURL != "http://cli-override:7890" || opts.AgentToken != "rw_sec_cli" {
			t.Errorf("expected CLI flags to override env: url=%s, token=%s", opts.DashboardURL, opts.AgentToken)
		}
	})
}

func TestPush_Precedence_Hierarchy(t *testing.T) {
	t.Run("CLI Flag overrides Env Var, AgentConfig, and Defaults", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "http://env-url:7890")
		t.Setenv("RW_AGENT_KEY", "rw_env_key")
		t.Setenv("RW_STATUS", "301")
		t.Setenv("RW_ALL_TRAFFIC", "false")
		t.Setenv("RW_ALL_LOGS", "false")
		t.Setenv("RW_TAIL", "10")
		t.Setenv("RW_BATCH_SIZE", "20")

		agentCfg := &AgentConfig{
			DashboardURL: "http://cfg-url:7890",
			AgentToken:   "rw_cfg_key",
			StatusCodes:  "400-404",
			AllTraffic:   false,
			AllLogs:      false,
		}

		args := []string{
			"--url", "http://cli-url:7890",
			"--key", "rw_cli_key",
			"--status", "500-504",
			"--all-traffic",
			"--all-logs",
			"--tail", "999",
			"--batch-size", "500",
		}

		opts, err := parsePushOptions(args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resolved := resolvePushConfig(opts, agentCfg)

		if resolved.DashboardURL != "http://cli-url:7890" {
			t.Errorf("expected CLI URL to override env and config, got %s", resolved.DashboardURL)
		}
		if resolved.AgentToken != "rw_cli_key" {
			t.Errorf("expected CLI Key to override env and config, got %s", resolved.AgentToken)
		}
		if resolved.StatusCodesFlag != "500-504" {
			t.Errorf("expected CLI StatusCodes to override env and config, got %s", resolved.StatusCodesFlag)
		}
		if !resolved.AllTraffic {
			t.Errorf("expected CLI AllTraffic=true to override env and config")
		}
		if !resolved.AllLogs {
			t.Errorf("expected CLI AllLogs=true to override env and config")
		}
		if opts.TailLines != "999" || opts.BatchSize != 500 {
			t.Errorf("expected CLI flags for tail and batch size: tail=%s, batch=%d", opts.TailLines, opts.BatchSize)
		}
	})

	t.Run("Env Var overrides AgentConfig and Defaults when CLI Flag omitted", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "http://env-url:7890")
		t.Setenv("RW_AGENT_KEY", "rw_env_key")
		t.Setenv("RW_STATUS", "5xx")
		t.Setenv("RW_ALL_TRAFFIC", "true")
		t.Setenv("RW_ALL_LOGS", "1")

		agentCfg := &AgentConfig{
			DashboardURL: "http://cfg-url:7890",
			AgentToken:   "rw_cfg_key",
			StatusCodes:  "400-404",
			AllTraffic:   false,
			AllLogs:      false,
		}

		opts, err := parsePushOptions([]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resolved := resolvePushConfig(opts, agentCfg)

		if resolved.DashboardURL != "http://env-url:7890" {
			t.Errorf("expected Env URL to override config, got %s", resolved.DashboardURL)
		}
		if resolved.AgentToken != "rw_env_key" {
			t.Errorf("expected Env Key to override config, got %s", resolved.AgentToken)
		}
		if resolved.StatusCodesFlag != "5xx" {
			t.Errorf("expected Env Status to override config, got %s", resolved.StatusCodesFlag)
		}
		if !resolved.AllTraffic {
			t.Errorf("expected Env AllTraffic to override config")
		}
		if !resolved.AllLogs {
			t.Errorf("expected Env AllLogs to override config")
		}
	})

	t.Run("AgentConfig overrides Defaults when CLI Flag and Env Var omitted", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "")
		t.Setenv("RW_URL", "")
		t.Setenv("RW_AGENT_KEY", "")
		t.Setenv("RW_KEY", "")
		t.Setenv("RW_STATUS", "")
		t.Setenv("RW_STATUS_CODES", "")
		t.Setenv("RW_INCLUDE_STATUS", "")
		t.Setenv("RW_ALL_TRAFFIC", "")
		t.Setenv("RW_ALL_LOGS", "")

		agentCfg := &AgentConfig{
			DashboardURL: "http://cfg-url:7890",
			AgentToken:   "rw_cfg_key",
			StatusCodes:  "400-499",
			AllTraffic:   true,
			AllLogs:      false,
		}

		opts, err := parsePushOptions([]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resolved := resolvePushConfig(opts, agentCfg)

		if resolved.DashboardURL != "http://cfg-url:7890" {
			t.Errorf("expected Config URL, got %s", resolved.DashboardURL)
		}
		if resolved.AgentToken != "rw_cfg_key" {
			t.Errorf("expected Config Key, got %s", resolved.AgentToken)
		}
		if resolved.StatusCodesFlag != "400-499" {
			t.Errorf("expected Config StatusCodes, got %s", resolved.StatusCodesFlag)
		}
		if !resolved.AllTraffic {
			t.Errorf("expected Config AllTraffic=true")
		}
		if resolved.AllLogs {
			t.Errorf("expected Config AllLogs=false")
		}
	})

	t.Run("AgentConfig IncludeFailed defaults StatusCodes to 400-599 when StatusCodes empty", func(t *testing.T) {
		t.Setenv("RW_STATUS", "")
		t.Setenv("RW_STATUS_CODES", "")
		t.Setenv("RW_INCLUDE_STATUS", "")
		t.Setenv("RW_INCLUDE_FAILED", "")

		agentCfg := &AgentConfig{
			DashboardURL:  "http://cfg-url:7890",
			AgentToken:    "rw_cfg_key",
			IncludeFailed: true,
			StatusCodes:   "",
		}

		opts, err := parsePushOptions([]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resolved := resolvePushConfig(opts, agentCfg)

		if !resolved.IncludeFailed {
			t.Errorf("expected IncludeFailed=true from config")
		}
		if resolved.StatusCodesFlag != "400-599" {
			t.Errorf("expected default StatusCodes 400-599 for IncludeFailed, got %s", resolved.StatusCodesFlag)
		}
	})

	t.Run("Defaults apply when Flag, Env, and Config are omitted", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "")
		t.Setenv("RW_URL", "")
		t.Setenv("RW_AGENT_KEY", "")
		t.Setenv("RW_KEY", "")
		t.Setenv("RW_STATUS", "")
		t.Setenv("RW_ALL_TRAFFIC", "")
		t.Setenv("RW_ALL_LOGS", "")

		opts, err := parsePushOptions([]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resolved := resolvePushConfig(opts, nil)

		if resolved.DashboardURL != "" || resolved.AgentToken != "" {
			t.Errorf("expected empty URL and Token on unconfigured agent: url=%s, key=%s", resolved.DashboardURL, resolved.AgentToken)
		}
		if resolved.AllTraffic || resolved.AllLogs || resolved.IncludeFailed {
			t.Errorf("expected false for boolean filter flags")
		}
		if opts.BatchSize != 50 || opts.FlushInterval != 1*time.Second || opts.MaxQueueSize != 10000 {
			t.Errorf("expected standard defaults for queue and batching")
		}
	})

	t.Run("Config file path precedence: CLI Flag > RW_CONFIG > Default", func(t *testing.T) {
		// 1. CLI flag overrides RW_CONFIG
		t.Setenv("RW_CONFIG", "/env/agent.json")
		opts1, _ := parsePushOptions([]string{"--config", "/cli/agent.json"})
		if opts1.ConfigPath != "/cli/agent.json" {
			t.Errorf("expected CLI --config to override RW_CONFIG, got %s", opts1.ConfigPath)
		}

		// 2. RW_CONFIG takes effect when flag omitted
		opts2, _ := parsePushOptions([]string{})
		if opts2.ConfigPath != "/env/agent.json" {
			t.Errorf("expected RW_CONFIG to take effect, got %s", opts2.ConfigPath)
		}

		// 3. Default path when neither specified
		t.Setenv("RW_CONFIG", "")
		opts3, _ := parsePushOptions([]string{})
		if opts3.ConfigPath != "" {
			t.Errorf("expected empty ConfigPath for default resolution, got %s", opts3.ConfigPath)
		}
	})
}

func TestPush_EnvironmentVariable_FallbackPrecedence(t *testing.T) {
	t.Run("RW_DASHBOARD_URL takes precedence over RW_URL", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "http://primary:7890")
		t.Setenv("RW_URL", "http://fallback:7890")
		opts, _ := parsePushOptions([]string{})
		if opts.URL != "http://primary:7890" {
			t.Errorf("expected primary RW_DASHBOARD_URL, got %s", opts.URL)
		}
	})

	t.Run("RW_AGENT_KEY takes precedence over RW_KEY", func(t *testing.T) {
		t.Setenv("RW_AGENT_KEY", "primary_key")
		t.Setenv("RW_KEY", "fallback_key")
		opts, _ := parsePushOptions([]string{})
		if opts.Key != "primary_key" {
			t.Errorf("expected primary RW_AGENT_KEY, got %s", opts.Key)
		}
	})

	t.Run("RW_STATUS takes precedence over RW_STATUS_CODES and RW_INCLUDE_STATUS", func(t *testing.T) {
		t.Setenv("RW_STATUS", "400-404")
		t.Setenv("RW_STATUS_CODES", "500-504")
		t.Setenv("RW_INCLUDE_STATUS", "301")
		opts, _ := parsePushOptions([]string{})
		if opts.StatusCodesFlag != "400-404" {
			t.Errorf("expected RW_STATUS precedence, got %s", opts.StatusCodesFlag)
		}

		t.Setenv("RW_STATUS", "")
		optsFallback1, _ := parsePushOptions([]string{})
		if optsFallback1.StatusCodesFlag != "500-504" {
			t.Errorf("expected RW_STATUS_CODES precedence over RW_INCLUDE_STATUS, got %s", optsFallback1.StatusCodesFlag)
		}

		t.Setenv("RW_STATUS_CODES", "")
		optsFallback2, _ := parsePushOptions([]string{})
		if optsFallback2.StatusCodesFlag != "301" {
			t.Errorf("expected RW_INCLUDE_STATUS fallback, got %s", optsFallback2.StatusCodesFlag)
		}
	})

	t.Run("RW_VERBOSE takes precedence over RW_DEBUG", func(t *testing.T) {
		t.Setenv("RW_VERBOSE", "1")
		t.Setenv("RW_DEBUG", "false")
		opts, _ := parsePushOptions([]string{})
		if !opts.Verbose {
			t.Errorf("expected RW_VERBOSE=1 to set Verbose=true")
		}
	})
}

func TestPush_FlagAliases_Equivalence(t *testing.T) {
	pairs := []struct {
		name      string
		longFlag  []string
		shortFlag []string
		assertFn  func(t *testing.T, longOpts, shortOpts *PushOptions)
	}{
		{
			name:      "url: --url vs -u",
			longFlag:  []string{"--url", "http://soc.test:7890"},
			shortFlag: []string{"-u", "http://soc.test:7890"},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if l.URL != s.URL || l.URL != "http://soc.test:7890" {
					t.Errorf("mismatch: long=%s, short=%s", l.URL, s.URL)
				}
			},
		},
		{
			name:      "key: --key vs -k",
			longFlag:  []string{"--key", "sec_token_123"},
			shortFlag: []string{"-k", "sec_token_123"},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if l.Key != s.Key || l.Key != "sec_token_123" {
					t.Errorf("mismatch: long=%s, short=%s", l.Key, s.Key)
				}
			},
		},
		{
			name:      "status: --status vs -s",
			longFlag:  []string{"--status", "4xx, 5xx"},
			shortFlag: []string{"-s", "4xx, 5xx"},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if l.StatusCodesFlag != s.StatusCodesFlag || l.StatusCodesFlag != "4xx, 5xx" {
					t.Errorf("mismatch: long=%s, short=%s", l.StatusCodesFlag, s.StatusCodesFlag)
				}
			},
		},
		{
			name:      "include-failed: --include-failed vs -F",
			longFlag:  []string{"--include-failed"},
			shortFlag: []string{"-F"},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if l.IncludeFailed != s.IncludeFailed || !l.IncludeFailed {
					t.Errorf("mismatch: long=%v, short=%v", l.IncludeFailed, s.IncludeFailed)
				}
			},
		},
		{
			name:      "detach: --detach vs -d",
			longFlag:  []string{"--detach"},
			shortFlag: []string{"-d"},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if l.DetachMode != s.DetachMode || !l.DetachMode {
					t.Errorf("mismatch: long=%v, short=%v", l.DetachMode, s.DetachMode)
				}
			},
		},
		{
			name:      "verbose: --verbose vs -v",
			longFlag:  []string{"--verbose"},
			shortFlag: []string{"-v"},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if l.Verbose != s.Verbose || !l.Verbose {
					t.Errorf("mismatch: long=%v, short=%v", l.Verbose, s.Verbose)
				}
			},
		},
		{
			name:      "label: --label vs -l",
			longFlag:  []string{"--label", "app=prod"},
			shortFlag: []string{"-l", "app=prod"},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if l.CustomLabel != s.CustomLabel || l.CustomLabel != "app=prod" {
					t.Errorf("mismatch: long=%s, short=%s", l.CustomLabel, s.CustomLabel)
				}
			},
		},
		{
			name:      "container: --container vs -c",
			longFlag:  []string{"--container", "caddy,traefik"},
			shortFlag: []string{"-c", "caddy,traefik"},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if !reflect.DeepEqual(l.ContainerFlags, s.ContainerFlags) {
					t.Errorf("mismatch: long=%v, short=%v", l.ContainerFlags, s.ContainerFlags)
				}
			},
		},
		{
			name:      "file: --file vs -f",
			longFlag:  []string{"--file", "/var/log/app.log"},
			shortFlag: []string{"-f", "/var/log/app.log"},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if !reflect.DeepEqual(l.FileFlags, s.FileFlags) {
					t.Errorf("mismatch: long=%v, short=%v", l.FileFlags, s.FileFlags)
				}
			},
		},
		{
			name:      "event: --event vs -e",
			longFlag:  []string{"--event", `{"attack":"sqli"}`},
			shortFlag: []string{"-e", `{"attack":"sqli"}`},
			assertFn: func(t *testing.T, l, s *PushOptions) {
				if !reflect.DeepEqual(l.EventFlags, s.EventFlags) {
					t.Errorf("mismatch: long=%v, short=%v", l.EventFlags, s.EventFlags)
				}
			},
		},
	}

	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			lOpts, errL := parsePushOptions(p.longFlag)
			sOpts, errS := parsePushOptions(p.shortFlag)
			if errL != nil || errS != nil {
				t.Fatalf("unexpected error: longErr=%v, shortErr=%v", errL, errS)
			}
			p.assertFn(t, lOpts, sOpts)
		})
	}
}

func TestPush_Filtering_FlagPreference(t *testing.T) {
	rawSysLog := `Feb 12 10:00:00 server systemd[1]: Started nginx service.`
	rawErrorLog := `ERROR 2026-10-27T10:00:00 database pool connection timed out`
	secEventJSON := `{"event":"waf_block","rule":"sqli","status":403,"client_ip":"198.51.100.1"}`
	secEventString := `[RouteWarden WAF] BLOCKED IP 198.51.100.1 - SQL injection detected`
	http200JSON := `{"status":200,"method":"GET","path":"/index.html","remote_addr":"10.0.0.1"}`
	http301JSON := `{"status":301,"method":"GET","path":"/old","remote_addr":"10.0.0.1"}`
	http404JSON := `{"status":404,"method":"GET","path":"/not-found","remote_addr":"10.0.0.1"}`
	http500JSON := `{"status":500,"method":"POST","path":"/api/checkout","remote_addr":"10.0.0.1"}`
	http502JSON := `{"status":502,"method":"GET","path":"/upstream","remote_addr":"10.0.0.1"}`

	t.Run("Preference 1: AllLogs passes all raw lines overriding other filters", func(t *testing.T) {
		opts := FilterOptions{
			AllLogs:       true,
			AllTraffic:    false,
			IncludeFailed: false,
		}
		for _, line := range []string{rawSysLog, rawErrorLog, http200JSON, http404JSON, http500JSON, secEventJSON} {
			_, ok := filterRouteWardenLogOpts(line, opts)
			if !ok {
				t.Errorf("expected line to pass when AllLogs=true: %s", line)
			}
		}

		optsNoAllLogs := FilterOptions{
			AllLogs:    false,
			AllTraffic: true,
		}
		if _, ok := filterRouteWardenLogOpts(rawSysLog, optsNoAllLogs); ok {
			t.Errorf("expected rawSysLog to be dropped when AllLogs=false")
		}
		if _, ok := filterRouteWardenLogOpts(rawErrorLog, optsNoAllLogs); ok {
			t.Errorf("expected rawErrorLog to be dropped when AllLogs=false")
		}
	})

	t.Run("Preference 2: Security Events pass regardless of HTTP traffic or status code filters", func(t *testing.T) {
		opts := FilterOptions{
			StatusCodes:   ParseStatusCodeFilter("500-504"),
			AllTraffic:    false,
			IncludeFailed: false,
		}
		if _, ok := filterRouteWardenLogOpts(secEventJSON, opts); !ok {
			t.Errorf("expected security event JSON to pass even when status filter is 500-504")
		}
		if _, ok := filterRouteWardenLogOpts(secEventString, opts); !ok {
			t.Errorf("expected security event string to pass even when status filter is 500-504")
		}
	})

	t.Run("Preference 3: AllTraffic overrides status code restrictions for HTTP requests", func(t *testing.T) {
		opts := FilterOptions{
			AllTraffic:    true,
			StatusCodes:   ParseStatusCodeFilter("500-504"),
			IncludeFailed: true,
		}
		if _, ok := filterRouteWardenLogOpts(http200JSON, opts); !ok {
			t.Errorf("expected 200 OK to pass when AllTraffic=true")
		}
		if _, ok := filterRouteWardenLogOpts(http301JSON, opts); !ok {
			t.Errorf("expected 301 Redirect to pass when AllTraffic=true")
		}
		if _, ok := filterRouteWardenLogOpts(http404JSON, opts); !ok {
			t.Errorf("expected 404 to pass when AllTraffic=true")
		}
		if _, ok := filterRouteWardenLogOpts(http500JSON, opts); !ok {
			t.Errorf("expected 500 to pass when AllTraffic=true")
		}
	})

	t.Run("Preference 4: Explicit StatusCodes takes precedence over IncludeFailed", func(t *testing.T) {
		opts := FilterOptions{
			StatusCodes:   ParseStatusCodeFilter("500-504"),
			IncludeFailed: true,
		}
		if _, ok := filterRouteWardenLogOpts(http500JSON, opts); !ok {
			t.Errorf("expected 500 to match StatusCodes 500-504")
		}
		if _, ok := filterRouteWardenLogOpts(http502JSON, opts); !ok {
			t.Errorf("expected 502 to match StatusCodes 500-504")
		}
		if _, ok := filterRouteWardenLogOpts(http404JSON, opts); ok {
			t.Errorf("expected 404 to be dropped because explicit StatusCodes 500-504 takes preference over IncludeFailed")
		}
		if _, ok := filterRouteWardenLogOpts(http200JSON, opts); ok {
			t.Errorf("expected 200 to be dropped")
		}
	})

	t.Run("Preference 5: IncludeFailed fallback passes all 4xx/5xx and drops 2xx/3xx", func(t *testing.T) {
		opts := FilterOptions{
			IncludeFailed: true,
		}
		if _, ok := filterRouteWardenLogOpts(http404JSON, opts); !ok {
			t.Errorf("expected 404 to pass on IncludeFailed")
		}
		if _, ok := filterRouteWardenLogOpts(http500JSON, opts); !ok {
			t.Errorf("expected 500 to pass on IncludeFailed")
		}
		if _, ok := filterRouteWardenLogOpts(http200JSON, opts); ok {
			t.Errorf("expected 200 to be dropped on IncludeFailed")
		}
		if _, ok := filterRouteWardenLogOpts(http301JSON, opts); ok {
			t.Errorf("expected 301 to be dropped on IncludeFailed")
		}
	})

	t.Run("Preference 6: Default (no flags) drops non-security HTTP traffic", func(t *testing.T) {
		opts := FilterOptions{}
		if _, ok := filterRouteWardenLogOpts(http200JSON, opts); ok {
			t.Errorf("expected 200 to be dropped by default")
		}
		if _, ok := filterRouteWardenLogOpts(http404JSON, opts); ok {
			t.Errorf("expected 404 to be dropped by default")
		}
		if _, ok := filterRouteWardenLogOpts(http500JSON, opts); ok {
			t.Errorf("expected 500 to be dropped by default")
		}
		if _, ok := filterRouteWardenLogOpts(secEventJSON, opts); !ok {
			t.Errorf("expected security event to pass by default")
		}
	})
}

