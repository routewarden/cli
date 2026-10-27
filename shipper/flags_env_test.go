package shipper

import (
	"reflect"
	"testing"
	"time"
)

func TestShipperPushOptions_AllFlagsAndAliases(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{})
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
		opts1, err := ParsePushOptions([]string{"--url", "http://soc.internal:7890", "--key", "rw_sec_long_key"})
		if err != nil || opts1.URL != "http://soc.internal:7890" || opts1.Key != "rw_sec_long_key" {
			t.Errorf("failed long flags: url=%s, key=%s, err=%v", opts1.URL, opts1.Key, err)
		}

		opts2, err := ParsePushOptions([]string{"-u", "http://soc.short:7890", "-k", "rw_sec_short_key"})
		if err != nil || opts2.URL != "http://soc.short:7890" || opts2.Key != "rw_sec_short_key" {
			t.Errorf("failed short aliases: url=%s, key=%s, err=%v", opts2.URL, opts2.Key, err)
		}
	})

	t.Run("config flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--config", "/etc/routewarden/custom.json"})
		if err != nil || opts.ConfigPath != "/etc/routewarden/custom.json" {
			t.Errorf("failed config flag: %s, err=%v", opts.ConfigPath, err)
		}
	})

	t.Run("docker flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--docker"})
		if err != nil || !opts.DockerMode {
			t.Errorf("failed docker flag: %v, err=%v", opts.DockerMode, err)
		}
	})

	t.Run("detach flag and alias", func(t *testing.T) {
		opts1, err := ParsePushOptions([]string{"--detach"})
		if err != nil || !opts1.DetachMode {
			t.Errorf("failed --detach: %v", opts1.DetachMode)
		}
		opts2, err := ParsePushOptions([]string{"-d"})
		if err != nil || !opts2.DetachMode {
			t.Errorf("failed -d: %v", opts2.DetachMode)
		}
	})

	t.Run("container flag, alias, repeatable and comma-separated", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"-c", "traefik", "--container", "caddy,nginx", "-c", "envoy"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []string{"traefik", "caddy,nginx", "envoy"}
		if !reflect.DeepEqual(opts.ContainerFlags, expected) {
			t.Errorf("expected container flags %v, got %v", expected, opts.ContainerFlags)
		}
	})

	t.Run("file flag, alias, repeatable and comma-separated", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"-f", "/var/log/caddy.log", "--file", "/var/log/nginx.log,/var/log/traefik.log"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []string{"/var/log/caddy.log", "/var/log/nginx.log,/var/log/traefik.log"}
		if !reflect.DeepEqual(opts.FileFlags, expected) {
			t.Errorf("expected file flags %v, got %v", expected, opts.FileFlags)
		}
	})

	t.Run("event flag, alias, repeatable", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"-e", `{"event":"1"}`, "--event", `{"event":"2"}`})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []string{`{"event":"1"}`, `{"event":"2"}`}
		if !reflect.DeepEqual(opts.EventFlags, expected) {
			t.Errorf("expected event flags %v, got %v", expected, opts.EventFlags)
		}
	})

	t.Run("stdin flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--stdin"})
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
			opts, err := ParsePushOptions([]string{tc.flag, tc.val})
			if err != nil || opts.StatusCodesFlag != tc.val {
				t.Errorf("alias %s failed: got %q, expected %q, err=%v", tc.alias, opts.StatusCodesFlag, tc.val, err)
			}
		}
	})

	t.Run("include-failed flag and alias", func(t *testing.T) {
		opts1, err := ParsePushOptions([]string{"--include-failed"})
		if err != nil || !opts1.IncludeFailed || opts1.StatusCodesFlag != "400-599" {
			t.Errorf("failed --include-failed: failed=%v, status=%s", opts1.IncludeFailed, opts1.StatusCodesFlag)
		}
		opts2, err := ParsePushOptions([]string{"-F"})
		if err != nil || !opts2.IncludeFailed || opts2.StatusCodesFlag != "400-599" {
			t.Errorf("failed -F alias: failed=%v, status=%s", opts2.IncludeFailed, opts2.StatusCodesFlag)
		}
	})

	t.Run("all-traffic flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--all-traffic"})
		if err != nil || !opts.AllTraffic {
			t.Errorf("failed all-traffic flag: %v", opts.AllTraffic)
		}
	})

	t.Run("all-logs flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--all-logs"})
		if err != nil || !opts.AllLogs {
			t.Errorf("failed all-logs flag: %v", opts.AllLogs)
		}
	})

	t.Run("label flag and alias", func(t *testing.T) {
		opts1, err := ParsePushOptions([]string{"--label", "com.docker.stack=waf"})
		if err != nil || opts1.CustomLabel != "com.docker.stack=waf" {
			t.Errorf("failed --label: %s", opts1.CustomLabel)
		}
		opts2, err := ParsePushOptions([]string{"-l", "env=prod"})
		if err != nil || opts2.CustomLabel != "env=prod" {
			t.Errorf("failed -l alias: %s", opts2.CustomLabel)
		}
	})

	t.Run("tail flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--tail", "500"})
		if err != nil || opts.TailLines != "500" {
			t.Errorf("failed tail flag: %s", opts.TailLines)
		}
	})

	t.Run("batch-size flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--batch-size", "100"})
		if err != nil || opts.BatchSize != 100 {
			t.Errorf("failed batch-size flag: %d", opts.BatchSize)
		}
	})

	t.Run("flush-interval flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--flush-interval", "2500ms"})
		if err != nil || opts.FlushInterval != 2500*time.Millisecond {
			t.Errorf("failed flush-interval flag: %v", opts.FlushInterval)
		}
	})

	t.Run("queue-size flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--queue-size", "25000"})
		if err != nil || opts.MaxQueueSize != 25000 {
			t.Errorf("failed queue-size flag: %d", opts.MaxQueueSize)
		}
	})

	t.Run("disconnect-timeout flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--disconnect-timeout", "15m"})
		if err != nil || opts.DisconnectTimeout != 15*time.Minute {
			t.Errorf("failed disconnect-timeout flag: %v", opts.DisconnectTimeout)
		}
	})

	t.Run("ping-interval flag", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--ping-interval", "45s"})
		if err != nil || opts.PingInterval != 45*time.Second {
			t.Errorf("failed ping-interval flag: %v", opts.PingInterval)
		}
	})

	t.Run("verbose flag and alias", func(t *testing.T) {
		opts1, err := ParsePushOptions([]string{"--verbose"})
		if err != nil || !opts1.Verbose {
			t.Errorf("failed --verbose: %v", opts1.Verbose)
		}
		opts2, err := ParsePushOptions([]string{"-v"})
		if err != nil || !opts2.Verbose {
			t.Errorf("failed -v alias: %v", opts2.Verbose)
		}
	})

	t.Run("subcommand prefixes up, start, run", func(t *testing.T) {
		for _, sub := range []string{"up", "start", "run"} {
			opts, err := ParsePushOptions([]string{sub, "--docker", "-d"})
			if err != nil {
				t.Fatalf("subcommand %s error: %v", sub, err)
			}
			if !opts.DockerMode || !opts.DetachMode {
				t.Errorf("subcommand %s failed to parse flags: docker=%v, detach=%v", sub, opts.DockerMode, opts.DetachMode)
			}
		}
	})

	t.Run("combined space-separated flags in single argument string", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"-docker --all-traffic -d -v"})
		if err != nil {
			t.Fatalf("unexpected error parsing combined flags: %v", err)
		}
		if !opts.DockerMode || !opts.AllTraffic || !opts.DetachMode || !opts.Verbose {
			t.Errorf("combined flags not set properly: docker=%v, allTraffic=%v, detach=%v, verbose=%v",
				opts.DockerMode, opts.AllTraffic, opts.DetachMode, opts.Verbose)
		}
	})

	t.Run("positional arguments preserved after flags", func(t *testing.T) {
		opts, err := ParsePushOptions([]string{"--docker", "/var/log/pos1.log", "/var/log/pos2.log"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(opts.PositionalArgs, []string{"/var/log/pos1.log", "/var/log/pos2.log"}) {
			t.Errorf("expected positional args [/var/log/pos1.log /var/log/pos2.log], got %v", opts.PositionalArgs)
		}
	})
}

func TestShipperPushOptions_AllEnvironmentVariables(t *testing.T) {
	t.Run("RW_DASHBOARD_URL and fallback RW_URL", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "http://soc.primary:7890")
		t.Setenv("RW_URL", "http://soc.fallback:7890")
		opts, _ := ParsePushOptions([]string{})
		if opts.URL != "http://soc.primary:7890" {
			t.Errorf("expected primary RW_DASHBOARD_URL, got %s", opts.URL)
		}

		t.Setenv("RW_DASHBOARD_URL", "")
		optsFallback, _ := ParsePushOptions([]string{})
		if optsFallback.URL != "http://soc.fallback:7890" {
			t.Errorf("expected fallback RW_URL, got %s", optsFallback.URL)
		}
	})

	t.Run("RW_AGENT_KEY and fallback RW_KEY", func(t *testing.T) {
		t.Setenv("RW_AGENT_KEY", "rw_sec_primary")
		t.Setenv("RW_KEY", "rw_sec_fallback")
		opts, _ := ParsePushOptions([]string{})
		if opts.Key != "rw_sec_primary" {
			t.Errorf("expected primary RW_AGENT_KEY, got %s", opts.Key)
		}

		t.Setenv("RW_AGENT_KEY", "")
		optsFallback, _ := ParsePushOptions([]string{})
		if optsFallback.Key != "rw_sec_fallback" {
			t.Errorf("expected fallback RW_KEY, got %s", optsFallback.Key)
		}
	})

	t.Run("RW_CONFIG", func(t *testing.T) {
		t.Setenv("RW_CONFIG", "/custom/path/agent.json")
		opts, _ := ParsePushOptions([]string{})
		if opts.ConfigPath != "/custom/path/agent.json" {
			t.Errorf("expected RW_CONFIG=/custom/path/agent.json, got %s", opts.ConfigPath)
		}
	})

	t.Run("RW_DOCKER", func(t *testing.T) {
		for _, val := range []string{"1", "true", "True", "TRUE"} {
			t.Setenv("RW_DOCKER", val)
			opts, _ := ParsePushOptions([]string{})
			if !opts.DockerMode {
				t.Errorf("expected DockerMode=true for RW_DOCKER=%s", val)
			}
		}
	})

	t.Run("RW_LABEL", func(t *testing.T) {
		t.Setenv("RW_LABEL", "com.docker.stack=security")
		opts, _ := ParsePushOptions([]string{})
		if opts.CustomLabel != "com.docker.stack=security" {
			t.Errorf("expected RW_LABEL=com.docker.stack=security, got %s", opts.CustomLabel)
		}
	})

	t.Run("RW_TAIL", func(t *testing.T) {
		t.Setenv("RW_TAIL", "250")
		opts, _ := ParsePushOptions([]string{})
		if opts.TailLines != "250" {
			t.Errorf("expected RW_TAIL=250, got %s", opts.TailLines)
		}
	})

	t.Run("RW_BATCH_SIZE", func(t *testing.T) {
		t.Setenv("RW_BATCH_SIZE", "120")
		opts, _ := ParsePushOptions([]string{})
		if opts.BatchSize != 120 {
			t.Errorf("expected RW_BATCH_SIZE=120, got %d", opts.BatchSize)
		}

		// Invalid values ignored and default preserved
		t.Setenv("RW_BATCH_SIZE", "invalid-number")
		optsDefault, _ := ParsePushOptions([]string{})
		if optsDefault.BatchSize != 50 {
			t.Errorf("expected default BatchSize=50 on invalid string, got %d", optsDefault.BatchSize)
		}
	})

	t.Run("RW_FLUSH_INTERVAL", func(t *testing.T) {
		t.Setenv("RW_FLUSH_INTERVAL", "3500ms")
		opts, _ := ParsePushOptions([]string{})
		if opts.FlushInterval != 3500*time.Millisecond {
			t.Errorf("expected RW_FLUSH_INTERVAL=3500ms, got %v", opts.FlushInterval)
		}

		t.Setenv("RW_FLUSH_INTERVAL", "bad-duration")
		optsDefault, _ := ParsePushOptions([]string{})
		if optsDefault.FlushInterval != 1*time.Second {
			t.Errorf("expected default FlushInterval=1s on invalid duration, got %v", optsDefault.FlushInterval)
		}
	})

	t.Run("RW_QUEUE_SIZE", func(t *testing.T) {
		t.Setenv("RW_QUEUE_SIZE", "50000")
		opts, _ := ParsePushOptions([]string{})
		if opts.MaxQueueSize != 50000 {
			t.Errorf("expected RW_QUEUE_SIZE=50000, got %d", opts.MaxQueueSize)
		}
	})

	t.Run("RW_DISCONNECT_TIMEOUT", func(t *testing.T) {
		t.Setenv("RW_DISCONNECT_TIMEOUT", "12m")
		opts, _ := ParsePushOptions([]string{})
		if opts.DisconnectTimeout != 12*time.Minute {
			t.Errorf("expected RW_DISCONNECT_TIMEOUT=12m, got %v", opts.DisconnectTimeout)
		}
	})

	t.Run("RW_PING_INTERVAL", func(t *testing.T) {
		t.Setenv("RW_PING_INTERVAL", "25s")
		opts, _ := ParsePushOptions([]string{})
		if opts.PingInterval != 25*time.Second {
			t.Errorf("expected RW_PING_INTERVAL=25s, got %v", opts.PingInterval)
		}
	})

	t.Run("RW_VERBOSE and RW_DEBUG fallback", func(t *testing.T) {
		t.Setenv("RW_VERBOSE", "1")
		opts1, _ := ParsePushOptions([]string{})
		if !opts1.Verbose {
			t.Errorf("expected Verbose=true for RW_VERBOSE=1")
		}

		t.Setenv("RW_VERBOSE", "")
		t.Setenv("RW_DEBUG", "true")
		opts2, _ := ParsePushOptions([]string{})
		if !opts2.Verbose {
			t.Errorf("expected Verbose=true for RW_DEBUG=true fallback")
		}
	})

	t.Run("RW_DETACH", func(t *testing.T) {
		for _, val := range []string{"1", "true", "True"} {
			t.Setenv("RW_DETACH", val)
			opts, _ := ParsePushOptions([]string{})
			if !opts.DetachMode {
				t.Errorf("expected DetachMode=true for RW_DETACH=%s", val)
			}
		}
	})

	t.Run("RW_STATUS, RW_STATUS_CODES, RW_INCLUDE_STATUS", func(t *testing.T) {
		t.Setenv("RW_STATUS", "400-599, 301")
		t.Setenv("RW_STATUS_CODES", "")
		t.Setenv("RW_INCLUDE_STATUS", "")
		opts1, _ := ParsePushOptions([]string{})
		if opts1.StatusCodesFlag != "400-599, 301" {
			t.Errorf("expected RW_STATUS=400-599, 301, got %s", opts1.StatusCodesFlag)
		}

		t.Setenv("RW_STATUS", "")
		t.Setenv("RW_STATUS_CODES", "4xx, 5xx")
		opts2, _ := ParsePushOptions([]string{})
		if opts2.StatusCodesFlag != "4xx, 5xx" {
			t.Errorf("expected RW_STATUS_CODES=4xx, 5xx, got %s", opts2.StatusCodesFlag)
		}

		t.Setenv("RW_STATUS_CODES", "")
		t.Setenv("RW_INCLUDE_STATUS", "301, 302")
		opts3, _ := ParsePushOptions([]string{})
		if opts3.StatusCodesFlag != "301, 302" {
			t.Errorf("expected RW_INCLUDE_STATUS=301, 302, got %s", opts3.StatusCodesFlag)
		}
	})

	t.Run("RW_INCLUDE_FAILED", func(t *testing.T) {
		t.Setenv("RW_INCLUDE_FAILED", "1")
		opts, _ := ParsePushOptions([]string{})
		if !opts.IncludeFailed || opts.StatusCodesFlag != "400-599" {
			t.Errorf("expected IncludeFailed=true and StatusCodes=400-599, got failed=%v, status=%s",
				opts.IncludeFailed, opts.StatusCodesFlag)
		}
	})

	t.Run("RW_ALL_TRAFFIC", func(t *testing.T) {
		for _, val := range []string{"1", "true", "TRUE"} {
			t.Setenv("RW_ALL_TRAFFIC", val)
			opts, _ := ParsePushOptions([]string{})
			if !opts.AllTraffic {
				t.Errorf("expected AllTraffic=true for RW_ALL_TRAFFIC=%s", val)
			}
		}
	})

	t.Run("RW_ALL_LOGS", func(t *testing.T) {
		for _, val := range []string{"1", "true", "TRUE"} {
			t.Setenv("RW_ALL_LOGS", val)
			opts, _ := ParsePushOptions([]string{})
			if !opts.AllLogs {
				t.Errorf("expected AllLogs=true for RW_ALL_LOGS=%s", val)
			}
		}
	})
}

func TestShipperPushOptions_FlagOverridesEnvironment(t *testing.T) {
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

	opts, err := ParsePushOptions(args)
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

func TestShipperRegisterOptions_AllFlagsAndEnvVars(t *testing.T) {
	t.Run("flags and aliases", func(t *testing.T) {
		opts1, err := ParseRegisterOptions([]string{
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
		opts2, err := ParseRegisterOptions([]string{
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

		opts, err := ParseRegisterOptions([]string{})
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
		optsFallback, _ := ParseRegisterOptions([]string{})
		if optsFallback.DashboardURL != "http://env-fallback:7890" || optsFallback.AgentToken != "rw_sec_fallback_key" {
			t.Errorf("expected fallback env vars: url=%s, key=%s", optsFallback.DashboardURL, optsFallback.AgentToken)
		}
	})

	t.Run("flags override environment variables", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_URL", "http://env-url:7890")
		t.Setenv("RW_AGENT_KEY", "rw_sec_env")
		opts, err := ParseRegisterOptions([]string{"-u", "http://cli-override:7890", "-k", "rw_sec_cli"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.DashboardURL != "http://cli-override:7890" || opts.AgentToken != "rw_sec_cli" {
			t.Errorf("expected CLI flags to override env: url=%s, token=%s", opts.DashboardURL, opts.AgentToken)
		}
	})
}
