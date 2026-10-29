package shipper

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AgentConfig represents the local client registration configuration.
type AgentConfig struct {
	DashboardURL    string `json:"dashboard_url"`
	AgentToken      string `json:"agent_token"`
	AgentID         string `json:"agent_id"`
	AgentName       string `json:"agent_name"`
	ServerPublicKey string `json:"server_public_key"`
	RegisteredAt    string `json:"registered_at"`
	StatusCodes     string `json:"status_codes,omitempty"`
	IncludeFailed   bool   `json:"include_failed,omitempty"`
	AllTraffic      bool   `json:"all_traffic,omitempty"`
	AllLogs         bool   `json:"all_logs,omitempty"`
}

func DefaultAgentConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".routewarden/agent.json"
	}
	return filepath.Join(home, ".routewarden", "agent.json")
}

func LoadAgentConfig(path string) (*AgentConfig, error) {
	if path == "" {
		path = DefaultAgentConfigPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func SaveAgentConfig(path string, cfg *AgentConfig) error {
	if path == "" {
		path = DefaultAgentConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// RegisterAgent connects to dashboardURL with agentToken, retrieves the server public key, and saves configuration.
func RegisterAgent(dashboardURL, agentToken, configPath string, client *http.Client) (*AgentConfig, error) {
	if dashboardURL == "" || agentToken == "" {
		return nil, fmt.Errorf("both dashboard URL and agent key are required")
	}

	cleanURL := strings.TrimRight(dashboardURL, "/")
	regEndpoint := cleanURL + "/api/v1/register"

	req, err := http.NewRequest(http.MethodPost, regEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create registration request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+agentToken)

	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &errResp)
		msg := errResp.Error
		if msg == "" {
			msg = string(body)
		}
		return nil, fmt.Errorf("server rejected registration (HTTP %d): %s", resp.StatusCode, msg)
	}

	var regResult struct {
		Status          string `json:"status"`
		AgentID         string `json:"agent_id"`
		AgentName       string `json:"agent_name"`
		ServerPublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &regResult); err != nil {
		return nil, fmt.Errorf("invalid response from server: %w", err)
	}

	cfg := &AgentConfig{
		DashboardURL:    cleanURL,
		AgentToken:      agentToken,
		AgentID:         regResult.AgentID,
		AgentName:       regResult.AgentName,
		ServerPublicKey: regResult.ServerPublicKey,
		RegisteredAt:    time.Now().UTC().Format(time.RFC3339),
	}

	destPath := configPath
	if destPath == "" {
		destPath = DefaultAgentConfigPath()
	}

	if err := SaveAgentConfig(destPath, cfg); err != nil {
		return nil, fmt.Errorf("save agent configuration: %w", err)
	}
	return cfg, nil
}

// RegisterOptions represents parsed flags and environment variables for register.
type RegisterOptions struct {
	DashboardURL    string
	AgentToken      string
	ConfigPath      string
	StatusCodesFlag string
	IncludeFailed   bool
	AllTraffic      bool
	AllLogs         bool
	PositionalArgs  []string
}

// ParseRegisterOptions parses command-line flags and environment variables for the register command.
func ParseRegisterOptions(args []string) (*RegisterOptions, error) {
	opts := &RegisterOptions{}

	if envURL := os.Getenv("RW_DASHBOARD_URL"); envURL != "" {
		opts.DashboardURL = envURL
	} else if envURL := os.Getenv("RW_URL"); envURL != "" {
		opts.DashboardURL = envURL
	}
	if envKey := os.Getenv("RW_AGENT_KEY"); envKey != "" {
		opts.AgentToken = envKey
	} else if envKey := os.Getenv("RW_KEY"); envKey != "" {
		opts.AgentToken = envKey
	}
	if env := os.Getenv("RW_CONFIG"); env != "" {
		opts.ConfigPath = env
	}
	if env := os.Getenv("RW_STATUS"); env != "" {
		opts.StatusCodesFlag = env
	} else if env := os.Getenv("RW_STATUS_CODES"); env != "" {
		opts.StatusCodesFlag = env
	} else if env := os.Getenv("RW_INCLUDE_STATUS"); env != "" {
		opts.StatusCodesFlag = env
	}
	if env := os.Getenv("RW_INCLUDE_FAILED"); env == "1" || strings.EqualFold(env, "true") {
		opts.IncludeFailed = true
		if opts.StatusCodesFlag == "" {
			opts.StatusCodesFlag = "400-599"
		}
	}
	if env := os.Getenv("RW_ALL_TRAFFIC"); env == "1" || strings.EqualFold(env, "true") {
		opts.AllTraffic = true
	}
	if env := os.Getenv("RW_ALL_LOGS"); env == "1" || strings.EqualFold(env, "true") {
		opts.AllLogs = true
	}

	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	fs.StringVar(&opts.DashboardURL, "url", opts.DashboardURL, "RouteWarden Central Dashboard URL (e.g. http://dashboard.internal:7890)")
	fs.StringVar(&opts.DashboardURL, "u", opts.DashboardURL, "Alias for --url")
	fs.StringVar(&opts.AgentToken, "key", opts.AgentToken, "Remote agent authentication key (rw_sec_...)")
	fs.StringVar(&opts.AgentToken, "k", opts.AgentToken, "Alias for --key")
	fs.StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "Custom path to store agent configuration (default: ~/.routewarden/agent.json)")
	fs.StringVar(&opts.StatusCodesFlag, "status", opts.StatusCodesFlag, "Forward HTTP requests matching status codes or ranges (e.g. '400-599, 301', '4xx, 5xx')")
	fs.StringVar(&opts.StatusCodesFlag, "s", opts.StatusCodesFlag, "Alias for --status")
	fs.StringVar(&opts.StatusCodesFlag, "status-codes", opts.StatusCodesFlag, "Alias for --status")
	fs.StringVar(&opts.StatusCodesFlag, "include-status", opts.StatusCodesFlag, "Alias for --status")
	fs.BoolVar(&opts.IncludeFailed, "include-failed", opts.IncludeFailed, "Legacy alias: forward all failed HTTP requests (status >= 400, equivalent to --status 400-599)")
	fs.BoolVar(&opts.IncludeFailed, "F", opts.IncludeFailed, "Alias for --include-failed")
	fs.BoolVar(&opts.AllTraffic, "all-traffic", opts.AllTraffic, "Always ship all HTTP access traffic (including 200 OK)")
	fs.BoolVar(&opts.AllLogs, "all-logs", opts.AllLogs, "Always ship all raw container lines without filtering")

	if err := ParseFlagsLenient(fs, args); err != nil {
		return nil, err
	}
	if opts.IncludeFailed && opts.StatusCodesFlag == "" {
		opts.StatusCodesFlag = "400-599"
	}
	opts.PositionalArgs = fs.Args()

	return opts, nil
}

func HandleRegister(args []string) {
	opts, err := ParseRegisterOptions(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	dashboardURL := &opts.DashboardURL
	agentToken := &opts.AgentToken
	configPath := &opts.ConfigPath
	statusCodesFlag := &opts.StatusCodesFlag
	includeFailed := &opts.IncludeFailed
	allTraffic := &opts.AllTraffic
	allLogs := &opts.AllLogs

	if *dashboardURL == "" || *agentToken == "" {
		fmt.Fprintln(os.Stderr, "Error: Both --url and --key are required for registration (or set RW_DASHBOARD_URL and RW_AGENT_KEY).")
		fmt.Fprintln(os.Stderr, "\nUsage:")
		fmt.Fprintln(os.Stderr, "  rwarden register --url http://<dashboard-ip>:7890 --key <agent-token>")
		os.Exit(1)
	}

	fmt.Printf("⏳ Connecting to RouteWarden Central Dashboard at %s...\n", *dashboardURL)

	cfg, err := RegisterAgent(*dashboardURL, *agentToken, *configPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Registration failed: %v\n", err)
		os.Exit(1)
	}

	destPath := *configPath
	if destPath == "" {
		destPath = DefaultAgentConfigPath()
	}

	if *statusCodesFlag == "" && *includeFailed {
		*statusCodesFlag = "400-599"
	}
	if *statusCodesFlag != "" {
		cfg.StatusCodes = *statusCodesFlag
		cfg.IncludeFailed = true
	}
	if *includeFailed {
		cfg.IncludeFailed = true
	}
	if *allTraffic || os.Getenv("RW_ALL_TRAFFIC") == "1" || strings.EqualFold(os.Getenv("RW_ALL_TRAFFIC"), "true") {
		cfg.AllTraffic = true
	}
	if *allLogs || os.Getenv("RW_ALL_LOGS") == "1" || strings.EqualFold(os.Getenv("RW_ALL_LOGS"), "true") {
		cfg.AllLogs = true
	}
	if *statusCodesFlag != "" || *includeFailed || cfg.AllTraffic || cfg.AllLogs {
		_ = SaveAgentConfig(destPath, cfg)
	}

	fmt.Println("✅ Successfully registered with RouteWarden Central Dashboard!")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("  Dashboard URL:     %s\n", cfg.DashboardURL)
	fmt.Printf("  Agent Name:        %s\n", cfg.AgentName)
	fmt.Printf("  Agent ID:          %s\n", cfg.AgentID)
	if len(cfg.ServerPublicKey) > 20 {
		fmt.Printf("  Server Public Key: %s...\n", cfg.ServerPublicKey[:20])
	}
	if cfg.AllLogs {
		fmt.Println("  Telemetry Filter:  All raw container lines (--all-logs)")
	} else if cfg.AllTraffic {
		fmt.Println("  Telemetry Filter:  All HTTP access traffic (--all-traffic)")
	} else if cfg.StatusCodes != "" {
		fmt.Printf("  Telemetry Filter:  Security events + HTTP status [%s]\n", cfg.StatusCodes)
	} else if cfg.IncludeFailed {
		fmt.Println("  Telemetry Filter:  Security events + failed HTTP calls (--include-failed)")
	}
	fmt.Printf("  Config Saved:      %s\n", destPath)
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("🚀 You are ready to stream! Start pushing logs with:")
	fmt.Println("   rwarden push")
	fmt.Println("   rwarden push --docker")
	fmt.Println("   rwarden push --file /var/log/nginx/access.log")
}
