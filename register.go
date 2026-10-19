package main

import (
	"encoding/json"
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
}

func defaultAgentConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".routewarden/agent.json"
	}
	return filepath.Join(home, ".routewarden", "agent.json")
}

func loadAgentConfig(path string) (*AgentConfig, error) {
	if path == "" {
		path = defaultAgentConfigPath()
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

func saveAgentConfig(path string, cfg *AgentConfig) error {
	if path == "" {
		path = defaultAgentConfigPath()
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
		destPath = defaultAgentConfigPath()
	}

	if err := saveAgentConfig(destPath, cfg); err != nil {
		return nil, fmt.Errorf("save agent configuration: %w", err)
	}
	return cfg, nil
}

func handleRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	dashboardURL := fs.String("url", "", "RouteWarden Central Dashboard URL (e.g. http://dashboard.internal:7890)")
	fs.StringVar(dashboardURL, "u", "", "Alias for --url")
	agentToken := fs.String("key", "", "Remote agent authentication key (rw_sec_...)")
	fs.StringVar(agentToken, "k", "", "Alias for --key")
	configPath := fs.String("config", "", "Custom path to store agent configuration (default: ~/.routewarden/agent.json)")
	_ = parseFlagsLenient(fs, args)

	if *dashboardURL == "" {
		if envURL := os.Getenv("RW_DASHBOARD_URL"); envURL != "" {
			*dashboardURL = envURL
		} else if envURL := os.Getenv("RW_URL"); envURL != "" {
			*dashboardURL = envURL
		}
	}
	if *agentToken == "" {
		if envKey := os.Getenv("RW_AGENT_KEY"); envKey != "" {
			*agentToken = envKey
		} else if envKey := os.Getenv("RW_KEY"); envKey != "" {
			*agentToken = envKey
		}
	}

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
		destPath = defaultAgentConfigPath()
	}

	fmt.Println("✅ Successfully registered with RouteWarden Central Dashboard!")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("  Dashboard URL:     %s\n", cfg.DashboardURL)
	fmt.Printf("  Agent Name:        %s\n", cfg.AgentName)
	fmt.Printf("  Agent ID:          %s\n", cfg.AgentID)
	if len(cfg.ServerPublicKey) > 20 {
		fmt.Printf("  Server Public Key: %s...\n", cfg.ServerPublicKey[:20])
	}
	fmt.Printf("  Config Saved:      %s\n", destPath)
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("🚀 You are ready to stream! Start pushing logs with:")
	fmt.Println("   rwarden push")
	fmt.Println("   rwarden push --docker")
	fmt.Println("   rwarden push --file /var/log/nginx/access.log")
}
