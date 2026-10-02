package observability

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// DefaultDir returns the default directory where observability files are unpacked.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".routewarden/observability"
	}
	return filepath.Join(home, ".routewarden", "observability")
}

// FindDockerCompose checks whether 'docker compose' or 'docker-compose' is available.
func FindDockerCompose() ([]string, error) {
	// Try 'docker compose'
	cmd := exec.Command("docker", "compose", "version")
	if err := cmd.Run(); err == nil {
		return []string{"docker", "compose"}, nil
	}

	// Try legacy 'docker-compose'
	if _, err := exec.LookPath("docker-compose"); err == nil {
		return []string{"docker-compose"}, nil
	}

	return nil, fmt.Errorf("neither 'docker compose' nor 'docker-compose' was found in PATH. Please install Docker with Compose support: https://docs.docker.com/compose/install/")
}

// EnsureStackPrepared unpacks embedded stack configuration to dir if not already present.
func EnsureStackPrepared(dir string) error {
	composeFile := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(composeFile); err == nil {
		return nil
	}
	return Export(dir)
}

// Up starts the Grafana, Loki, and Alloy stack.
func Up(ctx context.Context, dir string, grafanaPort, lokiPort int, noOpen bool, extraEnv ...string) error {
	composeCmd, err := FindDockerCompose()
	if err != nil {
		return err
	}

	if dir == "" {
		dir = DefaultDir()
	}

	if err := EnsureStackPrepared(dir); err != nil {
		return fmt.Errorf("prepare observability assets: %w", err)
	}

	composeFile := filepath.Join(dir, "docker-compose.yml")

	fmt.Println("🚀 Launching RouteWarden Observability Stack (Grafana + Loki + Alloy)...")
	fmt.Printf("   Config Directory: %s\n", dir)

	args := append(composeCmd[1:], "-f", composeFile, "up", "-d")
	cmd := exec.CommandContext(ctx, composeCmd[0], args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GRAFANA_PORT="+strconv.Itoa(grafanaPort),
		"LOKI_PORT="+strconv.Itoa(lokiPort),
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose up: %w", err)
	}

	grafanaURL := fmt.Sprintf("http://localhost:%d", grafanaPort)
	lokiURL := fmt.Sprintf("http://localhost:%d", lokiPort)

	fmt.Println("\n✅ RouteWarden Observability Stack is running!")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("📊 Grafana Dashboard:  %s  (Anonymous / Admin: admin/admin)\n", grafanaURL)
	fmt.Printf("🗄️  Loki Log Engine:    %s\n", lokiURL)
	fmt.Printf("🔄 Grafana Alloy:       http://localhost:12345\n")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("💡 Tailing Docker containers: Traefik, Caddy, NGINX, and TCP Warden")
	fmt.Println("   Pre-provisioned dashboard: 'RouteWarden — Threat & Security Intelligence'")
	fmt.Println("\nRun 'rwarden dashboard down' to stop the stack.")

	if !noOpen {
		go func() {
			time.Sleep(1 * time.Second)
			openBrowser(grafanaURL)
		}()
	}

	return nil
}

// Down stops the running observability stack.
func Down(ctx context.Context, dir string) error {
	composeCmd, err := FindDockerCompose()
	if err != nil {
		return err
	}

	if dir == "" {
		dir = DefaultDir()
	}

	composeFile := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		return fmt.Errorf("no running observability stack found in %s", dir)
	}

	fmt.Println("🛑 Stopping RouteWarden Observability Stack...")
	args := append(composeCmd[1:], "-f", composeFile, "down")
	cmd := exec.CommandContext(ctx, composeCmd[0], args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose down: %w", err)
	}

	fmt.Println("✅ Observability stack stopped.")
	return nil
}

// Status checks the status of the observability stack containers.
func Status(ctx context.Context, dir string) error {
	composeCmd, err := FindDockerCompose()
	if err != nil {
		return err
	}

	if dir == "" {
		dir = DefaultDir()
	}

	composeFile := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		return fmt.Errorf("no observability stack configured in %s (run 'rwarden dashboard up' first)", dir)
	}

	args := append(composeCmd[1:], "-f", composeFile, "ps")
	cmd := exec.CommandContext(ctx, composeCmd[0], args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
