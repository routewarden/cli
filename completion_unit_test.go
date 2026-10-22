package main

import (
	"strings"
	"testing"
)

func TestShellCompletions_Unit(t *testing.T) {
	requiredCommands := []string{
		"test",
		"validate",
		"generate",
		"audit",
		"diff",
		"sandbox",
		"dashboard",
		"up",
		"keys",
		"register",
		"push",
		"tcp",
		"monitor",
		"tui",
		"completion",
		"man",
		"cleanup",
		"schema",
		"version",
	}

	t.Run("bash completion", func(t *testing.T) {
		bash := generateBashCompletion()
		if len(bash) < 100 {
			t.Fatalf("bash completion is too short")
		}
		for _, cmd := range requiredCommands {
			if !strings.Contains(bash, cmd) {
				t.Errorf("bash completion missing command: %s", cmd)
			}
		}
		if strings.Contains(strings.ToLower(bash), "goaccess") {
			t.Errorf("bash completion should not contain goaccess reference")
		}
	})

	t.Run("zsh completion", func(t *testing.T) {
		zsh := generateZshCompletion()
		if len(zsh) < 100 {
			t.Fatalf("zsh completion is too short")
		}
		for _, cmd := range requiredCommands {
			if !strings.Contains(zsh, cmd) {
				t.Errorf("zsh completion missing command: %s", cmd)
			}
		}
		if strings.Contains(strings.ToLower(zsh), "goaccess") {
			t.Errorf("zsh completion should not contain goaccess reference")
		}
		if !strings.Contains(zsh, "SOC dashboard HTTP port") {
			t.Errorf("zsh completion should reference SOC dashboard HTTP port")
		}
	})

	t.Run("fish completion", func(t *testing.T) {
		fish := generateFishCompletion()
		if len(fish) < 100 {
			t.Fatalf("fish completion is too short")
		}
		for _, cmd := range requiredCommands {
			if !strings.Contains(fish, cmd) {
				t.Errorf("fish completion missing command: %s", cmd)
			}
		}
		if strings.Contains(strings.ToLower(fish), "goaccess") {
			t.Errorf("fish completion should not contain goaccess reference")
		}
		if !strings.Contains(fish, "Launch real-time SOC security dashboard") {
			t.Errorf("fish completion should reference real-time SOC security dashboard")
		}
	})

	t.Run("powershell completion", func(t *testing.T) {
		ps := generatePowerShellCompletion()
		if len(ps) < 100 {
			t.Fatalf("powershell completion is too short")
		}
		for _, cmd := range requiredCommands {
			if !strings.Contains(ps, cmd) {
				t.Errorf("powershell completion missing command: %s", cmd)
			}
		}
		if strings.Contains(strings.ToLower(ps), "goaccess") {
			t.Errorf("powershell completion should not contain goaccess reference")
		}
	})
}
