package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestResolveFileList(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "access_1.log")
	f2 := filepath.Join(tmpDir, "access_2.log")
	f3 := filepath.Join(tmpDir, "error.log")

	_ = os.WriteFile(f1, []byte("log1"), 0644)
	_ = os.WriteFile(f2, []byte("log2"), 0644)
	_ = os.WriteFile(f3, []byte("log3"), 0644)

	t.Run("direct paths and comma separation", func(t *testing.T) {
		flags := []string{f1 + "," + f2}
		posArgs := []string{f3, f1} // f1 is duplicate

		res := resolveFileList(flags, posArgs)
		if len(res) != 3 {
			t.Fatalf("expected 3 unique files, got %d: %v", len(res), res)
		}

		expected := map[string]bool{f1: true, f2: true, f3: true}
		for _, r := range res {
			if !expected[r] {
				t.Errorf("unexpected file in results: %s", r)
			}
		}
	})

	t.Run("glob expansion", func(t *testing.T) {
		pattern := filepath.Join(tmpDir, "access_*.log")
		res := resolveFileList([]string{pattern}, nil)
		if len(res) != 2 {
			t.Fatalf("expected 2 matched glob files, got %d: %v", len(res), res)
		}
		sort.Strings(res)
		expected := []string{f1, f2}
		sort.Strings(expected)
		if !reflect.DeepEqual(res, expected) {
			t.Errorf("expected %v, got %v", expected, res)
		}
	})

	t.Run("empty and whitespace handling", func(t *testing.T) {
		res := resolveFileList([]string{"", "   ", ","}, []string{"", "  "})
		if len(res) != 0 {
			t.Errorf("expected 0 files for empty inputs, got %d: %v", len(res), res)
		}
	})
}

func TestResolveContainerList(t *testing.T) {
	t.Run("comma separated with duplicates and whitespace", func(t *testing.T) {
		flags := []string{"traefik, caddy", "nginx", "traefik", "  ,  "}
		res := resolveContainerList(flags)
		if len(res) != 3 {
			t.Fatalf("expected 3 unique containers, got %d: %v", len(res), res)
		}
		expected := []string{"traefik", "caddy", "nginx"}
		if !reflect.DeepEqual(res, expected) {
			t.Errorf("expected %v, got %v", expected, res)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		res := resolveContainerList(nil)
		if len(res) != 0 {
			t.Errorf("expected 0 containers, got %v", res)
		}
	})
}
