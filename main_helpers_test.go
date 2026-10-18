package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestStringSlice(t *testing.T) {
	var ss stringSlice
	if ss.String() != "" {
		t.Errorf("expected empty string for empty slice, got %q", ss.String())
	}

	if err := ss.Set("header-1"); err != nil {
		t.Fatalf("unexpected error from Set: %v", err)
	}
	if err := ss.Set("header-2"); err != nil {
		t.Fatalf("unexpected error from Set: %v", err)
	}

	if ss.String() != "header-1, header-2" {
		t.Errorf("expected 'header-1, header-2', got %q", ss.String())
	}
	if len(ss) != 2 || ss[0] != "header-1" || ss[1] != "header-2" {
		t.Errorf("slice elements mismatch: %v", ss)
	}
}

func TestPrintUsage(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printUsage()

	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "RouteWarden CLI") {
		t.Errorf("expected usage title in output: %s", out)
	}
	if !strings.Contains(out, "Commands:") {
		t.Errorf("expected commands section in output: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "goaccess") {
		t.Errorf("usage output must not contain goaccess")
	}
}
