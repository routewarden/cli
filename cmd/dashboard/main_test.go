package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestDashboard_PrintUsage(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printUsage()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "RouteWarden Dashboard") {
		t.Errorf("expected header in dashboard printUsage, got: %s", output)
	}
	if !strings.Contains(output, "up") || !strings.Contains(output, "export") || !strings.Contains(output, "keys") {
		t.Errorf("expected commands up, export, keys in usage, got: %s", output)
	}
}
