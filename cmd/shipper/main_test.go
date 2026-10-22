package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestShipper_PrintUsage(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printUsage()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "RouteWarden Shipper") {
		t.Errorf("expected header in shipper printUsage, got: %s", output)
	}
	if !strings.Contains(output, "push") || !strings.Contains(output, "register") {
		t.Errorf("expected commands push, register in usage, got: %s", output)
	}
}
