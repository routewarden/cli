package logger

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"WARN", LevelWarn},
		{"warning", LevelWarn},
		{"error", LevelError},
		{"err", LevelError},
		{"off", LevelOff},
		{"silent", LevelOff},
		{"none", LevelOff},
		{"", LevelWarn}, // Default must be LevelWarn
		{"unknown_val", LevelWarn}, // Unknown input defaults to LevelWarn
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ParseLevel(tc.input)
			if got != tc.expected {
				t.Errorf("ParseLevel(%q) = %v; want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "debug"},
		{LevelInfo, "info"},
		{LevelWarn, "warn"},
		{LevelError, "error"},
		{LevelOff, "off"},
	}

	for _, tc := range tests {
		if tc.level.String() != tc.expected {
			t.Errorf("Level(%d).String() = %q; want %q", tc.level, tc.level.String(), tc.expected)
		}
	}
}

func TestLoggerOutputGating(t *testing.T) {
	var buf bytes.Buffer
	l := New(LevelWarn, &buf)

	l.Debug("should not appear")
	l.Info("should not appear")
	if buf.Len() > 0 {
		t.Errorf("expected no output for debug/info at warn level, got: %s", buf.String())
	}

	buf.Reset()
	l.Warn("test warning %d", 1)
	if !strings.Contains(buf.String(), "test warning 1") {
		t.Errorf("expected warning output, got: %s", buf.String())
	}

	buf.Reset()
	l.Error("test error")
	if !strings.Contains(buf.String(), "test error") {
		t.Errorf("expected error output, got: %s", buf.String())
	}
}
