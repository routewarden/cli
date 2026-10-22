package core

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// LogWriter writes SecurityEvents as single-line JSON entries (JSONL)
// to stdout (for Docker container logs and RouteWarden dashboard streaming)
// as well as the configured log file (for persistent logging and CrowdSec).
//
// Events are filtered by level before being written:
//   - debug  → all events (allowed, blocked, auth_failure, …)
//   - info   → all events (default)
//   - warn   → blocked and auth_failure events only
//   - error  → blocked events only
//   - off    → no events written
type LogWriter struct {
	mu     sync.Mutex
	file   *os.File
	path   string
	stdout io.Writer
	level  Level
}

// NewLogWriter opens or creates the target log file.
// By default the writer emits all events (LevelInfo).
func NewLogWriter(path string) (*LogWriter, error) {
	if path == "" {
		return &LogWriter{stdout: os.Stdout, level: LevelInfo}, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &LogWriter{stdout: os.Stdout, level: LevelInfo}, fmt.Errorf("creating log directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return &LogWriter{stdout: os.Stdout, level: LevelInfo}, fmt.Errorf("opening log file %s: %w", path, err)
	}

	return &LogWriter{file: f, path: path, stdout: os.Stdout, level: LevelInfo}, nil
}

// SetLevel configures the minimum severity required for a SecurityEvent to be
// written. Events below this threshold are silently dropped.
//
//   - LevelDebug / LevelInfo → all events (allowed, blocked, auth_failure)
//   - LevelWarn              → blocked and auth_failure events only
//   - LevelError             → blocked events only
//   - LevelOff               → nothing written
func (w *LogWriter) SetLevel(level Level) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.level = level
}

// SetOutput redirects the stdout stream (useful for testing).
func (w *LogWriter) SetOutput(out io.Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stdout = out
}

// shouldWrite returns true if an event with the given action should be written
// at the current log level.
//
// Mapping from SecurityEvent.Action → minimum level to suppress:
//
//	"allowed"      suppressed at LevelWarn and above
//	"auth_failure" suppressed at LevelError and above
//	"blocked"      always written (suppressed only at LevelOff)
func (w *LogWriter) shouldWrite(action string) bool {
	if w.level >= LevelOff {
		return false
	}
	switch strings.ToLower(action) {
	case "allowed":
		return w.level <= LevelInfo
	case "auth_failure":
		return w.level <= LevelWarn
	default: // "blocked", "banned", and any future action types
		// Use < LevelOff (not <= LevelError) so this remains correct if new
		// levels are ever inserted between LevelError and LevelOff.
		return w.level < LevelOff
	}
}

// Write appends an event as JSON line to stdout and file if its action passes
// the configured log level filter.
func (w *LogWriter) Write(ev SecurityEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.shouldWrite(ev.Action) {
		return nil
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Always output to stdout so Docker captures container logs for 'docker logs'
	// and the RouteWarden dashboard can tail security events.
	out := w.stdout
	if out == nil {
		out = os.Stdout
	}
	_, _ = out.Write(data)

	if w.file != nil {
		_, err = w.file.Write(data)
		return err
	}
	return nil
}

// Close closes the underlying file handle.
func (w *LogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}
