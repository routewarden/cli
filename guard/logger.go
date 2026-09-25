package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LogWriter writes GuardEvents as JSON lines to a designated log file.
// This log format can be directly ingested by CrowdSec, Vector, Fluentbit, or Filebeat.
type LogWriter struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	encoder *json.Encoder
}

// NewLogWriter creates a LogWriter pointing to the destination path.
// If path is empty, it returns a no-op writer.
func NewLogWriter(path string) (*LogWriter, error) {
	if path == "" {
		return &LogWriter{}, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating log directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening log file %s: %w", path, err)
	}

	return &LogWriter{
		path:    path,
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// WriteEvent serializes and writes a single event to the file.
func (w *LogWriter) WriteEvent(ev GuardEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.encoder == nil {
		return nil
	}
	return w.encoder.Encode(ev)
}

// Close closes the underlying file handle.
func (w *LogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		w.encoder = nil
		return err
	}
	return nil
}
