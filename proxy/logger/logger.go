// Package logger provides a levelled operational logger for the tcp-warden daemon.
// It is a leaf package (no imports from within tcp-warden) so it can be safely
// imported by both core and plugins without creating an import cycle.
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"
)

// Level represents a log verbosity level.
// The numeric value is used for comparison: a message is emitted only when
// its level is >= the configured minimum level.
type Level int

const (
	LevelDebug Level = iota // most verbose — connection trace, plugin detail
	LevelInfo               // verbose — startup banners, plugin status, API listeners
	LevelWarn               // default — warnings only, auth failures & blocked events
	LevelError              // errors only — fatal or operational failures
	LevelOff                // suppress all operational log output
)

// ParseLevel converts a string (from config or CLI) to a Level.
// Accepted values (case-insensitive): debug, info, warn/warning, error, off.
// Defaults to LevelWarn on unrecognised input or empty string.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning", "":
		return LevelWarn
	case "error", "err":
		return LevelError
	case "off", "none", "silent":
		return LevelOff
	default:
		return LevelWarn
	}
}

// String returns the canonical name of the level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case LevelOff:
		return "off"
	default:
		return "info"
	}
}

// Logger is a levelled operational logger used throughout the daemon.
// It is distinct from core.LogWriter, which handles structured SecurityEvent JSONL.
// Logger handles human-readable startup/operational messages.
type Logger struct {
	level  Level
	logger *log.Logger
}

// New creates a Logger at the given level writing to out.
// Pass os.Stderr (or os.Stdout) for normal use; pass io.Discard in tests.
func New(level Level, out io.Writer) *Logger {
	if out == nil {
		out = os.Stderr
	}
	return &Logger{
		level:  level,
		logger: log.New(out, "", log.LstdFlags),
	}
}

// SetLevel updates the minimum log level.
func (l *Logger) SetLevel(level Level) {
	l.level = level
}

// Level returns the current minimum log level.
func (l *Logger) Level() Level {
	return l.level
}

// Debug emits a message at DEBUG level.
func (l *Logger) Debug(format string, args ...any) {
	if l.level <= LevelDebug {
		_ = l.logger.Output(2, fmt.Sprintf("[DEBUG] "+format, args...))
	}
}

// Info emits a message at INFO level.
func (l *Logger) Info(format string, args ...any) {
	if l.level <= LevelInfo {
		_ = l.logger.Output(2, fmt.Sprintf(format, args...))
	}
}

// Warn emits a message at WARN level.
func (l *Logger) Warn(format string, args ...any) {
	if l.level <= LevelWarn {
		_ = l.logger.Output(2, fmt.Sprintf("⚠️  "+format, args...))
	}
}

// Error emits a message at ERROR level.
func (l *Logger) Error(format string, args ...any) {
	if l.level <= LevelError {
		_ = l.logger.Output(2, fmt.Sprintf("❌ "+format, args...))
	}
}

// globalPtr holds a *Logger via atomic pointer so it can be replaced at startup
// without a mutex in the hot path.
var globalPtr atomic.Pointer[Logger]

func init() {
	// Safe default: INFO on stderr so messages are never silently lost before
	// the config is loaded.
	globalPtr.Store(New(LevelInfo, os.Stderr))
}

// SetDefault replaces the package-level logger. Called once by the daemon after
// the config is loaded. All packages that import logger will pick up the new
// value on their next call.
func SetDefault(l *Logger) {
	if l != nil {
		globalPtr.Store(l)
	}
}

// Default returns the current package-level logger.
func Default() *Logger {
	return globalPtr.Load()
}

// ensure Logger pointer size matches uintptr for atomic use (compile-time check).
var _ = (*unsafe.Pointer)(nil)
