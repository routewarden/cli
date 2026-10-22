package core

import (
	"github.com/routewarden/cli/proxy/logger"
)

// Re-export logger types so the rest of the core package can use them
// without having to import the logger package directly.

// Level is an alias for logger.Level.
type Level = logger.Level

const (
	LevelDebug = logger.LevelDebug
	LevelInfo  = logger.LevelInfo
	LevelWarn  = logger.LevelWarn
	LevelError = logger.LevelError
	LevelOff   = logger.LevelOff
)

// ParseLevel converts a string to a Level (case-insensitive).
// Accepts: debug, info, warn, warning, error, err, off, none, silent.
// Defaults to LevelWarn on unrecognised input or empty string.
var ParseLevel = logger.ParseLevel

// Logger is a levelled operational logger.
type Logger = logger.Logger

// NewLogger creates a Logger at the given level writing to out.
var NewLogger = logger.New

// SetDefaultLogger replaces the package-level logger. Called by NewDaemon once
// the config is loaded.
func SetDefaultLogger(l *Logger) {
	logger.SetDefault(l)
}

// DefaultLogger returns the current package-level logger.
func DefaultLogger() *Logger {
	return logger.Default()
}
