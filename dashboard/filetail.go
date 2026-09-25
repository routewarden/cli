package dashboard

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileTailer tails one or more log files on disk and pushes parsed
// RouteWarden security_event lines into the ring buffer and WebSocket hub.
// It handles log rotation: if the file is renamed/truncated fsnotify detects
// the change and the tailer re-opens the file from the start.
//
// Note: We implement a simple polling-based tail to keep the dependency list
// minimal (no fsnotify import needed for v1.0). Polling every 250 ms is
// adequate for a local dashboard and avoids the cgo/inotify complexity.
type FileTailer struct {
	patterns []string // glob patterns, e.g. ["/var/log/routewarden/*.log"]
	buf      *RingBuffer
	hub      *Hub

	mu      sync.Mutex
	sources map[string]*Source // file path → Source
}

// NewFileTailer creates a new FileTailer for the given glob patterns.
func NewFileTailer(patterns []string, buf *RingBuffer, hub *Hub) *FileTailer {
	return &FileTailer{
		patterns: patterns,
		buf:      buf,
		hub:      hub,
		sources:  make(map[string]*Source),
	}
}

// Run starts tailing all matched files. It re-evaluates globs every 5 s to
// pick up newly created log files. Blocks until ctx is done.
func (f *FileTailer) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	f.discoverAndTail(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.discoverAndTail(ctx)
		}
	}
}

func (f *FileTailer) discoverAndTail(ctx context.Context) {
	for _, pattern := range f.patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range matches {
			f.mu.Lock()
			if _, exists := f.sources[path]; exists {
				f.mu.Unlock()
				continue
			}
			src := &Source{
				ID:     hashPath(path),
				Name:   filepath.Base(path),
				Kind:   "file",
				Plugin: "unknown",
				Status: "live",
				Details: path,
			}
			f.sources[path] = src
			f.hub.BroadcastSources(f.sourcesLocked())
			f.mu.Unlock()

			go f.tailFile(ctx, path, src)
		}
	}
}

// tailFile tails a single file. It seeks to EOF on first open (to avoid
// replaying old events on restart) then blocks reading new lines.
// On rename/truncate it re-opens the file.
func (f *FileTailer) tailFile(ctx context.Context, path string, src *Source) {
	defer func() {
		f.mu.Lock()
		if s, ok := f.sources[path]; ok {
			s.Status = "stopped"
			f.hub.BroadcastSources(f.sourcesLocked())
		}
		f.mu.Unlock()
	}()

	var file *os.File
	var offset int64
	var inode uint64
	firstOpen := true

	openFile := func() {
		if file != nil {
			_ = file.Close()
		}
		var err error
		file, err = os.Open(path)
		if err != nil {
			file = nil
			return
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			file = nil
			return
		}
		inode = fileInode(info)

		if firstOpen {
			firstOpen = false
			// Load recent history on first startup so the dashboard is immediately populated.
			// If file is <= 2MB, start from byte 0.
			// If larger, seek to the last 2MB to keep startup fast and memory bounded.
			const maxInitialTail = 2 * 1024 * 1024
			if info.Size() > maxInitialTail {
				_, _ = file.Seek(-maxInitialTail, io.SeekEnd)
				// Discard any partial line
				scanner := bufio.NewScanner(file)
				if scanner.Scan() {
					offset, _ = file.Seek(0, io.SeekCurrent)
				}
			} else {
				offset = 0
			}
		} else {
			offset = 0
		}
	}

	openFile()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if file != nil {
				_ = file.Close()
			}
			return
		case <-ticker.C:
			if file == nil {
				openFile()
				if file == nil {
					continue
				}
			}

			// Detect rotation: inode changed or file shrank
			info, err := os.Stat(path)
			if err != nil {
				openFile()
				continue
			}
			if fileInode(info) != inode || info.Size() < offset {
				// File rotated — reopen from start
				openFile()
				if file == nil {
					continue
				}
				offset = 0
			}

			// Read new lines since last offset.
			// Use a 256 KB buffer per line — large enough for any RouteWarden
			// JSON event, even with large custom response body payloads.
			_, _ = file.Seek(offset, io.SeekStart)
			scanner := bufio.NewScanner(file)
			const maxLineBuf = 1 << 20 // 1 MB hard ceiling
			scanBuf := make([]byte, 64*1024)
			scanner.Buffer(scanBuf, maxLineBuf)

			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if e, ok := parseSecurityEventLine(line, src.Name, src.ID, src.Plugin); ok {
					// Detect plugin from first event
					if src.Plugin == "unknown" && e.Plugin != "" {
						f.mu.Lock()
						src.Plugin = e.Plugin
						f.mu.Unlock()
					}
					e = EnrichGeoIP(e)
					f.buf.Push(e)
					f.hub.Broadcast(e)
				}
			}

			// Always check scanner.Err() after the loop.
			// Scan() returns false for both EOF (err == nil, normal) and real
			// errors. Ignoring the error causes silent data loss or a stuck
			// offset when a line exceeds the scanner buffer.
			if err := scanner.Err(); err != nil {
				// Reset the file handle so the next tick reopens from a clean
				// state rather than getting stuck at a broken byte offset.
				_ = file.Close()
				file = nil
				continue
			}

			newOffset, _ := file.Seek(0, io.SeekCurrent)
			offset = newOffset

		}
	}
}

// ClearStopped removes all sources that are in "stopped" or "error" state.
func (f *FileTailer) ClearStopped() []Source {
	f.mu.Lock()
	defer f.mu.Unlock()

	for path, s := range f.sources {
		if s.Status == "stopped" || s.Status == "error" {
			delete(f.sources, path)
		}
	}
	sources := f.sourcesLocked()
	f.hub.BroadcastSources(sources)
	return sources
}

// SourceList returns a thread-safe copy of all file sources.
func (f *FileTailer) SourceList() []Source {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sourcesLocked()
}

func (f *FileTailer) sourcesLocked() []Source {
	out := make([]Source, 0, len(f.sources))
	for _, s := range f.sources {
		out = append(out, *s)
	}
	return out
}

// hashPath creates a short stable ID from a file path.
func hashPath(path string) string {
	h := uint32(2166136261)
	for _, b := range []byte(path) {
		h ^= uint32(b)
		h *= 16777619
	}
	return fmt.Sprintf("f%08x", h)
}

