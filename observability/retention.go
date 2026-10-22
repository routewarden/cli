package observability

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RetentionPolicy defines data retention, maximum storage limits, and pruning frequency.
type RetentionPolicy struct {
	RetentionPeriod time.Duration // Cutoff age (e.g. 30 * 24 * time.Hour, 7 * 24 * time.Hour). 0 = unlimited
	MaxEvents       int           // Maximum rows to retain (e.g. 100000). 0 = unlimited
	PruneInterval   time.Duration // Frequency of automated background prune check (e.g. 1 * time.Hour)
	MaxLogSizeBytes int64         // Maximum access.log size before rotation (default: 50MB)
	AutoVacuum      bool          // Whether to run VACUUM when rows are pruned
}

// DefaultRetentionPolicy returns sensible defaults for SOC operations.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		RetentionPeriod: 30 * 24 * time.Hour, // 30 days
		MaxEvents:       100000,              // 100,000 events
		PruneInterval:   1 * time.Hour,       // Prune hourly
		MaxLogSizeBytes: 50 * 1024 * 1024,    // 50 MB
		AutoVacuum:      true,
	}
}

// RetentionStats contains live status and metrics about automated retention execution.
type RetentionStats struct {
	RetentionPeriod string    `json:"retention_period"`
	RetentionDays   int       `json:"retention_days"`
	MaxEvents       int       `json:"max_events"`
	PruneInterval   string    `json:"prune_interval"`
	LastPrunedAt    time.Time `json:"last_pruned_at"`
	LastPrunedCount int64     `json:"last_pruned_count"`
	TotalPruned     int64     `json:"total_pruned"`
}

// RetentionManager oversees automated data retention and database maintenance.
type RetentionManager struct {
	sqStore *SQLiteStore
	dir     string
	policy  RetentionPolicy
	mu      sync.RWMutex
	stats   RetentionStats
}

// ParseRetention parses retention strings like "30d", "7d", "24h", "14" (days), or "0" (unlimited).
func ParseRetention(str string) (time.Duration, error) {
	str = strings.TrimSpace(str)
	if str == "" {
		return 30 * 24 * time.Hour, nil
	}
	if str == "0" || strings.EqualFold(str, "unlimited") || strings.EqualFold(str, "none") {
		return 0, nil
	}
	if strings.HasSuffix(str, "d") || strings.HasSuffix(str, "D") {
		daysStr := str[:len(str)-1]
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid retention days %q: %w", str, err)
		}
		if days <= 0 {
			return 0, nil
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	if days, err := strconv.Atoi(str); err == nil {
		if days <= 0 {
			return 0, nil
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(str)
}

// ParseByteSize parses human-friendly sizes like "50MB", "100M", "1GB", "500K".
func ParseByteSize(str string) (int64, error) {
	str = strings.TrimSpace(strings.ToUpper(str))
	if str == "" {
		return 50 * 1024 * 1024, nil
	}
	unitMultiplier := int64(1)
	clean := str
	if strings.HasSuffix(str, "MB") || strings.HasSuffix(str, "M") {
		unitMultiplier = 1024 * 1024
		clean = strings.TrimSuffix(strings.TrimSuffix(str, "MB"), "M")
	} else if strings.HasSuffix(str, "GB") || strings.HasSuffix(str, "G") {
		unitMultiplier = 1024 * 1024 * 1024
		clean = strings.TrimSuffix(strings.TrimSuffix(str, "GB"), "G")
	} else if strings.HasSuffix(str, "KB") || strings.HasSuffix(str, "K") {
		unitMultiplier = 1024
		clean = strings.TrimSuffix(strings.TrimSuffix(str, "KB"), "K")
	} else if strings.HasSuffix(str, "B") {
		clean = strings.TrimSuffix(str, "B")
	}
	val, err := strconv.ParseInt(strings.TrimSpace(clean), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q: %w", str, err)
	}
	return val * unitMultiplier, nil
}

// FormatBytes formats byte counts into human-readable strings (e.g. 4.2 MB).
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// StartAutomatedRetention initializes periodic background pruning and log rotation.
func StartAutomatedRetention(ctx context.Context, sqStore *SQLiteStore, dir string, policy RetentionPolicy) *RetentionManager {
	mgr := &RetentionManager{
		sqStore: sqStore,
		dir:     dir,
		policy:  policy,
		stats: RetentionStats{
			RetentionPeriod: policy.RetentionPeriod.String(),
			RetentionDays:   int(policy.RetentionPeriod / (24 * time.Hour)),
			MaxEvents:       policy.MaxEvents,
			PruneInterval:   policy.PruneInterval.String(),
		},
	}

	// Immediate run on startup
	mgr.RunPrune()

	// If prune interval is 0, do not start background loop
	if policy.PruneInterval <= 0 {
		return mgr
	}

	go func() {
		ticker := time.NewTicker(policy.PruneInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mgr.RunPrune()
			}
		}
	}()

	return mgr
}

// RunPrune executes a single prune cycle according to configured policy.
func (m *RetentionManager) RunPrune() (int64, error) {
	if m.sqStore == nil {
		return 0, nil
	}

	var totalPruned int64

	// 1. Prune by retention period (age)
	if m.policy.RetentionPeriod > 0 {
		pruned, err := m.sqStore.PruneOlderThanDuration(m.policy.RetentionPeriod)
		if err == nil {
			totalPruned += pruned
		}
	}

	// 2. Prune by maximum row count
	if m.policy.MaxEvents > 0 {
		pruned, err := m.sqStore.PruneMaxRows(m.policy.MaxEvents)
		if err == nil {
			totalPruned += pruned
		}
	}

	// 3. Compact database if substantial rows were deleted
	if totalPruned > 500 && m.policy.AutoVacuum {
		_ = m.sqStore.Vacuum()
	}

	// 4. Rotate access.log if it exceeds max size
	if m.dir != "" && m.policy.MaxLogSizeBytes > 0 {
		m.rotateAccessLogIfExceeded()
	}

	m.mu.Lock()
	m.stats.LastPrunedAt = time.Now().UTC()
	m.stats.LastPrunedCount = totalPruned
	m.stats.TotalPruned += totalPruned
	m.mu.Unlock()

	if totalPruned > 0 && IsVerboseLogging() {
		ts := time.Now().Format("15:04:05")
		fmt.Printf("[%s] 🧹 [Retention] Pruned %d expired/overflow event(s)\n", ts, totalPruned)
	}

	return totalPruned, nil
}

// GetStats returns current retention metrics.
func (m *RetentionManager) GetStats() RetentionStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

func (m *RetentionManager) rotateAccessLogIfExceeded() {
	accessLogPath := filepath.Join(m.dir, "access.log")
	fi, err := os.Stat(accessLogPath)
	if err != nil || fi.Size() < m.policy.MaxLogSizeBytes {
		return
	}

	dashboardLogMu.Lock()
	defer dashboardLogMu.Unlock()

	backupPath := filepath.Join(m.dir, "access.log.1")
	_ = os.Remove(backupPath)
	_ = os.Rename(accessLogPath, backupPath)

	// Create fresh access.log
	f, err := os.OpenFile(accessLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err == nil {
		_ = f.Close()
	}

	if IsVerboseLogging() {
		ts := time.Now().Format("15:04:05")
		fmt.Printf("[%s] 📄 [Retention] Rotated access.log (%s) to access.log.1\n", ts, FormatBytes(fi.Size()))
	}
}
