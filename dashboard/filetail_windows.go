//go:build windows

package dashboard

import "os"

// fileInode always returns 0 on Windows because syscall.Stat_t is not available.
// Log rotation is detected by file size change only.
func fileInode(_ os.FileInfo) uint64 {
	return 0
}
