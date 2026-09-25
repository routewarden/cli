//go:build !windows

package dashboard

import (
	"os"
	"syscall"
)

// fileInode extracts the inode number from os.FileInfo.
// Used on Unix systems to detect log rotation (rename/replace).
func fileInode(info os.FileInfo) uint64 {
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		return sys.Ino
	}
	return 0
}
