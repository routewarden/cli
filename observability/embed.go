package observability

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed docker-compose.yml README.md favicon.ico icon.svg
var EmbeddedFiles embed.FS

//go:embed favicon.ico
var FaviconICO []byte

//go:embed icon.svg
var FaviconSVG []byte

// Export exports all embedded dashboard assets to targetDir.
func Export(targetDir string) error {
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("create target directory %q: %w", targetDir, err)
	}

	return fs.WalkDir(EmbeddedFiles, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}

		destPath := filepath.Join(targetDir, path)
		if d.IsDir() {
			return os.MkdirAll(destPath, 0755)
		}

		data, err := EmbeddedFiles.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read embedded file %q: %w", path, err)
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("create parent dir for %q: %w", destPath, err)
		}

		if err := os.WriteFile(destPath, data, 0644); err != nil {
			return fmt.Errorf("write destination file %q: %w", destPath, err)
		}

		return nil
	})
}
