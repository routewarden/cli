package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var embeddedDist embed.FS

// getSPAFileSystem returns the embedded Vite build output as an http.FileSystem.
// The SPA assets are baked into the rwarden binary at compile time.
// Falls back to serving ./web/dist from disk when not embedded (dev mode).
func getSPAFileSystem() http.FileSystem {
	// Strip the "dist/" prefix so "/" maps to index.html
	stripped, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		// Fallback for development: serve from disk
		return http.Dir("web/dist")
	}
	return http.FS(stripped)
}
