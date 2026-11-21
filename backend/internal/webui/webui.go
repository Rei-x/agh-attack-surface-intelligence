// Package webui embeds the built React SOC dashboard into the aegis binary.
//
// `make ui` (or scripts in the Makefile) copies frontend/dist/* into ./ui before `go build`.
// The directory is git-ignored except for .gitkeep, so a plain `go build ./...` always works:
// without a frontend build the server serves a small placeholder page instead.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:ui
var embedded embed.FS

// FS returns the embedded UI rooted at the dist directory.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "ui")
	if err != nil {
		panic(err)
	}
	return sub
}

// Available reports whether a real frontend build (index.html) was embedded.
func Available() bool {
	_, err := fs.Stat(FS(), "index.html")
	return err == nil
}

// PlaceholderHTML is served when the binary was built without the frontend.
const PlaceholderHTML = `<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AegisASI</title>
<style>body{font-family:system-ui,sans-serif;background:#0b1020;color:#e6e9f2;display:grid;place-items:center;min-height:100vh;margin:0}
main{max-width:40rem;padding:2rem}code{background:#1b2340;padding:.15rem .4rem;border-radius:4px}a{color:#7aa2ff}</style></head>
<body><main><h1>AegisASI API działa</h1>
<p>Ten plik binarny został zbudowany bez interfejsu webowego. Zbuduj go poleceniem <code>make build</code>
(które uruchamia <code>make ui</code>) albo wskaż zbudowany frontend przez <code>ASI_STATIC_DIR=/ścieżka/do/dist</code>.</p>
<p>API: <a href="/api/v1/health">/api/v1/health</a></p></main></body></html>`
