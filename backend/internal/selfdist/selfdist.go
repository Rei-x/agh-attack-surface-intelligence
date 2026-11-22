// Package selfdist lets a Dzięcioł instance hand out its own build, so a one-line
// `curl https://<instance>/install.sh | sh -s -- --agent ...` needs nothing but this server:
//
//	GET /install.sh               the installer (copy of the repository's install.sh) with this
//	                              instance's /download URL filled in
//	GET /download/checksums.txt   SHA-256 of every binary below, computed from the files served
//	GET /download/dzieciol-<os>-<arch>
//
// Binaries come from a directory (the Docker image ships linux and darwin builds for amd64 and
// arm64 in /app/dist); the running executable is served for its own platform when the
// directory has no file for it.
package selfdist

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// installScript is the repository's install.sh (a test keeps the two identical).
//
//go:embed install.sh
var installScript []byte

// baseLine is the install.sh line the server fills in with its download URL.
const baseLine = `SERVER_DOWNLOAD_BASE=""`

// safeBase accepts plain http(s) URLs only: the value is pasted into a shell script, so a
// forged Host header must never smuggle quotes, `$` or spaces into it.
var safeBase = regexp.MustCompile(`^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$`)

// Script returns install.sh with downloadBase (e.g. https://dzieciol.example.edu/download) as
// its default download location. An empty or unsafe base returns the script unchanged, so it
// downloads from GitHub Releases.
func Script(downloadBase string) []byte {
	downloadBase = strings.TrimRight(strings.TrimSpace(downloadBase), "/")
	if downloadBase == "" || !safeBase.MatchString(downloadBase) {
		return append([]byte(nil), installScript...)
	}
	return bytes.Replace(installScript, []byte(baseLine), []byte(`SERVER_DOWNLOAD_BASE='`+downloadBase+`'`), 1)
}

// Platforms are the os/arch pairs an instance can serve.
var Platforms = []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"}

// AssetName is the published file name of one platform's binary.
func AssetName(platform string) string {
	return "dzieciol-" + strings.ReplaceAll(platform, "/", "-")
}

// ChecksumsName is the checksum list served next to the binaries.
const ChecksumsName = "checksums.txt"

// Dist serves the binaries found in Dir, plus Self for its own platform.
type Dist struct {
	Dir          string // directory with dzieciol-<os>-<arch> files ("" = none)
	Self         string // the running executable ("" = do not serve it)
	SelfPlatform string // GOOS/GOARCH of Self

	mu   sync.Mutex
	hash map[string]hashed // path -> checksum of the version last seen
}

type hashed struct {
	size int64
	mod  time.Time
	sum  string
}

// asset is one servable binary.
type asset struct {
	name string
	path string
	info os.FileInfo
}

// FromEnvironment serves DZIECIOL_DOWNLOAD_DIR (default: a "dist" directory next to the
// executable) and the running executable for its own platform.
func FromEnvironment() *Dist {
	d := &Dist{SelfPlatform: runtime.GOOS + "/" + runtime.GOARCH}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		d.Self = exe
		d.Dir = filepath.Join(filepath.Dir(exe), "dist")
	}
	if v := strings.TrimSpace(os.Getenv("DZIECIOL_DOWNLOAD_DIR")); v != "" {
		d.Dir = v
	}
	return d
}

func (d *Dist) assets() []asset {
	var out []asset
	for _, p := range Platforms {
		name := AssetName(p)
		var path string
		if d.Dir != "" {
			path = filepath.Join(d.Dir, name)
		}
		info, err := os.Stat(path)
		if path == "" || err != nil || !info.Mode().IsRegular() {
			if p != d.SelfPlatform || d.Self == "" {
				continue
			}
			path = d.Self
			if info, err = os.Stat(path); err != nil || !info.Mode().IsRegular() {
				continue
			}
		}
		out = append(out, asset{name: name, path: path, info: info})
	}
	return out
}

// Available lists the platforms this instance can serve.
func (d *Dist) Available() []string {
	var out []string
	for _, a := range d.assets() {
		out = append(out, strings.Replace(strings.TrimPrefix(a.name, "dzieciol-"), "-", "/", 1))
	}
	return out
}

func (d *Dist) checksum(a asset) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if h, ok := d.hash[a.path]; ok && h.size == a.info.Size() && h.mod.Equal(a.info.ModTime()) {
		return h.sum, nil
	}
	f, err := os.Open(a.path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	if d.hash == nil {
		d.hash = map[string]hashed{}
	}
	h := hashed{size: a.info.Size(), mod: a.info.ModTime(), sum: hex.EncodeToString(sum.Sum(nil))}
	d.hash[a.path] = h
	return h.sum, nil
}

// Checksums returns checksums.txt in sha256sum format for every servable binary.
func (d *Dist) Checksums() ([]byte, error) {
	assets := d.assets()
	sort.Slice(assets, func(i, j int) bool { return assets[i].name < assets[j].name })
	var b bytes.Buffer
	for _, a := range assets {
		sum, err := d.checksum(a)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "%s  %s\n", sum, a.name)
	}
	return b.Bytes(), nil
}

// ServeFile answers GET /download/{name}: checksums.txt or one binary. Unknown names are 404,
// so no other file on the server can be reached.
func (d *Dist) ServeFile(w http.ResponseWriter, r *http.Request, name string) {
	w.Header().Set("Cache-Control", "no-cache")
	if name == ChecksumsName {
		body, err := d.Checksums()
		if err != nil {
			http.Error(w, "cannot read the binaries", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
		return
	}
	for _, a := range d.assets() {
		if a.name != name {
			continue
		}
		f, err := os.Open(a.path)
		if err != nil {
			http.Error(w, "cannot read the binary", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		if sum, err := d.checksum(a); err == nil {
			w.Header().Set("X-Checksum-Sha256", sum)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+a.name+`"`)
		http.ServeContent(w, r, a.name, a.info.ModTime(), f)
		return
	}
	http.Error(w, "no such download; this server offers: "+strings.Join(d.Available(), ", "), http.StatusNotFound)
}
