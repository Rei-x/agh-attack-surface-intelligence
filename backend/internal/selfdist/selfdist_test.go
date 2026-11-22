package selfdist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The embedded installer is the repository's install.sh, byte for byte.
func TestEmbeddedScriptMatchesRepository(t *testing.T) {
	repo, err := os.ReadFile(filepath.Join("..", "..", "..", "install.sh"))
	if err != nil {
		t.Skipf("repository install.sh not found: %v", err)
	}
	if !bytes.Equal(repo, installScript) {
		t.Fatal("backend/internal/selfdist/install.sh differs from install.sh: copy it (cp install.sh backend/internal/selfdist/)")
	}
	if !bytes.Contains(installScript, []byte("\n"+baseLine+"\n")) {
		t.Fatalf("install.sh has no %q line for the server to fill in", baseLine)
	}
}

func TestScriptTemplatesTheInstanceURL(t *testing.T) {
	got := string(Script("https://dzieciol.example.edu/download/"))
	if !strings.Contains(got, "\nSERVER_DOWNLOAD_BASE='https://dzieciol.example.edu/download'\n") {
		t.Fatal("download base not filled in")
	}
	if strings.Contains(got, baseLine) {
		t.Fatal("empty base line left in the script")
	}
	if !strings.HasPrefix(got, "#!/bin/sh\n") {
		t.Fatal("shebang lost")
	}
	for _, u := range []string{"http://127.0.0.1:8080/download", "https://[fd00::1]:8443/download", "https://a-b.example/x_y/~z"} {
		if !strings.Contains(string(Script(u)), "SERVER_DOWNLOAD_BASE='"+u+"'") {
			t.Errorf("%s not accepted", u)
		}
	}
	// A forged Host header must not inject shell code: unsafe bases leave the GitHub default.
	for _, bad := range []string{
		"https://x$(id)/download", "https://x'; rm -rf / #/download", "https://x/download`id`",
		"https://x y/download", "ftp://x/download", "javascript:alert(1)", "https://x/\"download", "",
	} {
		if s := Script(bad); !bytes.Equal(s, installScript) {
			t.Errorf("unsafe base %q changed the script", bad)
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func get(t *testing.T, d *Dist, name string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	d.ServeFile(rec, httptest.NewRequest(http.MethodGet, "/download/"+name, nil), name)
	return rec
}

func TestDownloadsWithChecksums(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "dzieciol-linux-amd64"), "linux amd64 build")
	writeFile(t, filepath.Join(dir, "dzieciol-darwin-arm64"), "darwin arm64 build")
	writeFile(t, filepath.Join(dir, "secret.txt"), "not served")
	writeFile(t, filepath.Join(dir, "checksums.txt"), "stale  dzieciol-linux-amd64\n") // ignored: recomputed
	self := filepath.Join(t.TempDir(), "dzieciol")
	writeFile(t, self, "the running linux arm64 server")
	d := &Dist{Dir: dir, Self: self, SelfPlatform: "linux/arm64"}

	rec := get(t, d, ChecksumsName)
	want := sum("darwin arm64 build") + "  dzieciol-darwin-arm64\n" +
		sum("linux amd64 build") + "  dzieciol-linux-amd64\n" +
		sum("the running linux arm64 server") + "  dzieciol-linux-arm64\n"
	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Fatalf("checksums.txt: %d\n%s\nwant\n%s", rec.Code, rec.Body, want)
	}
	if got := strings.Join(d.Available(), ","); got != "linux/amd64,linux/arm64,darwin/arm64" {
		t.Fatalf("available: %s", got)
	}

	rec = get(t, d, "dzieciol-linux-amd64")
	if rec.Code != http.StatusOK || rec.Body.String() != "linux amd64 build" ||
		rec.Header().Get("X-Checksum-Sha256") != sum("linux amd64 build") ||
		rec.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("binary: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	if rec = get(t, d, "dzieciol-linux-arm64"); rec.Body.String() != "the running linux arm64 server" {
		t.Fatalf("self binary not served for its platform: %q", rec.Body)
	}
	for _, name := range []string{"dzieciol-darwin-amd64", "secret.txt", "../secret.txt", "dzieciol-windows-amd64.exe", ""} {
		if rec = get(t, d, name); rec.Code != http.StatusNotFound {
			t.Errorf("%q: %d, want 404", name, rec.Code)
		}
	}

	// A replaced binary (redeploy) gets a fresh checksum, never a cached stale one.
	time.Sleep(10 * time.Millisecond)
	writeFile(t, filepath.Join(dir, "dzieciol-linux-amd64"), "linux amd64 build v2")
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(filepath.Join(dir, "dzieciol-linux-amd64"), future, future)
	if rec = get(t, d, ChecksumsName); !strings.Contains(rec.Body.String(), sum("linux amd64 build v2")+"  dzieciol-linux-amd64") {
		t.Fatalf("checksum not refreshed:\n%s", rec.Body)
	}

	// A directory entry for the server's own platform wins over the running binary.
	writeFile(t, filepath.Join(dir, "dzieciol-linux-arm64"), "shipped arm64 build")
	if rec = get(t, d, "dzieciol-linux-arm64"); rec.Body.String() != "shipped arm64 build" {
		t.Fatalf("dist file should win: %q", rec.Body)
	}
}

func TestDownloadsWithoutDirectoryServeSelf(t *testing.T) {
	self := filepath.Join(t.TempDir(), "dzieciol")
	writeFile(t, self, "mac build")
	d := &Dist{Dir: filepath.Join(t.TempDir(), "missing"), Self: self, SelfPlatform: "darwin/arm64"}
	if got := d.Available(); len(got) != 1 || got[0] != "darwin/arm64" {
		t.Fatalf("available: %v", got)
	}
	rec := get(t, d, "dzieciol-linux-amd64")
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "darwin/arm64") {
		t.Fatalf("missing platform: %d %q", rec.Code, rec.Body)
	}
}
