package fingerprint

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func probeServer(t *testing.T, h http.Handler) (*domain.HTTPFingerprint, []string) {
	t.Helper()
	var mu sync.Mutex
	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.Path)
		mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	opts := DefaultOptions()
	opts.Scheme = "http"
	fp, err := Probe(context.Background(), host, port, "", &opts)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return fp, requested
}

func findHit(fp *domain.HTTPFingerprint, path string) *domain.SafePathHit {
	for i := range fp.SafePathHits {
		if fp.SafePathHits[i].Path == path {
			return &fp.SafePathHits[i]
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Joomla 4 front page + administrator login, as shipped.
func TestFollowupJoomlaAdministrator(t *testing.T) {
	fp, requested := probeServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<!DOCTYPE html><html lang="pl-pl"><head><meta name="generator" content="Joomla! - Open Source Content Management"><title>Strona główna - Koło</title></head><body></body></html>`)
		case "/administrator/":
			fmt.Fprint(w, `<!DOCTYPE html><html><head><meta name="generator" content="Joomla! - Open Source Content Management"><title>Koło - Administracja</title></head>
<body class="admin com_login view-login"><form action="/administrator/index.php" method="post" id="form-login">
<input name="username" id="mod-login-username" type="text" required><input name="passwd" id="mod-login-password" type="password" required></form></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	if !contains(requested, "/administrator/") {
		t.Fatalf("Joomla follow-up not requested: %v", requested)
	}
	h := findHit(fp, "/administrator/")
	if h == nil || h.StatusCode != 200 || !h.LoginForm {
		t.Fatalf("administrator hit = %+v", h)
	}
}

// Tomcat default page + manager behind Basic auth.
func TestFollowupTomcatManager(t *testing.T) {
	fp, requested := probeServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<!DOCTYPE html><html lang="en"><head><title>Apache Tomcat/9.0.83</title></head><body><a href="/manager/html">Manager App</a></body></html>`)
		case "/manager/html":
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `<!doctype html><html lang="en"><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	if !contains(requested, "/manager/html") {
		t.Fatalf("Tomcat follow-up not requested: %v", requested)
	}
	h := findHit(fp, "/manager/html")
	if h == nil || h.StatusCode != 401 || h.AuthChallenge != `Basic realm="Tomcat Manager Application"` {
		t.Fatalf("manager hit = %+v", h)
	}
}

// No follow-ups for an unidentified site, and login forms are flagged on the root page.
func TestNoFollowupForUnknownApp(t *testing.T) {
	fp, requested := probeServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html><head><title>Logowanie</title></head><body><form method="post"><input name="u"><input type='password' name="p"></form></body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	if contains(requested, "/administrator/") || contains(requested, "/manager/html") {
		t.Fatalf("unexpected follow-up: %v", requested)
	}
	if !fp.LoginForm {
		t.Fatal("root login form not detected")
	}
}
