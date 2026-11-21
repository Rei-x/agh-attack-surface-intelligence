package fingerprint

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func probePaths(t *testing.T, h http.Handler, paths ...string) ([]string, bool) {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	opts := DefaultOptions()
	opts.Scheme = "http"
	opts.SafePaths = paths
	fp, err := Probe(context.Background(), host, port, "", &opts)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	var got []string
	for _, h := range fp.SafePathHits {
		got = append(got, h.Path)
	}
	return got, fp.CatchAll
}

// Real deployments are full of catch-alls; none of them may produce path evidence.
func TestSafePathsIgnoreSoftNotFound(t *testing.T) {
	paths := []string{"/phpmyadmin", "/wp-login.php", "/admin", "/actuator/info", "/metrics"}
	cases := map[string]http.HandlerFunc{
		"spa fallback": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><head><title>Portal</title></head><body><div id="root"></div><script src="/assets/app.js"></script></body></html>`)
		},
		"templated 200 error page echoing the path": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `<html><head><title>Not found</title></head><body>Page %s does not exist on this server.</body></html>`, r.URL.Path)
		},
		"redirect everything to login": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/login" {
				fmt.Fprint(w, "<title>Login</title>")
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
		},
		"path-preserving redirect (e.g. to a canonical host)": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				fmt.Fprint(w, "<title>Home</title>")
				return
			}
			http.Redirect(w, r, "https://www.portal.agh.local"+r.URL.Path, http.StatusMovedPermanently)
		},
		"blanket 403 (WAF)": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<title>403 Forbidden</title>Access denied")
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			got, catchAll := probePaths(t, h, paths...)
			if len(got) != 0 || !catchAll {
				t.Fatalf("catch-all must yield no path hits (got %v, catch_all=%v)", got, catchAll)
			}
		})
	}
}

func TestSafePathsKeepRealHits(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "<title>Blog</title>")
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "wordpress_test_cookie", Value: "WP Cookie check"})
		fmt.Fprint(w, `<title>Log In &lsaquo; Blog &#8212; WordPress</title><form id="loginform">`)
	})
	mux.HandleFunc("/wp-admin/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/wp-login.php?redirect_to=%2Fwp-admin%2F", http.StatusFound)
	})
	got, catchAll := probePaths(t, mux, "/wp-login.php", "/wp-admin/", "/phpmyadmin")
	if catchAll || len(got) != 2 || got[0] != "/wp-login.php" || got[1] != "/wp-admin/" {
		t.Fatalf("expected real hits [/wp-login.php /wp-admin/] without catch_all, got %v catch_all=%v", got, catchAll)
	}

	// A catch-all SPA that ALSO serves a genuinely different page keeps that page.
	spa := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-login.php" {
			fmt.Fprint(w, `<title>Log In &lsaquo; WordPress</title><form id="loginform" action="/wp-login.php" method="post"><input name="log"><input name="pwd"></form>`)
			return
		}
		fmt.Fprint(w, `<html><head><title>Portal</title></head><body><div id="root"></div></body></html>`)
	})
	got, catchAll = probePaths(t, spa, "/wp-login.php", "/phpmyadmin")
	if !catchAll || len(got) != 1 || got[0] != "/wp-login.php" {
		t.Fatalf("expected only /wp-login.php on catch-all SPA, got %v catch_all=%v", got, catchAll)
	}
}
