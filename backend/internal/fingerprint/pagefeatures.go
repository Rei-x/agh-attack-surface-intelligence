package fingerprint

import (
	"regexp"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Page features used by identification rules (admin consoles, login pages), and the
// app-specific follow-up paths that are requested only once the root page has already
// identified the application. Follow-ups are plain GETs through the same rate limiter and
// soft-404 filter as the default safe paths, at most two per service.

var rePasswordInput = regexp.MustCompile(`(?i)<input\b[^>]*\btype\s*=\s*["']?password\b`)

// hasPasswordField reports whether an HTML page contains a password input (a login form).
func hasPasswordField(body string) bool {
	return rePasswordInput.MatchString(body)
}

var (
	reJoomlaGen    = regexp.MustCompile(`(?i)<meta[^>]+content\s*=\s*["']Joomla!`)
	reTomcatMarker = regexp.MustCompile(`(?i)Apache Tomcat/[0-9]`)
)

// followupPaths returns read-only paths worth one extra GET because the root page has
// identified an application whose admin console lives at a well-known path:
//
//	Joomla!  (meta generator "Joomla! - Open Source Content Management") -> /administrator/
//	Tomcat   (default page / error page "Apache Tomcat/9.0.x")          -> /manager/html (401 Basic realm "Tomcat Manager Application")
func followupPaths(fp *domain.HTTPFingerprint, already []string) []string {
	if fp == nil {
		return nil
	}
	var out []string
	add := func(p string) {
		for _, a := range already {
			if strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(p, "/")) {
				return
			}
		}
		out = append(out, p)
	}
	page := fp.Title + "\n" + fp.MetaGenerator + "\n" + fp.BodySnippet
	if strings.HasPrefix(strings.ToLower(fp.MetaGenerator), "joomla") || reJoomlaGen.MatchString(fp.BodySnippet) {
		add("/administrator/")
	}
	if reTomcatMarker.MatchString(page) {
		add("/manager/html")
	}
	return out
}

func truncateHeader(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) > n {
		return v[:n]
	}
	return v
}
