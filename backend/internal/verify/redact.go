package verify

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Redaction of evidence. A verified finding proves that something is readable; it must not
// copy the secret itself into Dzięcioł, DefectDojo or a screenshot. Values that look like
// credentials keep their first two characters and length class, the rest is masked.

const redacted = "[redacted]"

var redactRules = []struct {
	re   *regexp.Regexp
	repl func(m []string) string
}{
	// PEM private keys.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)`), func(m []string) string {
		return "-----BEGIN PRIVATE KEY----- " + redacted + " -----END PRIVATE KEY-----"
	}},
	// Authorization / cookie headers.
	{regexp.MustCompile(`(?im)^((?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token)(\s*:\s*)(.+)$`), func(m []string) string {
		return m[1] + m[2] + redacted
	}},
	// URLs and DSNs with credentials: scheme://user:pass@host.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@"']+:)([^\s@/"']+)(@)`), func(m []string) string {
		return m[1] + redacted + m[3]
	}},
	// KEY=value / KEY: value / "key": "value" where the key names a secret (.env, phpinfo,
	// config dumps, JSON).
	{regexp.MustCompile(`(?i)("?[A-Za-z0-9_.\-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential|salt|session[_-]?key|app[_-]?key|dsn|requirepass|masterauth)[A-Za-z0-9_.\-]*"?)(\s*(?:=|:|=>)\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;<"'\r\n]+)`), func(m []string) string {
		return m[1] + m[2] + maskValue(m[3])
	}},
	// phpinfo() / config tables: <td>DB_PASSWORD</td><td>value</td>.
	{regexp.MustCompile(`(?i)(<td[^>]*>\s*[A-Za-z0-9_.\-\[\]"']*(?:pass|pwd|secret|token|key|auth|credential|salt)[A-Za-z0-9_.\-\[\]"']*\s*</td>\s*<td[^>]*>)([^<]*)`), func(m []string) string {
		return m[1] + maskValue(strings.TrimSpace(m[2]))
	}},
	// AWS access key ids, GitHub / GitLab / Slack tokens, JWTs.
	{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), func(m []string) string { return m[1] + "****" + redacted }},
	{regexp.MustCompile(`\b(ghp|gho|ghs|ghu|github_pat|glpat|xox[abprs])[-_][A-Za-z0-9_\-]{10,}`), func(m []string) string { return m[1] + "_" + redacted }},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`), func(m []string) string { return "eyJ" + redacted }},
}

// maskValue keeps quotes and the first two characters of a value: `"hunter2"` -> `"hu[redacted]"`.
func maskValue(v string) string {
	q := ""
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		q, v = v[:1], v[1:len(v)-1]
	}
	if v == "" || strings.EqualFold(v, "null") || strings.EqualFold(v, "false") || strings.EqualFold(v, "true") || v == redacted {
		return q + v + q
	}
	keep := ""
	if utf8.RuneCountInString(v) > 6 {
		r := []rune(v)
		keep = string(r[:2])
	}
	return q + keep + redacted + q
}

// Redact masks credentials in evidence text.
func Redact(s string) string {
	for _, r := range redactRules {
		rule := r
		s = rule.re.ReplaceAllStringFunc(s, func(match string) string {
			return rule.repl(rule.re.FindStringSubmatch(match))
		})
	}
	return s
}

// snippet returns a window of at most max bytes around the first match position (or the
// start), on rune boundaries, with non-printable bytes replaced, then redacted.
func snippet(body string, at, max int) string {
	if at < 0 || at > len(body) {
		at = 0
	}
	start := at - max/3
	if start < 0 {
		start = 0
	}
	end := start + max
	if end > len(body) {
		end = len(body)
	}
	for start > 0 && !utf8.RuneStart(body[start]) {
		start--
	}
	for end < len(body) && !utf8.RuneStart(body[end]) {
		end++
	}
	out := printable(body[start:end])
	if start > 0 {
		out = "..." + out
	}
	if end < len(body) {
		out += "..."
	}
	return Redact(out)
}

// printable replaces control bytes (binary protocols) with '.', keeping newlines and tabs.
func printable(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == '\r':
		case r == utf8.RuneError || r < 0x20 || r == 0x7f:
			b.WriteByte('.')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
