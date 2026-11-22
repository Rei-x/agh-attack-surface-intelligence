package signatures

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ValidationResult reports whether a signature is safe and well-formed.
type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

var allowedCategories = map[string]bool{
	"cms":                true,
	"framework":          true,
	"server":             true,
	"iot":                true,
	"bmc":                true,
	"admin_panel":        true,
	"staging":            true,
	"interesting_header": true,
	"interesting_cookie": true,
	"custom":             true,
}

var allowedMatcherTypes = map[string]bool{
	"header":         true,
	"cookie":         true,
	"favicon_mmh3":   true,
	"favicon_sha256": true,
	"html_body":      true,
	"footer_version": true,
	"safe_path":      true,
	"tls_cert":       true,
	"jarm":           true,
	"banner":         true,
	"port":           true,
	"title":          true,
	"meta_generator": true,
	"url":            true,
	"service_name":   true,
}

var (
	reMutatingMethod = regexp.MustCompile(`(?i)\b(POST|PUT|DELETE|PATCH|TRACE|CONNECT)\b\s*[:/]|\bmethod\s*[:=]\s*(POST|PUT|DELETE|PATCH|TRACE|CONNECT)\b`)
	reCredPayload    = regexp.MustCompile(`(?i)(authorization\s*:\s*(basic|bearer|digest)|\b(password|passwd|pwd|j_password|wp_submit|login_pass|user_pass|api_key|apikey|secret_key)\s*=|\bunion\s+select\b|'\s*or\s+1\s*=\s*1|<script[^>]*>|\b(exec|eval|system|passthru)\s*\()`)
	rePathTraversal  = regexp.MustCompile(`(?i)(\.\.|%2e%2e|%252e|%00|\x00|\\|\r|\n)`)
	reNestedQuant    = regexp.MustCompile(`\([^)]*[+*][^)]*\)[+*]`)
	reHugeRepeat     = regexp.MustCompile(`\{(\d{3,}),?`)
	reJARM           = regexp.MustCompile(`^(?i)[0-9a-f]{62}$`)
	reExternalScheme = regexp.MustCompile(`(?i)^(https?|ftp|file|gopher|ldap|dict)://`)
)

// ValidateSignature enforces passive, read-only safety constraints on any detection signature.
func ValidateSignature(sig domain.Signature) ValidationResult {
	res := ValidationResult{Valid: true}
	addErr := func(msg string) {
		res.Valid = false
		res.Errors = append(res.Errors, msg)
	}
	addWarn := func(msg string) {
		res.Warnings = append(res.Warnings, msg)
	}

	if strings.TrimSpace(sig.Name) == "" {
		addErr("signature name is required")
	} else if len(sig.Name) > 120 {
		addErr("signature name exceeds 120 characters")
	}

	cat := strings.ToLower(strings.TrimSpace(sig.Category))
	if !allowedCategories[cat] {
		addErr(fmt.Sprintf("unsupported category %q", sig.Category))
	}

	mode := strings.ToLower(strings.TrimSpace(sig.MatchMode))
	if mode == "" {
		mode = "any"
	}
	if mode != "any" && mode != "all" {
		addErr(fmt.Sprintf("match_mode must be 'any' or 'all', got %q", sig.MatchMode))
	}

	if sig.ConfidenceWeight < 0.1 || sig.ConfidenceWeight > 0.98 {
		addErr(fmt.Sprintf("confidence_weight must be between 0.10 and 0.98, got %.2f", sig.ConfidenceWeight))
	}

	if sig.InterestingPts < 0 || sig.InterestingPts > 50 {
		addErr(fmt.Sprintf("interesting_points must be between 0 and 50, got %d", sig.InterestingPts))
	}

	if len(sig.Matchers) == 0 {
		addErr("at least one matcher is required")
	}
	if len(sig.Matchers) > 20 {
		addErr("too many matchers (max 20)")
	}

	for i, m := range sig.Matchers {
		prefix := fmt.Sprintf("matcher[%d]", i)
		mt := strings.ToLower(strings.TrimSpace(m.Type))
		if !allowedMatcherTypes[mt] {
			addErr(fmt.Sprintf("%s: unsupported matcher type %q", prefix, m.Type))
			continue
		}

		if strings.TrimSpace(m.Pattern) == "" && strings.TrimSpace(m.Key) == "" {
			addErr(fmt.Sprintf("%s: pattern or key is required", prefix))
			continue
		}

		// Block CRLF / null bytes anywhere in keys.
		if strings.ContainsAny(m.Key, "\r\n\x00") || strings.ContainsAny(m.Pattern, "\x00") {
			addErr(fmt.Sprintf("%s: control characters (CRLF/NUL) are forbidden", prefix))
		}

		// Block mutating HTTP methods (strictly GET/HEAD read-only).
		if reMutatingMethod.MatchString(m.Key) || reMutatingMethod.MatchString(m.Pattern) {
			addErr(fmt.Sprintf("%s: mutating HTTP methods (POST/PUT/DELETE/PATCH/TRACE/CONNECT) are forbidden", prefix))
		}

		// Block credential, login-attempt, or exploit payloads.
		if reCredPayload.MatchString(m.Key) || reCredPayload.MatchString(m.Pattern) {
			addErr(fmt.Sprintf("%s: credential, login-submission, or active exploit payloads are forbidden", prefix))
		}

		// Path safety checks for safe_path matchers.
		if mt == "safe_path" {
			checkPath := strings.TrimSpace(m.Key)
			if checkPath == "" {
				checkPath = strings.TrimSpace(m.Pattern)
			}
			// With a Key the Pattern is matched against the response (path, title, body
			// snippet), not requested, so a regex there may contain escapes like \.
			patternIsPath := strings.TrimSpace(m.Key) == "" || !m.Regex
			if rePathTraversal.MatchString(checkPath) || (patternIsPath && rePathTraversal.MatchString(m.Pattern)) {
				addErr(fmt.Sprintf("%s: path traversal or unsafe characters are forbidden in safe_path", prefix))
			}
			if reExternalScheme.MatchString(checkPath) || reExternalScheme.MatchString(m.Pattern) {
				addErr(fmt.Sprintf("%s: external URL schemes are forbidden in safe_path (use relative /path)", prefix))
			}
			if !m.Regex && checkPath != "" && !strings.HasPrefix(checkPath, "/") {
				addErr(fmt.Sprintf("%s: safe_path must start with '/'", prefix))
			}
		}

		// JARM equality matchers must be a 62-char lowercase-hex fingerprint.
		if mt == "jarm" && !m.Regex && !reJARM.MatchString(strings.TrimSpace(m.Pattern)) {
			addErr(fmt.Sprintf("%s: jarm pattern must be a 62-character hex JARM fingerprint (or set regex=true)", prefix))
		}

		// Validate regex safety and capture groups.
		if m.Regex {
			if len(m.Pattern) > 512 {
				addErr(fmt.Sprintf("%s: regex pattern exceeds 512 characters", prefix))
			}
			if reNestedQuant.MatchString(m.Pattern) {
				addErr(fmt.Sprintf("%s: unsafe nested quantifier regex rejected", prefix))
			}
			if reHugeRepeat.MatchString(m.Pattern) {
				addErr(fmt.Sprintf("%s: excessively large regex repetition quantifier rejected", prefix))
			}
			re, err := regexp.Compile(m.Pattern)
			if err != nil {
				addErr(fmt.Sprintf("%s: invalid regex: %v", prefix, err))
			} else {
				if m.VersionGroup < 0 {
					addErr(fmt.Sprintf("%s: version_group cannot be negative", prefix))
				} else if m.VersionGroup > re.NumSubexp() {
					addErr(fmt.Sprintf("%s: version_group %d exceeds regex capture groups (%d)", prefix, m.VersionGroup, re.NumSubexp()))
				}
			}
		} else if m.VersionGroup != 0 {
			addWarn(fmt.Sprintf("%s: version_group is ignored when regex=false", prefix))
		}

		// Validate status codes if provided.
		for _, code := range m.StatusCodes {
			if code < 100 || code > 599 {
				addErr(fmt.Sprintf("%s: invalid HTTP status code %d", prefix, code))
			}
		}
	}

	return res
}
