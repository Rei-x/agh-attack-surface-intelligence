package signatures

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// MatchResult represents a single signature evaluation outcome against a service.
type MatchResult struct {
	Signature domain.Signature      `json:"signature"`
	Matched   bool                  `json:"matched"`
	Version   string                `json:"version,omitempty"`
	Evidence  []domain.TechEvidence `json:"evidence,omitempty"`
}

// RetroactiveMatch represents a match returned by the Signature Playground on stored services.
type RetroactiveMatch struct {
	ServiceID   string                `json:"service_id"`
	HostID      string                `json:"host_id"`
	HostIP      string                `json:"host_ip"`
	Port        int                   `json:"port"`
	ServiceName string                `json:"service_name"`
	Version     string                `json:"version,omitempty"`
	Evidence    []domain.TechEvidence `json:"evidence"`
}

type compiledMatcher struct {
	matcher domain.SignatureMatcher
	re      *regexp.Regexp
}

type compiledSignature struct {
	sig      domain.Signature
	matchers []compiledMatcher
}

// Engine evaluates built-in and custom detection signatures against observed services.
type Engine struct {
	compiled []compiledSignature
}

// NewEngine builds an evaluation engine from built-in signatures plus optional custom signatures.
// Invalid or disabled signatures are skipped.
func NewEngine(custom []domain.Signature) *Engine {
	all := make([]domain.Signature, 0, len(custom)+60)
	all = append(all, BuiltinSignatures()...)
	all = append(all, custom...)
	return NewEngineFromList(all)
}

// NewEngineFromList builds an evaluation engine from an explicit list of signatures.
func NewEngineFromList(sigs []domain.Signature) *Engine {
	e := &Engine{
		compiled: make([]compiledSignature, 0, len(sigs)),
	}
	seenIDs := make(map[string]struct{}, len(sigs))
	for _, sig := range sigs {
		if !sig.Enabled {
			continue
		}
		if sig.ID != "" {
			if _, dup := seenIDs[sig.ID]; dup {
				continue
			}
			seenIDs[sig.ID] = struct{}{}
		}
		if !ValidateSignature(sig).Valid {
			continue
		}
		cs, ok := compileSignature(sig)
		if ok {
			e.compiled = append(e.compiled, cs)
		}
	}
	return e
}

func compileSignature(sig domain.Signature) (compiledSignature, bool) {
	cs := compiledSignature{
		sig:      sig,
		matchers: make([]compiledMatcher, 0, len(sig.Matchers)),
	}
	for _, m := range sig.Matchers {
		cm := compiledMatcher{matcher: m}
		if m.Regex {
			re, err := regexp.Compile(m.Pattern)
			if err != nil {
				return compiledSignature{}, false
			}
			cm.re = re
		}
		cs.matchers = append(cs.matchers, cm)
	}
	return cs, true
}

// Evaluate runs all active signatures against an ObservedService and returns matches.
func (e *Engine) Evaluate(svc domain.ObservedService) []MatchResult {
	var results []MatchResult
	for _, cs := range e.compiled {
		if res := evalCompiled(cs, svc); res.Matched {
			results = append(results, res)
		}
	}
	return results
}

// EvaluateOne validates and evaluates a single signature against an ObservedService.
func EvaluateOne(sig domain.Signature, svc domain.ObservedService) MatchResult {
	cs, ok := compileSignature(sig)
	if !ok {
		return MatchResult{Signature: sig, Matched: false}
	}
	return evalCompiled(cs, svc)
}

// RetroactiveTest validates a candidate signature and tests it against stored domain.Service records.
func RetroactiveTest(sig domain.Signature, services []domain.Service) ([]RetroactiveMatch, ValidationResult) {
	vr := ValidateSignature(sig)
	if !vr.Valid {
		return nil, vr
	}
	cs, ok := compileSignature(sig)
	if !ok {
		vr.Valid = false
		vr.Errors = append(vr.Errors, "failed to compile signature matchers")
		return nil, vr
	}

	var matches []RetroactiveMatch
	for _, svc := range services {
		obs := domain.ObservedService{
			Port:        svc.Port,
			Protocol:    svc.Protocol,
			State:       svc.State,
			ServiceName: svc.ServiceName,
			Product:     svc.Product,
			Version:     svc.Version,
			CPE:         svc.CPE,
			Banner:      svc.Banner,
			HTTP:        svc.HTTP,
			Tags:        svc.Tags,
			Notes:       svc.Notes,
		}
		res := evalCompiled(cs, obs)
		if res.Matched {
			matches = append(matches, RetroactiveMatch{
				ServiceID:   svc.ID,
				HostID:      svc.HostID,
				HostIP:      svc.HostIP,
				Port:        svc.Port,
				ServiceName: svc.ServiceName,
				Version:     res.Version,
				Evidence:    res.Evidence,
			})
		}
	}
	return matches, vr
}

func evalCompiled(cs compiledSignature, svc domain.ObservedService) MatchResult {
	mode := strings.ToLower(strings.TrimSpace(cs.sig.MatchMode))
	if mode == "" {
		mode = "any"
	}

	var evidence []domain.TechEvidence
	var version string
	matchedCount := 0

	for _, cm := range cs.matchers {
		ok, ver, detail := matchSingle(cm, svc)
		if ok {
			matchedCount++
			if version == "" && ver != "" {
				version = ver
			}
			evidence = append(evidence, domain.TechEvidence{
				SignalType: signalTypeOf(cm.matcher),
				Detail:     detail,
				Weight:     cs.sig.ConfidenceWeight,
			})
		} else if mode == "all" {
			return MatchResult{Signature: cs.sig, Matched: false}
		}
	}

	matched := false
	if mode == "all" {
		matched = matchedCount == len(cs.matchers) && len(cs.matchers) > 0
	} else {
		matched = matchedCount > 0
	}
	if !matched {
		return MatchResult{Signature: cs.sig, Matched: false}
	}

	return MatchResult{
		Signature: cs.sig,
		Matched:   true,
		Version:   version,
		Evidence:  evidence,
	}
}

// signalTypeOf is normalizeSignalType, except that a safe_path matcher whose regex checks
// the response body for a vendor-specific structure (Toxiproxy's /proxies JSON, Traefik's
// /api/version with its Codename) is "path_body": stronger than a bare path status.
func signalTypeOf(m domain.SignatureMatcher) string {
	if strings.EqualFold(m.Type, "safe_path") && m.Regex && m.Key != "" && m.Pattern != m.Key {
		return "path_body"
	}
	return normalizeSignalType(m.Type)
}

func normalizeSignalType(matcherType string) string {
	switch strings.ToLower(matcherType) {
	case "header":
		return "header"
	case "cookie":
		return "cookie"
	case "favicon_mmh3", "favicon_sha256":
		return "favicon"
	case "html_body", "title", "meta_generator", "footer_version", "url":
		return "html"
	case "safe_path":
		return "path"
	case "tls_cert", "jarm":
		return "tls"
	case "banner", "port", "service_name":
		return "banner"
	default:
		return "signature"
	}
}

func matchSingle(cm compiledMatcher, svc domain.ObservedService) (bool, string, string) {
	m := cm.matcher
	mt := strings.ToLower(strings.TrimSpace(m.Type))
	httpFP := svc.HTTP

	switch mt {
	case "header":
		if httpFP == nil {
			return false, "", ""
		}
		if m.Key != "" {
			val := getHeaderCaseInsensitive(httpFP.Headers, m.Key)
			if val == "" && strings.EqualFold(m.Key, "Server") {
				val = httpFP.ServerHeader
			}
			if val == "" {
				return false, "", ""
			}
			if ok, ver := matchString(cm, val); ok {
				return true, ver, fmt.Sprintf("header %s: %s", m.Key, truncate(val, 120))
			}
			return false, "", ""
		}
		for k, v := range httpFP.Headers {
			combined := k + ": " + v
			if ok, ver := matchString(cm, combined); ok {
				return true, ver, fmt.Sprintf("header %s: %s", k, truncate(v, 120))
			}
		}
		return false, "", ""

	case "cookie":
		if httpFP == nil {
			return false, "", ""
		}
		for _, c := range httpFP.Cookies {
			if m.Key != "" && !strings.Contains(strings.ToLower(c.Name), strings.ToLower(m.Key)) {
				continue
			}
			haystack := c.Name + " " + strings.Join(c.Flags, " ")
			if ok, ver := matchString(cm, haystack); ok {
				return true, ver, fmt.Sprintf("cookie %s (flags: %s)", c.Name, strings.Join(c.Flags, ","))
			}
		}
		return false, "", ""

	case "favicon_mmh3":
		if httpFP == nil || httpFP.FaviconMMH3 == "" {
			return false, "", ""
		}
		if ok, ver := matchString(cm, httpFP.FaviconMMH3); ok {
			return true, ver, fmt.Sprintf("favicon_mmh3=%s", httpFP.FaviconMMH3)
		}
		return false, "", ""

	case "favicon_sha256":
		if httpFP == nil || httpFP.FaviconSHA256 == "" {
			return false, "", ""
		}
		if ok, ver := matchString(cm, httpFP.FaviconSHA256); ok {
			return true, ver, fmt.Sprintf("favicon_sha256=%s", truncate(httpFP.FaviconSHA256, 24))
		}
		return false, "", ""

	case "title":
		if httpFP == nil || httpFP.Title == "" {
			return false, "", ""
		}
		if ok, ver := matchString(cm, httpFP.Title); ok {
			return true, ver, fmt.Sprintf("title=%q", truncate(httpFP.Title, 100))
		}
		return false, "", ""

	case "meta_generator":
		if httpFP == nil || httpFP.MetaGenerator == "" {
			return false, "", ""
		}
		if ok, ver := matchString(cm, httpFP.MetaGenerator); ok {
			return true, ver, fmt.Sprintf("meta[generator]=%q", httpFP.MetaGenerator)
		}
		return false, "", ""

	case "footer_version":
		if httpFP == nil || httpFP.FooterVersion == "" {
			return false, "", ""
		}
		if ok, ver := matchString(cm, httpFP.FooterVersion); ok {
			return true, ver, fmt.Sprintf("footer=%q", httpFP.FooterVersion)
		}
		return false, "", ""

	case "html_body":
		if httpFP == nil {
			return false, "", ""
		}
		haystack := httpFP.BodySnippet
		if haystack == "" {
			haystack = httpFP.Title
		}
		if haystack == "" {
			return false, "", ""
		}
		if ok, ver := matchString(cm, haystack); ok {
			return true, ver, fmt.Sprintf("html match (%s)", truncate(m.Pattern, 64))
		}
		return false, "", ""

	case "url":
		if httpFP == nil || httpFP.URL == "" {
			return false, "", ""
		}
		if ok, ver := matchString(cm, httpFP.URL); ok {
			return true, ver, fmt.Sprintf("url=%s", httpFP.URL)
		}
		return false, "", ""

	case "safe_path":
		if httpFP == nil {
			return false, "", ""
		}
		for _, hit := range httpFP.SafePathHits {
			if len(m.StatusCodes) > 0 && !containsInt(m.StatusCodes, hit.StatusCode) {
				continue
			}
			if m.Key != "" && !strings.EqualFold(hit.Path, m.Key) {
				continue
			}
			target := hit.Path
			if m.Key != "" && m.Pattern != "" && m.Pattern != m.Key {
				target = hit.Path + " " + hit.Title + " " + hit.Snippet
			}
			if ok, ver := matchString(cm, target); ok {
				return true, ver, fmt.Sprintf("safe_path %s -> %d", hit.Path, hit.StatusCode)
			}
		}
		return false, "", ""

	case "tls_cert":
		if httpFP == nil || httpFP.TLS == nil {
			return false, "", ""
		}
		tlsInfo := httpFP.TLS
		switch strings.ToLower(m.Key) {
		case "is_self_signed":
			val := strconv.FormatBool(tlsInfo.IsSelfSigned)
			if ok, ver := matchString(cm, val); ok {
				return true, ver, "tls self-signed certificate"
			}
			return false, "", ""
		case "is_expired":
			val := strconv.FormatBool(tlsInfo.IsExpired)
			if ok, ver := matchString(cm, val); ok {
				return true, ver, fmt.Sprintf("tls certificate expired (%d days)", tlsInfo.DaysToExpiry)
			}
			return false, "", ""
		default:
			combined := strings.Join(append([]string{tlsInfo.SubjectCN, tlsInfo.Issuer}, tlsInfo.SANs...), " ")
			if ok, ver := matchString(cm, combined); ok {
				return true, ver, fmt.Sprintf("tls cert CN=%s Issuer=%s", tlsInfo.SubjectCN, tlsInfo.Issuer)
			}
			return false, "", ""
		}

	case "jarm":
		// JARM equality: exact (case-insensitive) match of the 62-char fingerprint,
		// or a regex (e.g. prefix "^2ad2ad16d" to match a cipher/version pattern).
		if httpFP == nil || httpFP.TLS == nil || httpFP.TLS.JARM == "" {
			return false, "", ""
		}
		j := httpFP.TLS.JARM
		if m.Regex && cm.re != nil {
			if ok, ver := matchString(cm, j); ok {
				return true, ver, "jarm=" + j
			}
			return false, "", ""
		}
		if strings.EqualFold(strings.TrimSpace(m.Pattern), j) {
			return true, "", "jarm=" + j
		}
		return false, "", ""

	case "banner":
		combined := strings.TrimSpace(svc.Banner + " " + svc.Product + " " + svc.Version)
		if combined == "" {
			return false, "", ""
		}
		if ok, ver := matchString(cm, combined); ok {
			return true, ver, fmt.Sprintf("banner=%q", truncate(combined, 100))
		}
		return false, "", ""

	case "port":
		portStr := strconv.Itoa(svc.Port)
		if ok, ver := matchString(cm, portStr); ok {
			return true, ver, fmt.Sprintf("port=%d/%s", svc.Port, svc.Protocol)
		}
		return false, "", ""

	case "service_name":
		if svc.ServiceName == "" {
			return false, "", ""
		}
		if ok, ver := matchString(cm, svc.ServiceName); ok {
			return true, ver, fmt.Sprintf("service=%s", svc.ServiceName)
		}
		return false, "", ""
	}

	return false, "", ""
}

func matchString(cm compiledMatcher, value string) (bool, string) {
	if cm.matcher.Regex && cm.re != nil {
		m := cm.re.FindStringSubmatch(value)
		if len(m) == 0 {
			return false, ""
		}
		var ver string
		if cm.matcher.VersionGroup > 0 && cm.matcher.VersionGroup < len(m) {
			ver = normalizeVersion(strings.TrimSpace(m[cm.matcher.VersionGroup]))
		}
		return true, ver
	}
	if cm.matcher.Pattern == "" {
		return value != "", ""
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(cm.matcher.Pattern)), ""
}

var reDigits = regexp.MustCompile(`[0-9]+`)

// normalizeVersion turns a captured JSON fragment such as 2,"minor":17,"revision":1 (Nginx
// Proxy Manager's /api/ version object) into 2.17.1. Plain versions are returned unchanged.
func normalizeVersion(v string) string {
	if !strings.ContainsAny(v, "\":,") {
		return v
	}
	return strings.Join(reDigits.FindAllString(v, 4), ".")
}

func getHeaderCaseInsensitive(headers map[string]string, key string) string {
	if v, ok := headers[key]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func containsInt(slice []int, v int) bool {
	for _, x := range slice {
		if x == v {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ExportJSON serializes signatures as indented JSON for sharing/backup.
func ExportJSON(sigs []domain.Signature) ([]byte, error) {
	return json.MarshalIndent(sigs, "", "  ")
}

// ImportJSON parses JSON (either an array or a single signature object) and validates every entry.
// It returns the valid signatures, per-item validation errors and any JSON parse error.
func ImportJSON(data []byte) ([]domain.Signature, []string, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil, fmt.Errorf("empty JSON payload")
	}

	var parsed []domain.Signature
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, nil, fmt.Errorf("invalid signatures JSON array: %w", err)
		}
	} else {
		var single domain.Signature
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, nil, fmt.Errorf("invalid signature JSON object: %w", err)
		}
		parsed = []domain.Signature{single}
	}

	var valid []domain.Signature
	var rejected []string
	for i, sig := range parsed {
		sig.IsBuiltin = false
		if sig.MatchMode == "" {
			sig.MatchMode = "any"
		}
		vr := ValidateSignature(sig)
		if !vr.Valid {
			rejected = append(rejected, fmt.Sprintf("signature[%d] (%s): %s", i, sig.Name, strings.Join(vr.Errors, "; ")))
			continue
		}
		valid = append(valid, sig)
	}
	return valid, rejected, nil
}
