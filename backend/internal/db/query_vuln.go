package db

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	_ "github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb" // registers the CVE annotator
)

// Vulnerability-intelligence query terms (internal/vulndb, internal/verify):
//
//	cve:CVE-2021-41773   a service matched to that CVE (cve:true = any known CVE)
//	kev:true             a matched CVE is in CISA KEV (exploited in the wild)
//	epss>0.5             highest EPSS probability above 0.5 (also epss:>=0.1, epss<0.01)
//	cvss>=9              highest CVSS score of the matched CVEs
//	verified:true        confirmed by a safe verification check
//
// "possible" matches on an incomplete version count too: the badge in the UI carries the
// confidence. Matches ruled out by the protocol probe (a Rapid Reset CVE on a server with
// HTTP/2 off, VulnSummary.Suppressed) and matches on a distribution package whose fix may be
// backported (VulnSummary.Backported) never count.

var reComparison = regexp.MustCompile(`^(-?)(epss|cvss)(>=|<=|>|<|=)(.+)$`)

// normalizeComparison rewrites "epss>0.5" as "epss:>0.5" so the key:value parser sees it.
func normalizeComparison(raw string) string {
	m := reComparison.FindStringSubmatch(strings.ToLower(raw))
	if m == nil {
		return raw
	}
	return m[1] + m[2] + ":" + m[3] + m[4]
}

func compileVulnTerm(t *QueryTerm) error {
	v := t.Values[0]
	switch t.Key {
	case "kev", "verified":
		return compileBool(t)
	case "cve":
		if v == "true" || v == "false" || v == "yes" || v == "no" || v == "1" || v == "0" {
			return compileBool(t)
		}
		for i, id := range t.Values {
			t.Values[i] = strings.ToUpper(id)
		}
		return nil
	case "epss", "cvss":
		op := ">="
		for _, p := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(v, p) {
				op, v = p, strings.TrimPrefix(v, p)
				break
			}
		}
		pct := strings.HasSuffix(v, "%")
		n, err := strconv.ParseFloat(strings.TrimSuffix(v, "%"), 64)
		if err != nil {
			return fmt.Errorf("%s: expected a number, e.g. %s>=%s", t.Key, t.Key, map[string]string{"epss": "0.5", "cvss": "9"}[t.Key])
		}
		if t.Key == "epss" && (pct || n > 1) {
			n /= 100 // epss>50% or epss>50
		}
		t.op, t.threshold = op, n
	}
	return nil
}

func compileBool(t *QueryTerm) error {
	switch t.Values[0] {
	case "true", "yes", "1", "tak":
		t.Values = []string{"true"}
	case "false", "no", "0", "nie":
		t.Values = []string{"false"}
	default:
		return fmt.Errorf("%s: expected true/false", t.Key)
	}
	return nil
}

func compare(x float64, op string, y float64) bool {
	switch op {
	case ">":
		return x > y
	case "<":
		return x < y
	case "<=":
		return x <= y
	case "=":
		return x == y
	}
	return x >= y
}

// annotated returns a copy of s with the read-time derived fields filled in.
func annotated(s *domain.Service, now time.Time) domain.Service {
	cp := *s
	if cp.Vulns == nil && cp.Verified == nil {
		eol.Annotate(&cp, now)
	}
	return cp
}

func hasKnownCVE(s *domain.Service, now time.Time) bool {
	cp := annotated(s, now)
	return len(cp.KnownVulns) > 0 || domain.AnyVulnFindings(cp.Vulns)
}

func (t *QueryTerm) matchVulnTerm(s *domain.Service, now time.Time) bool {
	cp := annotated(s, now)
	switch t.Key {
	case "verified":
		return (len(cp.Verified) > 0) == (t.Values[0] == "true")
	case "kev":
		kev := false
		for _, v := range cp.Vulns {
			kev = kev || v.KEV > 0
		}
		return kev == (t.Values[0] == "true")
	case "cve":
		if len(t.Values) == 1 && (t.Values[0] == "true" || t.Values[0] == "false") {
			return (len(cp.KnownVulns) > 0 || domain.AnyVulnFindings(cp.Vulns)) == (t.Values[0] == "true")
		}
		for _, want := range t.Values {
			for _, v := range cp.Vulns {
				for _, id := range v.CVEIDs {
					if id == want {
						return true
					}
				}
			}
			for _, h := range cp.KnownVulns {
				if h.ID == want {
					return true
				}
			}
		}
		return false
	case "epss", "cvss":
		if !domain.AnyVulnFindings(cp.Vulns) {
			return false
		}
		best := 0.0
		for _, v := range cp.Vulns {
			if v.Total == 0 {
				continue
			}
			x := v.MaxCVSS
			if t.Key == "epss" {
				x = v.MaxEPSS
			}
			if x > best {
				best = x
			}
		}
		return compare(best, t.op, t.threshold)
	}
	return false
}
