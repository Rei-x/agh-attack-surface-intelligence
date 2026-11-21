package intelligence

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

// NoisyOR computes 1 - prod(1 - w_i) for independent evidence weights clamped to [0.01, 0.99].
func NoisyOR(weights []float64) float64 {
	if len(weights) == 0 {
		return 0
	}
	prod := 1.0
	for _, w := range weights {
		if w <= 0 {
			continue
		}
		if w < 0.01 {
			w = 0.01
		}
		if w > 0.99 {
			w = 0.99
		}
		prod *= (1.0 - w)
	}
	return 1.0 - prod
}

// FuseConfidence computes a 0..100 integer confidence using Noisy-OR fusion,
// temporal stability boost (when seen consistently across scans), and conflict dampening.
func FuseConfidence(evidence []domain.TechEvidence, temporalScansSeen int, hasConflict bool) int {
	if len(evidence) == 0 {
		return 0
	}
	weights := make([]float64, 0, len(evidence))
	for _, ev := range evidence {
		if ev.SignalType == "conflict" {
			continue
		}
		weights = append(weights, ev.Weight)
	}
	p := NoisyOR(weights)

	// Temporal stability boost: repeated consistent observations increase confidence smoothly.
	if temporalScansSeen >= 2 && p > 0 {
		extraScans := temporalScansSeen - 1
		if extraScans > 4 {
			extraScans = 4
		}
		boost := 0.03 * float64(extraScans)
		p = 1.0 - (1.0-p)*(1.0-boost)
	}

	// Conflicting signals reduce certainty (e.g. two different versions or contradictory server banners).
	if hasConflict {
		p *= 0.80
	}

	score := int(math.Round(p * 100.0))
	if score < 0 {
		score = 0
	}
	if score > 99 && hasConflict {
		score = 99
	}
	if score > 100 {
		score = 100
	}
	return score
}

type techBucket struct {
	name        string
	category    string
	versions    map[string]int
	evidence    []domain.TechEvidence
	hasConflict bool
}

var (
	reServerToken = regexp.MustCompile(`(?i)\b(nginx|apache|microsoft-iis|caddy|traefik|lighttpd|openresty|envoy|haproxy|gunicorn|uvicorn|werkzeug|jetty|tomcat|cloudflare)(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`)
	rePoweredTok  = regexp.MustCompile(`(?i)\b(php|asp\.net|express|next\.js|django|rails|laravel|python|node\.js)(?:/([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`)
)

// DetectTechnologies fuses signature matches, Nmap/banner metadata, and HTTP evidence
// into deduplicated DetectedTechnology entries scored with Noisy-OR confidence.
func DetectTechnologies(svc domain.ObservedService, sigMatches []signatures.MatchResult, temporalScansSeen int) []domain.DetectedTechnology {
	buckets := make(map[string]*techBucket)

	addSignal := func(rawName, category, version string, ev domain.TechEvidence) {
		canonName, canonCat := canonicalTech(rawName, category)
		if canonName == "" {
			return
		}
		key := strings.ToLower(canonName)
		b, ok := buckets[key]
		if !ok {
			b = &techBucket{
				name:     canonName,
				category: canonCat,
				versions: make(map[string]int),
			}
			buckets[key] = b
		} else if b.category == "custom" && canonCat != "custom" {
			b.category = canonCat
		}
		if v := strings.TrimSpace(version); v != "" {
			b.versions[v]++
		}
		b.evidence = append(b.evidence, ev)
	}

	// 1. Signature engine matches.
	for _, m := range sigMatches {
		if !m.Matched {
			continue
		}
		if len(m.Evidence) == 0 {
			addSignal(m.Signature.Name, m.Signature.Category, m.Version, domain.TechEvidence{
				SignalType: "signature",
				Detail:     fmt.Sprintf("signature %s matched", m.Signature.Name),
				Weight:     m.Signature.ConfidenceWeight,
			})
			continue
		}
		for _, ev := range m.Evidence {
			addSignal(m.Signature.Name, m.Signature.Category, m.Version, ev)
		}
	}

	// 2. Service product / banner from Nmap or TCP probe.
	if strings.TrimSpace(svc.Product) != "" {
		detail := fmt.Sprintf("product=%s", svc.Product)
		if svc.Version != "" {
			detail += " version=" + svc.Version
		}
		addSignal(svc.Product, guessCategoryFromService(svc.Product, svc.ServiceName), svc.Version, domain.TechEvidence{
			SignalType: "banner",
			Detail:     detail,
			Weight:     0.78,
		})
	}

	// 3. Direct HTTP fingerprint clues (Server, X-Powered-By, MetaGenerator).
	if svc.HTTP != nil {
		if svc.HTTP.ServerHeader != "" {
			for _, m := range reServerToken.FindAllStringSubmatch(svc.HTTP.ServerHeader, 4) {
				ver := ""
				if len(m) > 2 {
					ver = m[2]
				}
				addSignal(m[1], "server", ver, domain.TechEvidence{
					SignalType: "header",
					Detail:     "Server: " + svc.HTTP.ServerHeader,
					Weight:     0.72,
				})
			}
		}
		if powered := headerCI(svc.HTTP.Headers, "X-Powered-By"); powered != "" {
			for _, m := range rePoweredTok.FindAllStringSubmatch(powered, 4) {
				ver := ""
				if len(m) > 2 {
					ver = m[2]
				}
				addSignal(m[1], "framework", ver, domain.TechEvidence{
					SignalType: "header",
					Detail:     "X-Powered-By: " + powered,
					Weight:     0.68,
				})
			}
		}
	}

	// Detect mutually exclusive web server conflicts (e.g. Microsoft IIS + Apache + Nginx simultaneously).
	webServerKeys := []string{"microsoft iis", "apache http server"}
	var presentServers []string
	for _, k := range webServerKeys {
		if _, ok := buckets[k]; ok {
			presentServers = append(presentServers, buckets[k].name)
		}
	}
	if len(presentServers) > 1 {
		for _, k := range webServerKeys {
			if b, ok := buckets[k]; ok {
				b.hasConflict = true
				b.evidence = append(b.evidence, domain.TechEvidence{
					SignalType: "conflict",
					Detail:     fmt.Sprintf("conflicting server signals observed simultaneously: %s", strings.Join(presentServers, " vs ")),
					Weight:     0,
				})
			}
		}
	}

	out := make([]domain.DetectedTechnology, 0, len(buckets))
	for _, b := range buckets {
		version, versionConflict := resolveVersion(b.versions)
		if versionConflict {
			b.hasConflict = true
			vers := sortedKeys(b.versions)
			b.evidence = append(b.evidence, domain.TechEvidence{
				SignalType: "conflict",
				Detail:     fmt.Sprintf("conflicting versions reported: %s", strings.Join(vers, ", ")),
				Weight:     0,
			})
		}

		dedupEv := dedupeEvidence(b.evidence)
		conf := FuseConfidence(dedupEv, temporalScansSeen, b.hasConflict)
		out = append(out, domain.DetectedTechnology{
			Name:       b.name,
			Category:   b.category,
			Version:    version,
			Confidence: conf,
			Evidence:   dedupEv,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Name < out[j].Name
	})

	return out
}

// EnrichService runs signature evaluation, technology fusion, flags, cluster key, and scoring on a Service.
func EnrichService(svc *domain.Service, obs domain.ObservedService, sigEngine *signatures.Engine, temporalScansSeen int) []signatures.MatchResult {
	var matches []signatures.MatchResult
	if sigEngine != nil {
		matches = sigEngine.Evaluate(obs)
	}

	svc.Technologies = DetectTechnologies(obs, matches, temporalScansSeen)

	sigNames := make([]string, 0, len(matches))
	for _, m := range matches {
		sigNames = append(sigNames, m.Signature.Name)
		switch m.Signature.Category {
		case "admin_panel":
			svc.IsAdminPanel = true
		case "staging":
			svc.IsStagingEnv = true
		case "iot":
			svc.IsIoT = true
		}
	}
	svc.MatchedSignatures = sigNames

	// Also mark admin/staging from HTTP safe paths or title heuristics.
	if svc.HTTP != nil {
		for _, hit := range svc.HTTP.SafePathHits {
			p := strings.ToLower(hit.Path)
			if p == "/admin" || p == "/wp-login.php" || p == "/phpmyadmin" {
				svc.IsAdminPanel = true
			}
		}
		tl := strings.ToLower(svc.HTTP.Title + " " + svc.HTTP.URL)
		if strings.Contains(tl, "staging") || strings.Contains(tl, "dev.") || strings.Contains(tl, "test.") {
			svc.IsStagingEnv = true
		}
	}

	svc.ClusterKey = ComputeServiceClusterKey(*svc)
	score, factors := ScoreService(svc, matches)
	svc.Interestingness = score
	svc.InterestingFactors = factors

	return matches
}

func canonicalTech(raw, category string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", category
	}
	sl := strings.ToLower(s)
	switch sl {
	case "nginx":
		return "Nginx", "server"
	case "apache", "apache httpd", "apache http server":
		return "Apache HTTP Server", "server"
	case "microsoft-iis", "iis", "microsoft iis":
		return "Microsoft IIS", "server"
	case "tomcat", "apache tomcat":
		return "Apache Tomcat", "server"
	case "openssh":
		return "OpenSSH", "server"
	case "php":
		return "PHP", "framework"
	case "next.js", "nextjs":
		return "Next.js", "framework"
	case "asp.net", "aspnet":
		return "ASP.NET", "framework"
	case "express":
		return "Express", "framework"
	case "werkzeug":
		return "Flask", "framework"
	case "wordpress":
		return "WordPress", "cms"
	case "drupal":
		return "Drupal", "cms"
	case "moodle":
		return "Moodle", "cms"
	case "grafana":
		return "Grafana", "server"
	case "gitlab":
		return "GitLab", "server"
	case "jenkins":
		return "Jenkins", "admin_panel"
	case "phpmyadmin":
		return "phpMyAdmin", "admin_panel"
	}
	if category == "" {
		category = "custom"
	}
	return s, category
}

func guessCategoryFromService(product, serviceName string) string {
	pl := strings.ToLower(product + " " + serviceName)
	switch {
	case strings.Contains(pl, "printer") || strings.Contains(pl, "jetdirect") || strings.Contains(pl, "mikrotik") || strings.Contains(pl, "hikvision"):
		return "iot"
	case strings.Contains(pl, "wordpress") || strings.Contains(pl, "drupal") || strings.Contains(pl, "moodle"):
		return "cms"
	default:
		return "server"
	}
}

func resolveVersion(versions map[string]int) (string, bool) {
	if len(versions) == 0 {
		return "", false
	}
	if len(versions) == 1 {
		for v := range versions {
			return v, false
		}
	}
	// Multiple versions: pick highest count / longest (most specific), and check if they conflict.
	vers := sortedKeys(versions)
	best := vers[0]
	for _, v := range vers[1:] {
		if versions[v] > versions[best] || (versions[v] == versions[best] && len(v) > len(best)) {
			best = v
		}
	}
	// Check if one is simply a prefix of another (e.g. "6.4" vs "6.4.2" is NOT a conflict).
	conflict := false
	for _, v := range vers {
		if !strings.HasPrefix(best, v) && !strings.HasPrefix(v, best) {
			conflict = true
			break
		}
	}
	return best, conflict
}

func dedupeEvidence(in []domain.TechEvidence) []domain.TechEvidence {
	seen := make(map[string]struct{}, len(in))
	out := make([]domain.TechEvidence, 0, len(in))
	for _, ev := range in {
		key := ev.SignalType + "|" + ev.Detail
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ev)
	}
	return out
}

func headerCI(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
