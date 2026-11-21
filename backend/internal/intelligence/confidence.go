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

// Evidence channels and their likelihood weights.
//
// In the noisy-OR model each piece of evidence i is an independent "cause" that
// would reveal the technology with probability w_i, so
//
//	P(tech | evidence) = 1 - prod_channels (1 - w_channel)
//
// Two corrections make it honest:
//  1. Evidence from the SAME channel is correlated (three regexes over one HTML
//     body are not three independent witnesses). Within a channel we noisy-OR the
//     items but never exceed the channel cap; only DIFFERENT channels multiply.
//  2. Each channel's cap is its calibrated reliability: the observed precision of
//     detections supported by that channel alone (lab/scale ground truth, see
//     cmd/calibrate and docs/RESEARCH.md), bounded by a policy ceiling of 0.80 for
//     anything a single HTTP response can fake. So one weak signal (a safe-path
//     hit, a generic header) can never exceed 80%; >80% needs corroboration from
//     an independent channel or a protocol banner.
//
// A signature's own confidence_weight expresses its specificity and is used as
// the item weight, clamped by the cap of the channel it matched on.
type ChannelWeight struct {
	Cap       float64 // maximum weight of this channel alone
	Rationale string
}

// EvidenceChannels documents the likelihood weight of every evidence type.
var EvidenceChannels = map[string]ChannelWeight{
	"banner":    {0.90, "nmap -sV / protocol banner: the service identifies itself on its own protocol"},
	"favicon":   {0.80, "exact favicon MMH3/SHA-256 of a vendor product; favicons are sometimes copied"},
	"header":    {0.80, "Server / X-Powered-By / vendor headers; lab precision 100% (n=1420) but headers are trivially rewritten by proxies/WAFs -> policy ceiling"},
	"html":      {0.80, "meta generator / title / body markers; lab precision 88% (n=252)"},
	"cookie":    {0.75, "framework session-cookie names; lab precision 100% (n=44), generic names collide"},
	"tls":       {0.60, "certificate CN/issuer or JARM: identifies the TLS stack or vendor appliance, not the application"},
	"path":      {0.25, "a safe-path hit (status/title of e.g. /metrics) alone; lab precision 0% (n=23, Grafana also serves /metrics): many apps expose the same paths"},
	"signature": {0.70, "signature without a typed matcher"},
}

// SingleChannelCeiling is the maximum confidence any single non-banner channel can produce.
const SingleChannelCeiling = 0.80

func channelCap(signalType string) float64 {
	if c, ok := EvidenceChannels[signalType]; ok {
		return c.Cap
	}
	return EvidenceChannels["signature"].Cap
}

type channelScore struct {
	name string
	w    float64
}

// fuseChannels groups evidence per channel (within-channel noisy-OR, capped) and
// returns channel scores sorted by weight (descending).
func fuseChannels(evidence []domain.TechEvidence) []channelScore {
	byCh := map[string][]float64{}
	for _, ev := range evidence {
		if ev.SignalType == "conflict" || ev.Weight <= 0 {
			continue
		}
		cp := channelCap(ev.SignalType)
		w := ev.Weight
		if w > cp {
			w = cp
		}
		byCh[ev.SignalType] = append(byCh[ev.SignalType], w)
	}
	out := make([]channelScore, 0, len(byCh))
	for ch, ws := range byCh {
		w := NoisyOR(ws)
		if cp := channelCap(ch); w > cp {
			w = cp
		}
		out = append(out, channelScore{ch, w})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].w != out[j].w {
			return out[i].w > out[j].w
		}
		return out[i].name < out[j].name
	})
	return out
}

// FuseConfidence computes a 0..100 integer confidence using channel-aware Noisy-OR
// fusion, a small temporal stability boost and conflict dampening.
func FuseConfidence(evidence []domain.TechEvidence, temporalScansSeen int, hasConflict bool) int {
	score, _ := FuseConfidenceExplained(evidence, temporalScansSeen, hasConflict)
	return score
}

// FuseConfidenceExplained is FuseConfidence plus a human-readable derivation.
func FuseConfidenceExplained(evidence []domain.TechEvidence, temporalScansSeen int, hasConflict bool) (int, string) {
	chans := fuseChannels(evidence)
	if len(chans) == 0 {
		return 0, ""
	}
	weights := make([]float64, len(chans))
	terms := make([]string, len(chans))
	factors := make([]string, len(chans))
	for i, c := range chans {
		weights[i] = c.w
		terms[i] = fmt.Sprintf("%s %.2f", c.name, c.w)
		factors[i] = fmt.Sprintf("%.2f", 1-c.w)
	}
	p := NoisyOR(weights)
	expl := fmt.Sprintf("%s → 1-(%s) = %d%%", strings.Join(terms, " ⊕ "), strings.Join(factors, "·"), int(math.Round(p*100)))

	// Temporal stability: the same evidence seen again in later scans adds a little
	// certainty (it is not independent evidence, hence small and bounded).
	if temporalScansSeen >= 2 && p > 0 {
		extraScans := temporalScansSeen - 1
		if extraScans > 4 {
			extraScans = 4
		}
		boost := 0.03 * float64(extraScans)
		p = 1.0 - (1.0-p)*(1.0-boost)
		expl += fmt.Sprintf("; stable across %d scans +%.0f%%", temporalScansSeen, boost*100)
	}
	// One channel alone never exceeds its cap / the single-channel ceiling.
	if len(chans) == 1 {
		ceil := chans[0].w
		if chans[0].name != "banner" && ceil > SingleChannelCeiling {
			ceil = SingleChannelCeiling
		}
		if p > ceil {
			p = ceil
			expl += fmt.Sprintf("; single channel → cap %.0f%%", ceil*100)
		}
	}
	// Conflicting signals reduce certainty (two versions / contradictory servers).
	if hasConflict {
		p *= 0.80
		expl += "; conflicting signals ×0.8"
	}

	score := int(math.Round(p * 100.0))
	if score < 0 {
		score = 0
	}
	if score > 99 {
		score = 99 // never claim certainty
	}
	return score, expl + fmt.Sprintf(" ⇒ %d%%", score)
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

	// 2. Service product / banner from Nmap or TCP probe. A generic nmap answer
	// ("Golang net/http server" is a guess from how the stack answers malformed probes)
	// is dropped once the HTTP layer identified the server or the application itself.
	httpIdentified := len(buckets) > 0 || (svc.HTTP != nil && IdentifyProduct(svc).Source != SourceNmap)
	if strings.TrimSpace(svc.Product) != "" && !(genericNmapProducts[strings.ToLower(strings.TrimSpace(svc.Product))] && httpIdentified) {
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
					Weight:     0.80, // calibrated: lab precision 100% -> channel cap
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
					Weight:     0.78, // calibrated: lab precision 100%, slightly below Server (often proxied/stale)
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
		conf, expl := FuseConfidenceExplained(dedupEv, temporalScansSeen, b.hasConflict)
		out = append(out, domain.DetectedTechnology{
			Name:        b.name,
			Category:    b.category,
			Version:     version,
			Confidence:  conf,
			Evidence:    dedupEv,
			Explanation: expl,
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
		matches = dropDefaultTestPageStaging(sigEngine.Evaluate(obs), obs)
	}

	svc.Technologies = DetectTechnologies(obs, matches, temporalScansSeen)

	sigNames := make([]string, 0, len(matches))
	for _, m := range matches {
		sigNames = append(sigNames, m.Signature.Name)
		switch m.Signature.Category {
		case "admin_panel":
			// Built-in admin signatures only contribute identity; whether the service
			// really exposes a console is decided by AdminPanelEvidence below (a database
			// port, a generic login or an /admin redirect is not an admin panel).
			// Analyst-written signatures keep their declared meaning.
			if !m.Signature.IsBuiltin {
				svc.IsAdminPanel = true
			}
		case "staging":
			svc.IsStagingEnv = true
		case "iot", "bmc":
			svc.IsIoT = true
		}
	}
	svc.MatchedSignatures = sigNames

	if reason := AdminPanelEvidence(obs, svc.Technologies); reason != "" {
		svc.IsAdminPanel = true
		svc.Technologies = addFlagEvidence(svc.Technologies, "Admin Panel / Management Console", "admin_panel", reason)
	}
	if reason := StagingEvidence(obs); reason != "" {
		svc.IsStagingEnv = true
		svc.Technologies = addFlagEvidence(svc.Technologies, "Staging / Dev / Test Environment", "staging", reason)
	}
	if svc.HTTP != nil {
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

// addFlagEvidence records why a flag was raised as evidence on the matching generic
// finding (creating it when no signature produced one), so the UI can show the reason.
func addFlagEvidence(techs []domain.DetectedTechnology, name, category, reason string) []domain.DetectedTechnology {
	ev := domain.TechEvidence{SignalType: "html", Detail: reason, Weight: 0.8}
	for i := range techs {
		if strings.EqualFold(techs[i].Name, name) {
			for _, e := range techs[i].Evidence {
				if e.Detail == reason {
					return techs
				}
			}
			techs[i].Evidence = append(techs[i].Evidence, ev)
			return techs
		}
	}
	conf, expl := FuseConfidenceExplained([]domain.TechEvidence{ev}, 1, false)
	return append(techs, domain.DetectedTechnology{
		Name: name, Category: category, Confidence: conf, Evidence: []domain.TechEvidence{ev}, Explanation: expl,
	})
}

func canonicalTech(raw, category string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", category
	}
	sl := strings.ToLower(s)
	// nmap product names of daemons whose technology has a plainer name.
	switch {
	case strings.HasPrefix(sl, "mikrotik routeros") || strings.HasPrefix(sl, "mikrotik router"):
		return "MikroTik RouterOS", "iot"
	case strings.HasPrefix(sl, "hikvision"):
		return "Hikvision IP Camera / NVR", "iot"
	case sl == "debut embedded httpd": // Brother printers' embedded web server
		return "Brother Printer Web Interface", "iot"
	case sl == "hp http server" || sl == "hp-chaisoe" || strings.HasPrefix(sl, "hp jetdirect"):
		return "HP Printer / Embedded Web Server", "iot"
	case strings.HasPrefix(sl, "dovecot"):
		return "Dovecot", "server"
	}
	switch sl {
	case "microsoft iis httpd":
		return "Microsoft IIS", "server"
	case "apache tomcat/coyote jsp engine":
		return "Apache Tomcat", "server"
	case "postgresql db", "postgresql":
		return "PostgreSQL", "server"
	case "exim smtpd":
		return "Exim", "server"
	case "postfix smtpd":
		return "Postfix", "server"
	case "redis key-value store", "redis":
		return "Redis", "server"
	case "mysql":
		return "MySQL", "server"
	case "mariadb":
		return "MariaDB", "server"
	case "jetty":
		return "Jetty", "server"
	case "elasticsearch rest api":
		return "Elasticsearch", "server"
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
