package db

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
)

// Asset search query language (Shodan-like), evaluated server-side by both stores for the
// hosts and services list endpoints (the `q` parameter):
//
//	port:3389 tech:wordpress tag:wi state:new cidr:10.66.0.0/24 env:staging title:"admin" cert:expired
//	eol:true (end-of-life version, offline table in internal/eol) vuln:true (passive known-CVE hint)
//	db:true (exposed database) iot:true staging:true cleartext:true (telnet/ftp/r-services)
//	violation:true (open zone policy violation) policy:<zone name, rule or category>
//
// Terms are AND-ed. A comma inside a value is an OR (port:80,443). A leading "-" negates a
// term (-env:prod). Quoted values may contain spaces. Anything that is not a known key:value
// pair is free text, matched as a substring against IP, hostname, domains, notes, owner,
// tags, banners, products, technologies and HTTP titles (each word must match).
//
// Service-level terms (port, tech, title, cert, service, product, version, admin, triage)
// must all be satisfied by the SAME service of a host, so "port:443 tech:wordpress" means
// WordPress on 443, not WordPress anywhere plus something on 443.

// QueryTerm is a single key:value condition.
type QueryTerm struct {
	Key    string   `json:"key"`
	Values []string `json:"values"` // OR-ed
	Negate bool     `json:"negate,omitempty"`

	nets    []*net.IPNet
	ports   []int
	minimum int
}

// AssetQuery is a parsed search expression.
type AssetQuery struct {
	Terms []QueryTerm `json:"terms"`
	Text  []string    `json:"text"`
}

// queryKeyAliases maps accepted keys to their canonical form.
var queryKeyAliases = map[string]string{
	"port":     "port",
	"tech":     "tech",
	"tag":      "tag",
	"state":    "state",
	"cidr":     "cidr",
	"net":      "cidr",
	"ip":       "cidr",
	"env":      "env",
	"title":    "title",
	"cert":     "cert",
	"tls":      "cert",
	"service":  "service",
	"svc":      "service",
	"product":  "product",
	"version":  "version",
	"owner":    "owner",
	"hostname": "hostname",
	"host":     "hostname",
	"os":       "os",
	"triage":   "triage",
	"admin":    "admin",
	"score":    "score",
	"eol":      "eol",
	"outdated": "eol",
	"vuln":     "vuln",
	"cve":      "vuln",
	// Quick-filter flags (one-click chips in the asset list).
	"db":        "db",
	"database":  "db",
	"iot":       "iot",
	"staging":   "staging",
	"cleartext": "cleartext",
	"plaintext": "cleartext",
	// Zone policies (internal/policy).
	"violation":  "violation",
	"violations": "violation",
	"policy":     "policy",
	"zone":       "policy",
}

// serviceLevelKeys are evaluated per service (all must match one service).
var serviceLevelKeys = map[string]bool{
	"port": true, "tech": true, "title": true, "cert": true, "service": true,
	"product": true, "version": true, "admin": true, "eol": true, "vuln": true,
	"db": true, "iot": true, "staging": true, "cleartext": true,
}

// QueryKeys lists the canonical keys (used by the UI help and error messages).
var QueryKeys = []string{"port", "tech", "tag", "state", "cidr", "env", "title", "cert", "service", "product", "version", "owner", "hostname", "os", "triage", "admin", "score", "eol", "vuln", "db", "iot", "staging", "cleartext", "violation", "policy"}

// ParseAssetQuery parses a search expression. It returns an error for malformed values of
// known keys (bad port, bad CIDR, unknown cert condition, unterminated quote) so the API can
// answer 400 instead of silently matching nothing.
func ParseAssetQuery(input string) (*AssetQuery, error) {
	tokens, err := tokenizeQuery(input)
	if err != nil {
		return nil, err
	}
	q := &AssetQuery{}
	for _, tok := range tokens {
		raw := tok.text
		neg := false
		if !tok.quoted && strings.HasPrefix(raw, "-") && len(raw) > 1 && strings.Contains(raw, ":") {
			neg = true
			raw = raw[1:]
		}
		idx := strings.Index(raw, ":")
		if tok.quoted || idx <= 0 {
			if t := strings.ToLower(strings.TrimSpace(tok.text)); t != "" {
				q.Text = append(q.Text, t)
			}
			continue
		}
		key, ok := queryKeyAliases[strings.ToLower(raw[:idx])]
		if !ok {
			// Not a known key (e.g. "http://x" or "10.0.0.1:80"): free text.
			q.Text = append(q.Text, strings.ToLower(tok.text))
			continue
		}
		val := strings.TrimSpace(raw[idx+1:])
		if val == "" {
			return nil, fmt.Errorf("empty value for %q", key+":")
		}
		term := QueryTerm{Key: key, Negate: neg}
		if key == "title" || key == "owner" {
			term.Values = []string{strings.ToLower(val)}
		} else {
			for _, v := range strings.Split(val, ",") {
				if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
					term.Values = append(term.Values, v)
				}
			}
		}
		if err := compileTerm(&term); err != nil {
			return nil, err
		}
		q.Terms = append(q.Terms, term)
	}
	return q, nil
}

type queryToken struct {
	text   string
	quoted bool // whole token was a quoted phrase
}

// quoteClosers maps an opening quote to the quotes that may close it. Typographic quotes
// are accepted because values pasted from chat or docs (tech:„Server BMC”, tech:“Server
// BMC”) otherwise end up as a literal quote character and silently match nothing.
var quoteClosers = map[rune]string{
	'"':  `"”“`,
	'\'': `'`,
	'“':  `”“"`,
	'”':  `”"`,
	'„':  `”“"`,
	'«':  `»"`,
}

func tokenizeQuery(s string) ([]queryToken, error) {
	var out []queryToken
	var cur strings.Builder
	closers := "" // non-empty while inside a quoted phrase
	wholeQuoted := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, queryToken{text: cur.String(), quoted: wholeQuoted})
		}
		cur.Reset()
		wholeQuoted = false
	}
	for _, r := range s {
		switch {
		case closers != "":
			if strings.ContainsRune(closers, r) {
				closers = ""
			} else {
				cur.WriteRune(r)
			}
		case quoteClosers[r] != "" && quoteMayOpen(r, cur.String()):
			if cur.Len() == 0 {
				wholeQuoted = true
			}
			closers = quoteClosers[r]
		case r == ' ' || r == '\t' || r == '\n':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	if closers != "" {
		return nil, fmt.Errorf("unterminated quote in query")
	}
	flush()
	return out, nil
}

// quoteMayOpen: a quote opens a phrase at the start of a token, after "key:" or after a
// comma inside a list value. An apostrophe inside a word ("o'reilly") stays literal.
func quoteMayOpen(r rune, cur string) bool {
	if cur == "" || cur == "-" || strings.HasSuffix(cur, ":") || strings.HasSuffix(cur, ",") {
		return true
	}
	return r != '\''
}

func compileTerm(t *QueryTerm) error {
	switch t.Key {
	case "port":
		for _, v := range t.Values {
			p, err := strconv.Atoi(v)
			if err != nil || p < 0 || p > 65535 {
				return fmt.Errorf("invalid port %q", v)
			}
			t.ports = append(t.ports, p)
		}
	case "cidr":
		for _, v := range t.Values {
			if !strings.Contains(v, "/") {
				ip := net.ParseIP(v)
				if ip == nil {
					return fmt.Errorf("invalid address/CIDR %q", v)
				}
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				v = fmt.Sprintf("%s/%d", v, bits)
			}
			_, n, err := net.ParseCIDR(v)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q", v)
			}
			t.nets = append(t.nets, n)
		}
	case "cert":
		for _, v := range t.Values {
			switch v {
			case "expired", "selfsigned", "self-signed", "expiring", "any", "valid":
			default:
				return fmt.Errorf("cert: use expired, expiring, selfsigned, valid or any (got %q)", v)
			}
		}
	case "score":
		v := strings.TrimLeft(t.Values[0], ">=")
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("score: expected a number, e.g. score:>=70")
		}
		t.minimum = n
	case "admin", "eol", "vuln", "db", "iot", "staging", "cleartext", "violation":
		switch t.Values[0] {
		case "true", "yes", "1", "tak":
			t.Values = []string{"true"}
		case "false", "no", "0", "nie":
			t.Values = []string{"false"}
		default:
			return fmt.Errorf("%s: expected true/false", t.Key)
		}
	}
	return nil
}

// MatchHost evaluates the query against a host (with its services loaded).
func (q *AssetQuery) MatchHost(h *domain.Host) bool {
	if q == nil {
		return true
	}
	now := time.Now()
	var svcTerms []QueryTerm
	for i := range q.Terms {
		t := &q.Terms[i]
		if serviceLevelKeys[t.Key] {
			svcTerms = append(svcTerms, *t)
			continue
		}
		if t.matchHostLevel(h, now) == t.Negate {
			return false
		}
	}
	if len(svcTerms) > 0 {
		found := false
		for i := range h.Services {
			if matchServiceTerms(&h.Services[i], svcTerms, now) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, word := range q.Text {
		if !hostMatchesQuery(h, word) && !hostHasPortText(h, word) {
			return false
		}
	}
	return true
}

// hostHasPortText lets a bare number in free text match an open port ("rdp 3389").
func hostHasPortText(h *domain.Host, word string) bool {
	p, err := strconv.Atoi(word)
	if err != nil {
		return false
	}
	for i := range h.Services {
		if h.Services[i].Port == p {
			return true
		}
	}
	return false
}

// MatchService evaluates the query against a single service. Host-only terms that the
// service cannot answer (env, owner, hostname, os) are ignored; state matches the service
// port state (open/closed); cidr matches the service's host IP.
func (q *AssetQuery) MatchService(s *domain.Service) bool {
	if q == nil {
		return true
	}
	now := time.Now()
	for i := range q.Terms {
		t := &q.Terms[i]
		var ok bool
		switch t.Key {
		case "env", "owner", "hostname", "os":
			continue
		case "state":
			ok = anyEqual(t.Values, s.State)
		case "cidr":
			ok = t.ipInNets(s.HostIP)
		case "tag":
			ok = anyTag(t.Values, s.Tags)
		case "score":
			ok = s.Interestingness >= t.minimum
		case "triage":
			ok = anyEqual(t.Values, effectiveTriage(s.TriageStatus))
		default:
			ok = t.matchService(s, now)
		}
		if ok == t.Negate {
			return false
		}
	}
	for _, word := range q.Text {
		if !serviceMatchesQuery(s, word) && strconv.Itoa(s.Port) != word {
			return false
		}
	}
	return true
}

func matchServiceTerms(s *domain.Service, terms []QueryTerm, now time.Time) bool {
	for i := range terms {
		if terms[i].matchService(s, now) == terms[i].Negate {
			return false
		}
	}
	return true
}

func (t *QueryTerm) matchHostLevel(h *domain.Host, now time.Time) bool {
	switch t.Key {
	case "tag":
		if anyTag(t.Values, h.Tags) {
			return true
		}
		for i := range h.Services {
			if anyTag(t.Values, h.Services[i].Tags) {
				return true
			}
		}
		return false
	case "state":
		return anyEqual(t.Values, h.LifecycleState)
	case "cidr":
		return t.ipInNets(h.IP)
	case "env":
		return anyEqual(t.Values, h.Environment)
	case "owner":
		return strings.Contains(strings.ToLower(h.Owner), t.Values[0])
	case "hostname":
		hn := strings.ToLower(h.Hostname)
		for _, v := range t.Values {
			if strings.Contains(hn, v) {
				return true
			}
			for _, d := range h.Domains {
				if strings.Contains(strings.ToLower(d), v) {
					return true
				}
			}
		}
		return false
	case "os":
		return anyContains(t.Values, h.OSGuess)
	case "score":
		return h.Interestingness >= t.minimum
	case "violation", "policy":
		return t.matchPolicyTerm(h.ID, "")
	case "triage":
		// Host decision or any service decision.
		if anyEqual(t.Values, effectiveTriage(h.TriageStatus)) && h.TriageStatus != "" {
			return true
		}
		for i := range h.Services {
			if anyEqual(t.Values, effectiveTriage(h.Services[i].TriageStatus)) {
				return true
			}
		}
		return false
	}
	return false
}

func (t *QueryTerm) matchService(s *domain.Service, now time.Time) bool {
	switch t.Key {
	case "port":
		for _, p := range t.ports {
			if s.Port == p {
				return true
			}
		}
		return false
	case "tech":
		for _, v := range t.Values {
			for _, tech := range s.Technologies {
				if strings.Contains(strings.ToLower(tech.Name), v) {
					return true
				}
			}
			for _, sig := range s.MatchedSignatures {
				if strings.Contains(strings.ToLower(sig), v) {
					return true
				}
			}
			if strings.Contains(strings.ToLower(s.Product), v) {
				return true
			}
		}
		return false
	case "db":
		return IsDatabaseService(s) == (t.Values[0] == "true")
	case "iot":
		return s.IsIoT == (t.Values[0] == "true")
	case "staging":
		return s.IsStagingEnv == (t.Values[0] == "true")
	case "cleartext":
		return IsCleartextAdminService(s) == (t.Values[0] == "true")
	case "title":
		return s.HTTP != nil && strings.Contains(strings.ToLower(s.HTTP.Title), t.Values[0])
	case "service":
		return anyContains(t.Values, s.ServiceName)
	case "product":
		return anyContains(t.Values, s.Product)
	case "version":
		if anyContains(t.Values, s.Version) {
			return true
		}
		// Technology versions too (WordPress 6.4.3 runs on a service whose banner is Apache's).
		for _, tech := range s.Technologies {
			if anyContains(t.Values, tech.Version) {
				return true
			}
		}
		return false
	case "admin":
		return s.IsAdminPanel == (t.Values[0] == "true")
	case "eol", "vuln":
		outdated, hints := eol.Assess(s, now)
		if t.Key == "eol" {
			return (len(outdated) > 0) == (t.Values[0] == "true")
		}
		return (len(hints) > 0) == (t.Values[0] == "true")
	case "cert":
		if s.HTTP == nil || s.HTTP.TLS == nil {
			return false
		}
		tls := s.HTTP.TLS
		expired := tls.IsExpired || (!tls.NotAfter.IsZero() && now.After(tls.NotAfter))
		for _, v := range t.Values {
			switch v {
			case "any":
				return true
			case "expired":
				if expired {
					return true
				}
			case "expiring":
				if !expired && !tls.NotAfter.IsZero() && tls.NotAfter.Sub(now) < 30*24*time.Hour {
					return true
				}
			case "selfsigned", "self-signed":
				if tls.IsSelfSigned {
					return true
				}
			case "valid":
				if !expired && !tls.IsSelfSigned {
					return true
				}
			}
		}
		return false
	case "triage":
		return anyEqual(t.Values, effectiveTriage(s.TriageStatus))
	case "violation", "policy":
		return t.matchPolicyTerm(s.HostID, s.ID)
	}
	return false
}

func (t *QueryTerm) ipInNets(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, n := range t.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func effectiveTriage(s string) string {
	if s == "" {
		return domain.TriageNew
	}
	return strings.ToLower(s)
}

func anyEqual(values []string, got string) bool {
	g := strings.ToLower(got)
	for _, v := range values {
		if v == g {
			return true
		}
	}
	return false
}

func anyContains(values []string, got string) bool {
	g := strings.ToLower(got)
	if g == "" {
		return false
	}
	for _, v := range values {
		if strings.Contains(g, v) {
			return true
		}
	}
	return false
}

func anyTag(values, tags []string) bool {
	for _, v := range values {
		if hasTag(tags, v) {
			return true
		}
	}
	return false
}

// Parsed queries are cached so a list request evaluating 10k+ hosts parses once.
var (
	queryCacheMu sync.Mutex
	queryCache   = map[string]*AssetQuery{}
)

func cachedAssetQuery(s string) *AssetQuery {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	queryCacheMu.Lock()
	defer queryCacheMu.Unlock()
	if q, ok := queryCache[s]; ok {
		return q
	}
	q, err := ParseAssetQuery(s)
	if err != nil {
		// Unparseable input (API validates first; this is a defensive fallback): treat
		// the whole string as one free-text phrase, the legacy behaviour.
		q = &AssetQuery{Text: []string{strings.ToLower(s)}}
	}
	if len(queryCache) > 256 {
		queryCache = map[string]*AssetQuery{}
	}
	queryCache[s] = q
	return q
}

var databaseServiceNames = map[string]bool{
	"mysql": true, "postgresql": true, "postgres": true, "ms-sql-s": true, "mssql": true,
	"oracle": true, "oracle-tns": true, "mongodb": true, "mongod": true, "redis": true,
	"elasticsearch": true, "couchdb": true, "memcache": true, "memcached": true,
	"cassandra": true, "influxdb": true, "clickhouse": true, "neo4j": true,
}

var databasePorts = map[int]bool{
	3306: true, 5432: true, 1433: true, 1521: true, 27017: true, 6379: true,
	9200: true, 5984: true, 11211: true, 9042: true, 8086: true,
}

// IsDatabaseService reports a database listener reachable from the scanner (the "exposed
// DB" quick filter): by nmap service name, the "Exposed Database Service" signature, or a
// well-known database port.
func IsDatabaseService(s *domain.Service) bool {
	if databaseServiceNames[strings.ToLower(s.ServiceName)] || databasePorts[s.Port] {
		return true
	}
	for _, sig := range s.MatchedSignatures {
		if strings.Contains(strings.ToLower(sig), "exposed database") {
			return true
		}
	}
	for _, t := range s.Technologies {
		if strings.Contains(strings.ToLower(t.Name), "exposed database") {
			return true
		}
	}
	return false
}

var cleartextAdminNames = map[string]bool{
	"telnet": true, "ftp": true, "rlogin": true, "login": true, "shell": true, "exec": true, "tftp": true,
}

// IsCleartextAdminService reports management protocols that send credentials in clear text
// (telnet, ftp, r-services).
func IsCleartextAdminService(s *domain.Service) bool {
	name := strings.ToLower(s.ServiceName)
	if cleartextAdminNames[name] {
		return true
	}
	return name == "" && (s.Port == 21 || s.Port == 23)
}
