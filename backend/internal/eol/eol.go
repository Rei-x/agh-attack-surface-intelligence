// Package eol flags end-of-life software versions, fully offline.
//
// The data is a small curated table (eol_data.json, embedded in the binary) of release
// branches and their end-of-life dates for the products AegisASI identifies, copied from
// endoflife.date with the source URL and the date it was curated. Nothing is fetched at
// scan time. A version is matched to its branch by the longest dot-boundary prefix
// ("1.14.2" -> "1.14", never "1.1"), and the branch is end-of-life when its EOL date is
// on or before the evaluation time.
package eol

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

//go:embed eol_data.json
var rawData []byte

// Branch is one release line of a product.
type Branch struct {
	Cycle  string `json:"cycle"`
	EOL    string `json:"eol"` // YYYY-MM-DD, "" = supported on the data date
	Latest string `json:"latest"`
	Note   string `json:"note,omitempty"`
}

// Product is one entry of the table.
type Product struct {
	Key      string   `json:"key"`
	Name     string   `json:"name"`
	Source   string   `json:"source"`
	Aliases  []string `json:"aliases"`
	Branches []Branch `json:"branches"`
}

type vulnRange struct {
	Exact  string `json:"exact,omitempty"`
	From   string `json:"from,omitempty"`   // inclusive, "" = unbounded
	Before string `json:"before,omitempty"` // exclusive
}

// KnownVuln is a version-range hint at a well-known critical CVE.
type KnownVuln struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Product    string      `json:"product"`
	Ranges     []vulnRange `json:"ranges"`
	References []string    `json:"references"`
}

// Data is the parsed table.
type Data struct {
	DataVersion string      `json:"data_version"`
	AsOf        string      `json:"as_of"`
	Products    []Product   `json:"products"`
	KnownVulns  []KnownVuln `json:"known_vulns"`

	byAlias map[string]*Product
	byKey   map[string]*Product
}

var table = mustLoad(rawData)

func mustLoad(raw []byte) *Data {
	d, err := parse(raw)
	if err != nil {
		panic("eol: embedded eol_data.json: " + err.Error())
	}
	return d
}

func parse(raw []byte) (*Data, error) {
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	d.byAlias = map[string]*Product{}
	d.byKey = map[string]*Product{}
	for i := range d.Products {
		p := &d.Products[i]
		d.byKey[p.Key] = p
		for _, a := range p.Aliases {
			d.byAlias[strings.ToLower(a)] = p
		}
		for _, b := range p.Branches {
			if b.EOL == "" {
				continue
			}
			if _, err := time.Parse("2006-01-02", b.EOL); err != nil {
				return nil, fmt.Errorf("%s %s: bad eol date %q", p.Key, b.Cycle, b.EOL)
			}
		}
	}
	for _, v := range d.KnownVulns {
		if d.byKey[v.Product] == nil {
			return nil, fmt.Errorf("known vuln %s: unknown product %q", v.ID, v.Product)
		}
	}
	return &d, nil
}

// Table returns the embedded data (read-only).
func Table() *Data { return table }

// LookupProduct maps an identified product or technology name ("nginx", "Apache httpd",
// "PostgreSQL DB", "WordPress") to its table entry.
func (d *Data) LookupProduct(name string) *Product {
	return d.byAlias[strings.ToLower(strings.TrimSpace(name))]
}

var (
	reVersionCore = regexp.MustCompile(`^\s*[vV]?(\d+(?:\.\d+)*)(?:p(\d+))?`)
	// Distribution builds backport security fixes into old upstream versions.
	reDistro = regexp.MustCompile(`(?i)(ubuntu|debian|\+deb|deb\d+u|centos|red ?hat|rhel|\.el[5-9]|fedora|suse|amzn|alpine|raspbian|-fips)`)
	// One "name/version" token of a Server or X-Powered-By header.
	reHeaderToken = regexp.MustCompile(`(?i)\b(apache|nginx|php|openssl|microsoft-iis)/(\d+(?:\.\d+)*[a-z]?)`)
)

// versionCore returns the dotted numeric core of a version ("1.18.0 (Ubuntu)" -> "1.18.0",
// "8.9p1 Ubuntu-3ubuntu0.6" -> "8.9", "1.0.2k-fips" -> "1.0.2") and the OpenSSH portable
// patch level ("p1" -> 1, -1 when absent).
func versionCore(v string) (string, int) {
	m := reVersionCore.FindStringSubmatch(v)
	if m == nil {
		return "", -1
	}
	p := -1
	if m[2] != "" {
		p, _ = strconv.Atoi(m[2])
	}
	return m[1], p
}

// MatchBranch returns the release branch of version: the longest cycle that equals the
// version core or is a dot-boundary prefix of it.
func (p *Product) MatchBranch(version string) (Branch, bool) {
	core, _ := versionCore(version)
	if core == "" {
		return Branch{}, false
	}
	best, found := Branch{}, false
	for _, b := range p.Branches {
		if core == b.Cycle || strings.HasPrefix(core, b.Cycle+".") {
			if !found || len(b.Cycle) > len(best.Cycle) {
				best, found = b, true
			}
		}
	}
	return best, found
}

// supportedBranch is the first branch in table order (newest first) still supported at now.
func (p *Product) supportedBranch(now time.Time) (Branch, bool) {
	for _, b := range p.Branches {
		if b.EOL == "" {
			return b, true
		}
		if t, _ := time.Parse("2006-01-02", b.EOL); t.After(now) {
			return b, true
		}
	}
	return Branch{}, false
}

// candidate is one product/version claim found on a service.
type candidate struct {
	product *Product
	version string
	via     string
}

// candidates collects product/version claims from all evidence of a service, best first:
// the identified product/version, then the HTTP Server header (which also discloses
// PHP/OpenSSL modules), X-Powered-By, and fingerprinted technologies (WordPress, Grafana…).
func (d *Data) candidates(svc *domain.Service) []candidate {
	var out []candidate
	seen := map[string]bool{}
	add := func(p *Product, version, via string) {
		if p == nil || seen[p.Key] {
			return
		}
		if core, _ := versionCore(version); core == "" {
			return
		}
		seen[p.Key] = true
		out = append(out, candidate{product: p, version: strings.TrimSpace(version), via: via})
	}

	if svc.Product != "" && svc.Version != "" {
		p, v := d.LookupProduct(svc.Product), svc.Version
		// MariaDB answers the MySQL handshake as "5.5.5-10.6.16-MariaDB-0ubuntu...".
		if strings.Contains(strings.ToLower(v), "mariadb") {
			p, v = d.byKey["mariadb"], strings.TrimPrefix(v, "5.5.5-")
		}
		add(p, v, nonEmpty(svc.VersionSource, "nmap"))
	}
	if fp := svc.HTTP; fp != nil {
		for _, m := range reHeaderToken.FindAllStringSubmatch(fp.ServerHeader, -1) {
			add(d.LookupProduct(headerProduct(m[1])), m[2], "http-server-header")
		}
		for _, m := range reHeaderToken.FindAllStringSubmatch(headerValue(fp.Headers, "X-Powered-By"), -1) {
			add(d.LookupProduct(headerProduct(m[1])), m[2], "x-powered-by")
		}
	}
	for _, t := range svc.Technologies {
		if t.Version != "" {
			add(d.LookupProduct(t.Name), t.Version, "technology")
		}
	}
	return out
}

func headerProduct(token string) string {
	switch strings.ToLower(token) {
	case "apache":
		return "apache httpd"
	case "microsoft-iis":
		return "microsoft iis"
	}
	return token
}

func headerValue(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// distroPackaged reports whether the service's version evidence names a distribution build.
func distroPackaged(svc *domain.Service, version string) bool {
	ctx := version + " " + svc.Banner
	if svc.HTTP != nil {
		ctx += " " + svc.HTTP.ServerHeader
	}
	return reDistro.MatchString(ctx)
}

var viaLabels = map[string]string{
	"nmap":               "nmap -sV",
	"cpe":                "CPE z nmap",
	"banner":             "baner usługi",
	"http-server-header": "nagłówek Server",
	"http-page":          "treść strony HTTP",
	"x-powered-by":       "nagłówek X-Powered-By",
	"technology":         "fingerprint technologii",
}

// Assess evaluates a service against the table at now and returns its end-of-life
// components and passive known-vulnerability hints (both nil when nothing applies).
func Assess(svc *domain.Service, now time.Time) ([]domain.OutdatedComponent, []domain.VulnHint) {
	return table.Assess(svc, now)
}

// Assess is the table-bound variant of the package-level Assess.
func (d *Data) Assess(svc *domain.Service, now time.Time) ([]domain.OutdatedComponent, []domain.VulnHint) {
	if svc == nil {
		return nil, nil
	}
	var outdated []domain.OutdatedComponent
	var hints []domain.VulnHint
	for _, c := range d.candidates(svc) {
		distro := distroPackaged(svc, c.version)
		if b, ok := c.product.MatchBranch(c.version); ok && b.EOL != "" {
			eolAt, _ := time.Parse("2006-01-02", b.EOL)
			if !eolAt.After(now) {
				outdated = append(outdated, d.outdated(c, b, eolAt, now, distro))
			}
		}
		for _, kv := range d.KnownVulns {
			if kv.Product == c.product.Key && kv.affects(c.version) {
				hints = append(hints, d.hint(kv, c, distro))
			}
		}
	}
	return outdated, hints
}

func (d *Data) outdated(c candidate, b Branch, eolAt, now time.Time, distro bool) domain.OutdatedComponent {
	days := int(now.Sub(eolAt).Hours() / 24)
	core, _ := versionCore(c.version)
	oc := domain.OutdatedComponent{
		Product:        c.product.Name,
		Version:        c.version,
		Branch:         b.Cycle,
		EOLDate:        b.EOL,
		DaysSinceEOL:   days,
		LatestInBranch: b.Latest,
		Via:            c.via,
		DistroPackaged: distro,
		Label:          fmt.Sprintf("%s %s – gałąź EOL od %s", c.product.Name, b.Cycle, b.EOL[:7]),
		Source:         c.product.Source,
		DataAsOf:       d.AsOf,
	}
	if sb, ok := c.product.supportedBranch(now); ok {
		oc.SupportedBranch = sb.Cycle
	}
	var ev strings.Builder
	fmt.Fprintf(&ev, "%s %s (wersja z: %s) należy do gałęzi %s", c.product.Name, core, nonEmpty(viaLabels[c.via], c.via), b.Cycle)
	if b.Note != "" {
		fmt.Fprintf(&ev, " (%s)", b.Note)
	}
	fmt.Fprintf(&ev, ", której wsparcie zakończyło się %s (%s temu).", b.EOL, Age(days))
	if b.Latest != "" {
		fmt.Fprintf(&ev, " Ostatnie wydanie gałęzi: %s.", b.Latest)
	}
	if oc.SupportedBranch != "" {
		fmt.Fprintf(&ev, " Wspierana gałąź: %s.", oc.SupportedBranch)
	}
	if distro {
		ev.WriteString(" Wersja z pakietu dystrybucji: poprawki bezpieczeństwa mogą być backportowane, ale gałąź upstream nie jest już wspierana; sprawdź wsparcie wydania systemu.")
	}
	fmt.Fprintf(&ev, " Źródło: %s (dane z %s, bez zapytań sieciowych).", c.product.Source, d.AsOf)
	oc.Evidence = ev.String()
	return oc
}

func (d *Data) hint(kv KnownVuln, c candidate, distro bool) domain.VulnHint {
	ranges := make([]string, 0, len(kv.Ranges))
	for _, r := range kv.Ranges {
		switch {
		case r.Exact != "":
			ranges = append(ranges, r.Exact)
		case r.From == "":
			ranges = append(ranges, "< "+r.Before)
		default:
			ranges = append(ranges, fmt.Sprintf(">= %s, < %s", r.From, r.Before))
		}
	}
	h := domain.VulnHint{
		ID:             kv.ID,
		Name:           kv.Name,
		Product:        c.product.Name,
		Version:        c.version,
		Affected:       strings.Join(ranges, "; "),
		DistroPackaged: distro,
		References:     kv.References,
	}
	h.Evidence = fmt.Sprintf("Pasywna wskazówka (tylko na podstawie wersji, nic nie wysłano do usługi): %s %s mieści się w zakresie podatnym na %s (%s): %s.",
		c.product.Name, c.version, kv.ID, kv.Name, h.Affected)
	if distro {
		h.Evidence += " Build dystrybucji: poprawka mogła zostać backportowana; potwierdź wersję pakietu."
	}
	return h
}

// affects reports whether version falls in one of the CVE's ranges.
func (kv KnownVuln) affects(version string) bool {
	for _, r := range kv.Ranges {
		if r.Exact != "" {
			if compareVersions(version, r.Exact) == 0 {
				return true
			}
			continue
		}
		if r.From != "" && compareVersions(version, r.From) < 0 {
			continue
		}
		if r.Before != "" && compareVersions(version, r.Before) >= 0 {
			continue
		}
		return true
	}
	return false
}

// compareVersions compares dotted versions with an optional OpenSSH "pN" patch level
// ("8.9p1" < "9.8p1", "8.5" < "8.5p1"). Missing components count as zero.
func compareVersions(a, b string) int {
	ac, ap := versionCore(a)
	bc, bp := versionCore(b)
	as, bs := strings.Split(ac, "."), strings.Split(bc, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case ap < bp:
		return -1
	case ap > bp:
		return 1
	}
	return 0
}

// Age renders a day count in Polish ("7 lat", "2 lata", "1 rok", "5 mies.", "12 dni").
func Age(days int) string {
	if days < 0 {
		days = 0
	}
	years := days / 365
	switch {
	case years >= 1:
		return fmt.Sprintf("%d %s", years, plYears(years))
	case days >= 60:
		return fmt.Sprintf("%d mies.", days/30)
	default:
		return fmt.Sprintf("%d dni", days)
	}
}

func plYears(n int) string {
	if n == 1 {
		return "rok"
	}
	if n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14) {
		return "lata"
	}
	return "lat"
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
