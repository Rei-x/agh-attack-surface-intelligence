package vulndb

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Source URLs. CISA's own host rejects many datacenter networks, so the official GitHub
// mirror of the catalog (cisagov/kev-data) is tried next.
const (
	NVDAPI      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	KEVURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	KEVMirror   = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
	EPSSURL     = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	userAgent   = "dzieciol-vulndb/1 (+offline vulnerability snapshot builder)"
	summaryMax  = 200
	nvdPageSize = 2000
)

// Builder fetches the sources and assembles a snapshot.
type Builder struct {
	HTTP      *http.Client
	NVDAPIKey string // optional; raises the NVD rate limit from 5 to 50 requests / 30 s
	Log       func(format string, a ...any)
	// Delay between NVD requests (default 6.5 s without a key, 0.7 s with one).
	Delay time.Duration
}

func (b *Builder) logf(format string, a ...any) {
	if b.Log != nil {
		b.Log(format, a...)
	}
}

func (b *Builder) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return &http.Client{Timeout: 3 * time.Minute}
}

func (b *Builder) get(ctx context.Context, u string, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", u, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

// Build fetches NVD, KEV and EPSS and returns a full snapshot.
func (b *Builder) Build(ctx context.Context) (*Snapshot, error) {
	s := &Snapshot{Schema: SchemaVersion, Products: map[string][]Affected{}}
	cves := map[string]*CVE{}
	if err := b.fetchNVD(ctx, s, cves); err != nil {
		return nil, err
	}
	for _, c := range cves {
		s.CVEs = append(s.CVEs, *c)
	}
	s.index()
	if err := b.Enrich(ctx, s); err != nil {
		return nil, err
	}
	s.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	return s, nil
}

// Enrich refreshes the KEV and EPSS columns of an existing snapshot (the fast part of an
// update: two downloads, no NVD rate limit) and re-tags the protocol preconditions.
func (b *Builder) Enrich(ctx context.Context, s *Snapshot) error {
	if s.byID == nil {
		s.index()
	}
	if err := b.joinKEV(ctx, s); err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	if err := b.joinEPSS(ctx, s); err != nil {
		return fmt.Errorf("epss: %w", err)
	}
	// Protocol preconditions (offline: descriptions + the explicit table), so an update of
	// an older snapshot gets them too.
	st := TagRequirements(s)
	b.logf("protocol preconditions: %d HTTP/2, %d HTTP/3", st.ByRequirement[ReqHTTP2], st.ByRequirement[ReqHTTP3])
	s.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// ---- NVD -------------------------------------------------------------------------------

type nvdPage struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics        map[string][]nvdMetric `json:"metrics"`
	Weaknesses     []nvdWeakness          `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []nvdCPEMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	// CISA KEV fields mirrored by NVD (used when the KEV feed itself is unreachable).
	CISAExploitAdd string `json:"cisaExploitAdd"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // v2 keeps it outside cvssData
}

type nvdWeakness struct {
	Description []struct {
		Value string `json:"value"`
	} `json:"description"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

func (b *Builder) fetchNVD(ctx context.Context, s *Snapshot, cves map[string]*CVE) error {
	delay := b.Delay
	if delay == 0 {
		delay = 6500 * time.Millisecond
		if b.NVDAPIKey != "" {
			delay = 700 * time.Millisecond
		}
	}
	hdr := map[string]string{}
	if b.NVDAPIKey != "" {
		hdr["apiKey"] = b.NVDAPIKey
	}
	cpeOwner := map[string]string{} // "a:vendor:product" -> catalog key
	for _, def := range Catalog {
		for _, c := range def.CPEs {
			cpeOwner[unescapeCPE(c)] = def.Key
		}
	}
	first := true
	for _, def := range Catalog {
		for _, prefix := range def.CPEs {
			for start := 0; ; {
				if !first {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(delay):
					}
				}
				first = false
				q := url.Values{}
				q.Set("virtualMatchString", "cpe:2.3:"+prefix)
				q.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
				q.Set("startIndex", strconv.Itoa(start))
				page, err := b.nvdPage(ctx, NVDAPI+"?"+q.Encode(), hdr)
				if err != nil {
					return fmt.Errorf("nvd %s: %w", prefix, err)
				}
				for _, v := range page.Vulnerabilities {
					addNVD(s, cves, &v.CVE, cpeOwner)
				}
				b.logf("nvd %-45s %4d-%4d of %d", prefix, start, start+len(page.Vulnerabilities), page.TotalResults)
				start += len(page.Vulnerabilities)
				if len(page.Vulnerabilities) == 0 || start >= page.TotalResults {
					break
				}
			}
			s.Sources.ProductsCPE++
		}
	}
	s.Sources.NVD = NVDAPI
	s.Sources.NVDFetched = time.Now().UTC().Format("2006-01-02")
	return nil
}

// nvdPage fetches one page, retrying transient NVD errors (it often answers 503/403 under load).
func (b *Builder) nvdPage(ctx context.Context, u string, hdr map[string]string) (*nvdPage, error) {
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*10) * time.Second):
			}
		}
		resp, err := b.get(ctx, u, hdr)
		if err != nil {
			lastErr = err
			continue
		}
		var p nvdPage
		err = json.NewDecoder(resp.Body).Decode(&p)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return &p, nil
	}
	return nil, lastErr
}

func addNVD(s *Snapshot, cves map[string]*CVE, n *nvdCVE, cpeOwner map[string]string) {
	if n.ID == "" || strings.EqualFold(n.VulnStatus, "Rejected") {
		return
	}
	perProduct := map[string][]Range{}
	for _, cfg := range n.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue // platform the vulnerable component runs on, not affected itself
				}
				vp, ver, upd, ok := cpeVendorProduct(m.Criteria)
				if !ok {
					continue
				}
				key := cpeOwner[unescapeCPE(vp)]
				if key == "" {
					continue
				}
				r := Range{SI: m.VersionStartIncluding, SE: m.VersionStartExcluding, EI: m.VersionEndIncluding, EE: m.VersionEndExcluding}
				if r == (Range{}) {
					if ver == "*" || ver == "-" || ver == "" {
						continue // "all versions": no usable version information
					}
					r.Exact = joinUpdate(unescapeCPE(ver), unescapeCPE(upd))
				}
				perProduct[key] = appendRange(perProduct[key], r)
			}
		}
	}
	if len(perProduct) == 0 {
		return
	}
	c := cves[n.ID]
	if c == nil {
		c = &CVE{ID: n.ID}
		if len(n.Published) >= 10 {
			c.Published = n.Published[:10]
		}
		for _, d := range n.Descriptions {
			if d.Lang == "en" {
				c.Summary = shorten(d.Value, summaryMax)
				// Tag from the full description; the stored summary is cut short.
				c.Requires = DetectRequirement(d.Value)
				break
			}
		}
		c.CVSS, c.CVSSVersion, c.Severity = bestMetric(n.Metrics)
		for _, w := range n.Weaknesses {
			for _, d := range w.Description {
				if strings.HasPrefix(d.Value, "CWE-") && c.CWE == "" {
					c.CWE = d.Value
				}
			}
		}
		if len(n.CISAExploitAdd) >= 10 {
			c.KEVAdded = n.CISAExploitAdd[:10]
		}
		cves[n.ID] = c
	}
	for key, ranges := range perProduct {
		merged := false
		for i := range s.Products[key] {
			if s.Products[key][i].CVE == n.ID {
				for _, r := range ranges {
					s.Products[key][i].Ranges = appendRange(s.Products[key][i].Ranges, r)
				}
				merged = true
			}
		}
		if !merged {
			s.Products[key] = append(s.Products[key], Affected{CVE: n.ID, Ranges: ranges})
		}
	}
}

func appendRange(list []Range, r Range) []Range {
	for _, x := range list {
		if x == r {
			return list
		}
	}
	return append(list, r)
}

// joinUpdate merges a CPE update field into the version: OpenSSH "8.9"+"p1" -> "8.9p1",
// "3.0.0"+"rc1" -> "3.0.0-rc1".
func joinUpdate(ver, upd string) string {
	upd = strings.ToLower(upd)
	if upd == "" || upd == "*" || upd == "-" {
		return ver
	}
	if len(upd) > 1 && upd[0] == 'p' && upd[1] >= '0' && upd[1] <= '9' {
		return ver + upd
	}
	return ver + "-" + upd
}

func unescapeCPE(s string) string { return strings.ReplaceAll(s, `\`, "") }

func bestMetric(m map[string][]nvdMetric) (float64, string, string) {
	for _, k := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"} {
		list := m[k]
		if len(list) == 0 {
			continue
		}
		pick := list[0]
		for _, x := range list {
			if x.Type == "Primary" {
				pick = x
				break
			}
		}
		sev := pick.CVSSData.BaseSeverity
		if sev == "" {
			sev = pick.BaseSeverity
		}
		return pick.CVSSData.BaseScore, pick.CVSSData.Version, strings.ToUpper(sev)
	}
	return 0, "", ""
}

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	cut := strings.LastIndexByte(s[:n], ' ')
	if cut < n/2 {
		cut = n
	}
	return s[:cut] + "..."
}

// ---- KEV -------------------------------------------------------------------------------

type kevCatalog struct {
	CatalogVersion  string `json:"catalogVersion"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CVEID      string `json:"cveID"`
		DateAdded  string `json:"dateAdded"`
		Ransomware string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

func (b *Builder) joinKEV(ctx context.Context, s *Snapshot) error {
	var cat kevCatalog
	var src string
	var lastErr error
	for _, u := range []string{KEVURL, KEVMirror} {
		resp, err := b.get(ctx, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		err = json.NewDecoder(resp.Body).Decode(&cat)
		resp.Body.Close()
		if err != nil || len(cat.Vulnerabilities) == 0 {
			lastErr = fmt.Errorf("%s: unexpected content (%v)", u, err)
			continue
		}
		src = u
		break
	}
	if src == "" {
		return lastErr
	}
	ApplyKEV(s, cat.CatalogVersion, src, func(yield func(id, added string, ransomware bool)) {
		for _, v := range cat.Vulnerabilities {
			yield(v.CVEID, v.DateAdded, strings.EqualFold(v.Ransomware, "Known"))
		}
	})
	s.Sources.KEVCount = cat.Count
	b.logf("kev %s: catalog %s, %d entries", src, cat.CatalogVersion, cat.Count)
	return nil
}

// ApplyKEV joins KEV entries onto the snapshot's CVEs (resetting previous KEV marks).
func ApplyKEV(s *Snapshot, version, source string, each func(yield func(id, added string, ransomware bool))) {
	if s.byID == nil {
		s.index()
	}
	for i := range s.CVEs {
		s.CVEs[i].KEVAdded, s.CVEs[i].Ransomware = "", false
	}
	each(func(id, added string, ransomware bool) {
		if c := s.byID[strings.TrimSpace(id)]; c != nil {
			c.KEVAdded, c.Ransomware = added, ransomware
		}
	})
	s.Sources.KEV, s.Sources.KEVVersion = source, version
}

// ---- EPSS ------------------------------------------------------------------------------

func (b *Builder) joinEPSS(ctx context.Context, s *Snapshot) error {
	resp, err := b.get(ctx, EPSSURL, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer zr.Close()
	n, err := ApplyEPSS(s, zr, EPSSURL)
	if err != nil {
		return err
	}
	b.logf("epss %s: model %s, scores of %s, %d snapshot CVEs scored", EPSSURL, s.Sources.EPSSModel, s.Sources.EPSSDate, n)
	return nil
}

// ApplyEPSS joins an EPSS CSV ("#model_version:...,score_date:..." comment, then
// cve,epss,percentile) onto the snapshot and returns how many CVEs got a score.
func ApplyEPSS(s *Snapshot, r io.Reader, source string) (int, error) {
	if s.byID == nil {
		s.index()
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n, rows := 0, 0
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			for _, kv := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
				k, v, _ := strings.Cut(kv, ":")
				switch strings.TrimSpace(k) {
				case "model_version":
					s.Sources.EPSSModel = strings.TrimSpace(v)
				case "score_date":
					if v = strings.TrimSpace(v); len(v) >= 10 {
						s.Sources.EPSSDate = v[:10]
					}
				}
			}
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 3 || f[0] == "cve" {
			continue
		}
		rows++
		c := s.byID[f[0]]
		if c == nil {
			continue
		}
		e, err1 := strconv.ParseFloat(f[1], 64)
		p, err2 := strconv.ParseFloat(f[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		c.EPSS, c.EPSSPct = e, p
		n++
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	if rows == 0 {
		return 0, fmt.Errorf("no EPSS rows")
	}
	s.Sources.EPSS = source
	return n, nil
}
