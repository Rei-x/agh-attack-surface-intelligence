package defectdojo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Client communicates with DefectDojo API v2.
type Client struct {
	timeout time.Duration
}

// NewClient returns a DefectDojo API v2 client with a 30 s request timeout.
func NewClient() *Client {
	return &Client{timeout: 30 * time.Second}
}

func (c *Client) httpClient(verifyTLS bool) *http.Client {
	return &http.Client{
		Timeout: c.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS}, //nolint:gosec
		},
	}
}

// ConnectionStatus is returned by TestConnection.
type ConnectionStatus struct {
	OK               bool   `json:"ok"`
	StatusCode       int    `json:"status_code"`
	Message          string `json:"message"`
	EngagementsCount int    `json:"engagements_count,omitempty"`
}

// ImportResult is returned by ImportNmapXML.
type ImportResult struct {
	TestID       int    `json:"test"`
	EngagementID int    `json:"engagement_id"`
	ScanType     string `json:"scan_type"`
	ExternalID   string `json:"external_id"`
	ExternalURL  string `json:"external_url"`
	Message      string `json:"message,omitempty"`
	ProductID    int    `json:"product_id,omitempty"`
}

// FindingInput describes a single finding to push to DefectDojo /api/v2/findings/.
type FindingInput struct {
	SourceID    string   `json:"source_id"`
	HostIP      string   `json:"host_ip"`
	Port        int      `json:"port,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"` // Info, Low, Medium, High, Critical
	Tags        []string `json:"tags,omitempty"`
	Mitigation  string   `json:"mitigation,omitempty"`
	Impact      string   `json:"impact,omitempty"`
	References  string   `json:"references,omitempty"`
	TestID      int      `json:"test_id,omitempty"`
}

// FindingResult holds the outcome of pushing one finding.
type FindingResult struct {
	SourceID         string `json:"source_id"`
	Title            string `json:"title"`
	ExternalID       string `json:"external_id,omitempty"`
	ExternalURL      string `json:"external_url,omitempty"`
	UniqueIDFromTool string `json:"unique_id_from_tool"`
	Status           string `json:"status"` // success, failed
	Error            string `json:"error,omitempty"`
}

// UniqueID produces a deterministic deduplication key for DefectDojo unique_id_from_tool.
func UniqueID(hostIP string, port int, protocol, sourceID string) string {
	// The "aegis" seed/prefix predates the rename and is deliberately kept: it is the
	// finding identity DefectDojo deduplicates on, so changing it would close and
	// re-create every existing finding.
	raw := fmt.Sprintf("aegis-asi:%s:%d:%s:%s", strings.TrimSpace(hostIP), port, strings.ToLower(protocol), strings.TrimSpace(sourceID))
	sum := sha256.Sum256([]byte(raw))
	return "aegis-" + hex.EncodeToString(sum[:16])
}

// NormalizeSeverity converts arbitrary lowercase/uppercase severity strings into DefectDojo v2 values.
func NormalizeSeverity(s string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical", "S0"
	case "high":
		return "High", "S1"
	case "medium":
		return "Medium", "S2"
	case "low":
		return "Low", "S3"
	default:
		return "Info", "S4"
	}
}

func baseURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func (c *Client) setHeaders(req *http.Request, token string) {
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Token "+strings.TrimSpace(token))
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Dzieciol-CBI-AGH/1.0")
}

// TestConnection verifies API v2 reachability and token validity via /api/v2/users/ or /api/v2/engagements/.
func (c *Client) TestConnection(ctx context.Context, cfg *domain.DefectDojoConfig) (*ConnectionStatus, error) {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("defectdojo URL is required")
	}
	base := baseURL(cfg.URL)
	hc := c.httpClient(cfg.VerifyTLS)

	endpoints := []string{
		base + "/api/v2/engagements/?limit=1",
		base + "/api/v2/users/?limit=1",
	}
	var lastStatus int
	var lastBody string
	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			return nil, err
		}
		c.setHeaders(req, cfg.APIToken)
		resp, err := hc.Do(req)
		if err != nil {
			return &ConnectionStatus{OK: false, Message: err.Error()}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		lastStatus = resp.StatusCode
		lastBody = strings.TrimSpace(string(body))
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var parsed struct {
				Count int `json:"count"`
			}
			_ = json.Unmarshal(body, &parsed)
			return &ConnectionStatus{
				OK:               true,
				StatusCode:       resp.StatusCode,
				Message:          fmt.Sprintf("Connected to DefectDojo API v2 (%s)", ep),
				EngagementsCount: parsed.Count,
			}, nil
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return &ConnectionStatus{
				OK:         false,
				StatusCode: resp.StatusCode,
				Message:    "Authentication failed (invalid DefectDojo API v2 token)",
			}, nil
		}
	}
	return &ConnectionStatus{
		OK:         false,
		StatusCode: lastStatus,
		Message:    fmt.Sprintf("DefectDojo returned HTTP %d: %s", lastStatus, truncate(lastBody, 200)),
	}, nil
}

// Default DefectDojo context used when the operator has not pinned a product/engagement.
// DefectDojo's auto_create_context creates them on first import.
const (
	DefaultProductType = "Dzięcioł"
	DefaultProduct     = "AGH Attack Surface"
	DefaultEngagement  = "Dzięcioł continuous discovery"
	ObservationsTest   = "Dzięcioł observations"
	NmapTestPrefix     = "Dzięcioł Nmap"
)

// importContext identifies where a (re)import lands in DefectDojo.
type importContext struct {
	ProductType string
	Product     string
	Engagement  string
}

// resolveContext maps the configured IDs (if any) to names, because DefectDojo's
// reimport-scan only resolves its target by test id or by product/engagement names.
func (c *Client) resolveContext(ctx context.Context, cfg *domain.DefectDojoConfig, engagementID int) (importContext, error) {
	ic := defaultContext()
	if engagementID <= 0 {
		engagementID = cfg.EngagementID
	}
	productID := cfg.ProductID
	if engagementID > 0 {
		var eng struct {
			Name    string `json:"name"`
			Product int    `json:"product"`
		}
		if err := c.getJSON(ctx, cfg, fmt.Sprintf("/api/v2/engagements/%d/", engagementID), &eng); err != nil {
			return ic, fmt.Errorf("engagement %d: %w", engagementID, err)
		}
		ic.Engagement = eng.Name
		productID = eng.Product
	}
	if productID > 0 {
		var prod struct {
			Name     string `json:"name"`
			ProdType int    `json:"prod_type"`
		}
		if err := c.getJSON(ctx, cfg, fmt.Sprintf("/api/v2/products/%d/", productID), &prod); err != nil {
			return ic, fmt.Errorf("product %d: %w", productID, err)
		}
		ic.Product = prod.Name
		var pt struct {
			Name string `json:"name"`
		}
		if err := c.getJSON(ctx, cfg, fmt.Sprintf("/api/v2/product_types/%d/", prod.ProdType), &pt); err == nil && pt.Name != "" {
			ic.ProductType = pt.Name
		}
	}
	return ic, nil
}

func (c *Client) getJSON(ctx context.Context, cfg *domain.DefectDojoConfig, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL(cfg.URL)+path, nil)
	if err != nil {
		return err
	}
	c.setHeaders(req, cfg.APIToken)
	resp, err := c.httpClient(cfg.VerifyTLS).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	if len(body) > maxResponseBytes {
		return fmt.Errorf("DefectDojo response for %s is larger than %d MB; use a smaller page size", path, maxResponseBytes>>20)
	}
	return json.Unmarshal(body, out)
}

// maxResponseBytes caps one API response. DefectDojo finding objects are several KB each, so
// listings must be paged (findingsPageSize) rather than read in one large page.
const maxResponseBytes = 64 << 20

type reimportResponse struct {
	Test         int    `json:"test"`
	TestID       int    `json:"test_id"`
	EngagementID int    `json:"engagement_id"`
	ProductID    int    `json:"product_id"`
	Message      string `json:"message"`
	Statistics   struct {
		After struct {
			Total struct {
				Total int `json:"total"`
			} `json:"total"`
		} `json:"after"`
	} `json:"statistics"`
}

// reimportTarget names the test a reimport lands in: by id when TestID is set, otherwise by
// title inside the product type / product / engagement of Context.
type reimportTarget struct {
	Context importContext
	Title   string
	TestID  int
}

// httpError is a non-2xx answer from DefectDojo.
type httpError struct {
	Op     string
	Status int
	Body   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("defectdojo %s failed (HTTP %d): %s", e.Op, e.Status, truncate(e.Body, 300))
}

// isMissingTest reports whether a reimport by test id failed because the test is gone
// (deleted in DefectDojo): DefectDojo answers 400 {"test": ["Invalid pk ..."]} or 404.
func isMissingTest(err error) bool {
	var he *httpError
	if !errors.As(err, &he) {
		return false
	}
	return (he.Status == http.StatusBadRequest || he.Status == http.StatusNotFound) && strings.Contains(strings.ToLower(he.Body), "test")
}

// reimport posts to /api/v2/reimport-scan/. By title it sends the context names with
// auto_create_context: DefectDojo creates the product type/product/engagement/test on first
// use and afterwards updates the same test, deduplicating by its own hash or
// unique_id_from_tool. By id it sends only the test: DefectDojo rejects a test id that does
// not belong to the engagement the names resolve to, and the id alone is unambiguous.
func (c *Client) reimport(ctx context.Context, cfg *domain.DefectDojoConfig, t reimportTarget, scanType, version, fileName string, data []byte, closeOld bool) (*reimportResponse, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fields := [][2]string{{"scan_type", scanType}}
	if t.TestID > 0 {
		fields = append(fields, [2]string{"test", strconv.Itoa(t.TestID)})
	} else {
		fields = append(fields,
			[2]string{"product_type_name", t.Context.ProductType},
			[2]string{"product_name", t.Context.Product},
			[2]string{"engagement_name", t.Context.Engagement},
			[2]string{"test_title", t.Title},
			[2]string{"auto_create_context", "true"},
		)
	}
	fields = append(fields, [][2]string{
		{"active", "true"},
		{"verified", "false"},
		{"close_old_findings", strconv.FormatBool(closeOld)},
		{"scan_date", time.Now().UTC().Format("2006-01-02")},
		{"minimum_severity", minimumSeverity()},
	}...)
	fields = append(fields, extraReimportFields()...)
	if version != "" {
		fields = append(fields, [2]string{"version", version})
	}
	for _, f := range fields {
		_ = mw.WriteField(f[0], f[1])
	}
	_ = mw.WriteField("tags", "dzieciol")
	fw, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(data); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL(cfg.URL)+"/api/v2/reimport-scan/", &buf)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req, cfg.APIToken)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	hc := c.httpClient(cfg.VerifyTLS)
	hc.Timeout = 5 * time.Minute // large Nmap XML imports are processed synchronously
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &httpError{Op: "reimport-scan (" + scanType + ")", Status: resp.StatusCode, Body: string(body)}
	}
	var parsed reimportResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("defectdojo reimport-scan: unexpected response: %s", truncate(string(body), 200))
	}
	if parsed.Test == 0 {
		parsed.Test = parsed.TestID
	}
	return &parsed, nil
}

// NmapTestTitle is the stable DefectDojo test title for a scan profile, so every run of the
// same profile reimports into one test and DefectDojo closes services that disappeared.
func NmapTestTitle(profileName string) string {
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return NmapTestPrefix
	}
	return NmapTestPrefix + ": " + profileName
}

// ImportNmapXML reimports raw Nmap XML (scan_type "Nmap Scan") into the test named testTitle.
// close_old_findings is enabled: services missing from this run are mitigated in DefectDojo,
// which mirrors Dzięcioł's own new/disappeared diff. runLabel is stored as the test version.
func (c *Client) ImportNmapXML(ctx context.Context, cfg *domain.DefectDojoConfig, engagementID int, testTitle, runLabel, xmlData string) (*ImportResult, error) {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("defectdojo URL is not configured")
	}
	if strings.TrimSpace(xmlData) == "" {
		return nil, fmt.Errorf("raw Nmap XML payload is empty")
	}
	ic, err := c.resolveContext(ctx, cfg, engagementID)
	if err != nil {
		return nil, err
	}
	if testTitle == "" {
		testTitle = NmapTestPrefix
	}
	res, err := c.reimport(ctx, cfg, reimportTarget{Context: ic, Title: testTitle}, "Nmap Scan", runLabel, "dzieciol-nmap.xml", []byte(xmlData), true)
	if err != nil {
		return nil, err
	}
	out := &ImportResult{
		TestID:       res.Test,
		EngagementID: res.EngagementID,
		ProductID:    res.ProductID,
		ScanType:     "Nmap Scan",
		Message:      fmt.Sprintf("%d findings in DefectDojo test %q", res.Statistics.After.Total.Total, testTitle),
	}
	if res.Test > 0 {
		out.ExternalID = strconv.Itoa(res.Test)
		out.ExternalURL = fmt.Sprintf("%s/test/%d", baseURL(cfg.URL), res.Test)
	}
	return out, nil
}

type genericFinding struct {
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Severity         string            `json:"severity"`
	Date             string            `json:"date"`
	Active           bool              `json:"active"`
	Verified         bool              `json:"verified"`
	UniqueIDFromTool string            `json:"unique_id_from_tool"`
	VulnIDFromTool   string            `json:"vuln_id_from_tool"`
	Mitigation       string            `json:"mitigation,omitempty"`
	Impact           string            `json:"impact,omitempty"`
	References       string            `json:"references,omitempty"`
	ComponentName    string            `json:"component_name,omitempty"`
	ComponentVersion string            `json:"component_version,omitempty"`
	Service          string            `json:"service,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
	Endpoints        []genericEndpoint `json:"endpoints,omitempty"`

	// Vulnerability intelligence and verification evidence (vuln_fields.go). All are
	// Generic Findings Import fields of DefectDojo 2.x/3.x; none takes part in hash_code, so
	// volatile evidence goes to steps_to_reproduce.
	CVE                   string   `json:"cve,omitempty"`
	VulnerabilityIDs      []string `json:"vulnerability_ids,omitempty"`
	CVSSv3Score           float64  `json:"cvssv3_score,omitempty"`
	EPSSScore             float64  `json:"epss_score,omitempty"`
	EPSSPercentile        float64  `json:"epss_percentile,omitempty"`
	KnownExploited        bool     `json:"known_exploited,omitempty"`
	KEVDate               string   `json:"kev_date,omitempty"`
	RansomwareUsed        bool     `json:"ransomware_used,omitempty"`
	SeverityJustification string   `json:"severity_justification,omitempty"`
	StepsToReproduce      string   `json:"steps_to_reproduce,omitempty"`
}

type genericEndpoint struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// PushFindings exports selected observations as informational evidence through DefectDojo's
// "Generic Findings Import" into the "Dzięcioł observations" test. Re-pushing the same
// observation updates it (dedup by unique_id_from_tool) instead of creating a duplicate, and
// close_old_findings is off so a partial selection never closes earlier exports.
func (c *Client) PushFindings(ctx context.Context, cfg *domain.DefectDojoConfig, engagementID int, findings []FindingInput) ([]FindingResult, error) {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("defectdojo URL is not configured")
	}
	if len(findings) == 0 {
		return nil, nil
	}
	ic, err := c.resolveContext(ctx, cfg, engagementID)
	if err != nil {
		return nil, err
	}

	today := time.Now().UTC().Format("2006-01-02")
	doc := struct {
		Findings []genericFinding `json:"findings"`
	}{}
	results := make([]FindingResult, 0, len(findings))
	for _, f := range findings {
		sev, _ := NormalizeSeverity(f.Severity)
		uid := UniqueID(f.HostIP, f.Port, f.Protocol, f.SourceID)
		g := genericFinding{
			Title:            f.Title,
			Description:      f.Description,
			Severity:         sev,
			Date:             today,
			Active:           true,
			UniqueIDFromTool: uid,
			VulnIDFromTool:   uid,
			Mitigation:       f.Mitigation,
			Impact:           f.Impact,
			References:       f.References,
			Tags:             append([]string{"dzieciol", "cbi-agh"}, f.Tags...),
		}
		if f.HostIP != "" {
			g.ComponentName = f.HostIP
			ep := genericEndpoint{Host: f.HostIP, Port: f.Port}
			if f.Port > 0 {
				g.ComponentVersion = fmt.Sprintf("%d/%s", f.Port, f.Protocol)
				g.Service = g.ComponentVersion
			}
			g.Endpoints = []genericEndpoint{ep}
		}
		doc.Findings = append(doc.Findings, g)
		results = append(results, FindingResult{SourceID: f.SourceID, Title: f.Title, UniqueIDFromTool: uid})
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	res, err := c.reimport(ctx, cfg, reimportTarget{Context: ic, Title: ObservationsTest}, "Generic Findings Import", "", "dzieciol-observations.json", raw, false)
	if err != nil {
		for i := range results {
			results[i].Status = "failed"
			results[i].Error = err.Error()
		}
		return results, nil
	}

	// Map unique_id_from_tool -> DefectDojo finding id for deep links.
	ids := map[string]int{}
	if res.Test > 0 {
		type idRow struct {
			ID               int    `json:"id"`
			UniqueIDFromTool string `json:"unique_id_from_tool"`
		}
		if rows, err := listPaged[idRow](ctx, c, cfg, fmt.Sprintf("/api/v2/findings/?test=%d", res.Test), findingsPageSize); err == nil {
			for _, r := range rows {
				ids[r.UniqueIDFromTool] = r.ID
			}
		}
	}
	base := baseURL(cfg.URL)
	for i := range results {
		results[i].Status = "success"
		if id, ok := ids[results[i].UniqueIDFromTool]; ok {
			results[i].ExternalID = strconv.Itoa(id)
			results[i].ExternalURL = fmt.Sprintf("%s/finding/%d", base, id)
		} else if res.Test > 0 {
			results[i].ExternalURL = fmt.Sprintf("%s/test/%d", base, res.Test)
		}
	}
	return results, nil
}

// BuildServiceEvidenceDescription formats an audit-ready Markdown evidence receipt for DefectDojo.
func BuildServiceEvidenceDescription(host *domain.Host, svc *domain.Service) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Dzięcioł Attack Surface Evidence Receipt\n\n")
	fmt.Fprintf(&b, "- **Host:** `%s`", svc.HostIP)
	if host != nil && host.Hostname != "" {
		fmt.Fprintf(&b, " (%s)", host.Hostname)
	}
	fmt.Fprintf(&b, "\n- **Service:** `%d/%s` (%s %s %s)\n", svc.Port, svc.Protocol, svc.ServiceName, svc.Product, svc.Version)
	fmt.Fprintf(&b, "- **Interestingness Score:** `%d/100`\n", svc.Interestingness)
	if host != nil {
		fmt.Fprintf(&b, "- **Lifecycle State:** `%s` | **Environment:** `%s`\n", host.LifecycleState, host.Environment)
		fmt.Fprintf(&b, "- **Owner (CIDR rule):** %s\n", nonEmpty(host.Owner, "none (add a CIDR rule)"))
	}
	for _, o := range svc.Outdated {
		fmt.Fprintf(&b, "- **End of life:** %s\n", o.Evidence)
	}
	for _, v := range svc.KnownVulns {
		fmt.Fprintf(&b, "- **Passive CVE hint:** %s\n", v.Evidence)
	}
	if len(svc.Technologies) > 0 {
		fmt.Fprintf(&b, "\n### Detected Technologies (Noisy-OR Confidence)\n")
		for _, t := range svc.Technologies {
			fmt.Fprintf(&b, "- **%s** %s (%s), confidence `%d%%`\n", t.Name, t.Version, t.Category, t.Confidence)
		}
	}
	if svc.HTTP != nil {
		fmt.Fprintf(&b, "\n### HTTP / TLS Evidence\n")
		fmt.Fprintf(&b, "- **URL:** %s (HTTP `%d`)\n", svc.HTTP.URL, svc.HTTP.StatusCode)
		if svc.HTTP.Title != "" {
			fmt.Fprintf(&b, "- **Title:** `%s`\n", svc.HTTP.Title)
		}
		if svc.HTTP.ServerHeader != "" {
			fmt.Fprintf(&b, "- **Server:** `%s`\n", svc.HTTP.ServerHeader)
		}
		if len(svc.HTTP.MissingSecHeaders) > 0 {
			fmt.Fprintf(&b, "- **Missing Security Headers:** `%s`\n", strings.Join(svc.HTTP.MissingSecHeaders, ", "))
		}
		if svc.HTTP.FaviconMMH3 != "" {
			fmt.Fprintf(&b, "- **Favicon MMH3:** `%s`\n", svc.HTTP.FaviconMMH3)
		}
		if svc.HTTP.TLS != nil {
			fmt.Fprintf(&b, "- **TLS Cert:** CN=`%s`, Issuer=`%s`, SelfSigned=`%v`, DaysToExpiry=`%d`\n",
				svc.HTTP.TLS.SubjectCN, svc.HTTP.TLS.Issuer, svc.HTTP.TLS.IsSelfSigned, svc.HTTP.TLS.DaysToExpiry)
		}
	}
	if len(svc.InterestingFactors) > 0 {
		fmt.Fprintf(&b, "\n### Risk Factors\n")
		for _, f := range svc.InterestingFactors {
			fmt.Fprintf(&b, "- (+%d pts) %s\n", f.Points, f.Reason)
		}
	}
	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
