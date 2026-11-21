package defectdojo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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
	req.Header.Set("User-Agent", "AegisASI-CBI-AGH/1.0")
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

// ImportNmapXML uploads raw Nmap XML to POST /api/v2/import-scan/ with scan_type="Nmap Scan".
func (c *Client) ImportNmapXML(ctx context.Context, cfg *domain.DefectDojoConfig, engagementID int, scanName, xmlData string) (*ImportResult, error) {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("defectdojo URL is not configured")
	}
	if strings.TrimSpace(xmlData) == "" {
		return nil, fmt.Errorf("raw Nmap XML payload is empty")
	}
	if engagementID <= 0 {
		engagementID = cfg.EngagementID
	}
	if engagementID <= 0 {
		engagementID = 1
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("scan_type", "Nmap Scan")
	_ = mw.WriteField("engagement", strconv.Itoa(engagementID))
	_ = mw.WriteField("active", "true")
	_ = mw.WriteField("verified", "false")
	_ = mw.WriteField("close_old_findings", "false")
	_ = mw.WriteField("scan_date", time.Now().UTC().Format("2006-01-02"))
	if scanName != "" {
		_ = mw.WriteField("test_title", scanName)
	}
	fw, err := mw.CreateFormFile("file", "aegis-asi-nmap.xml")
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write([]byte(xmlData)); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	base := baseURL(cfg.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v2/import-scan/", &buf)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req, cfg.APIToken)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := c.httpClient(cfg.VerifyTLS).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("defectdojo import-scan failed (HTTP %d): %s", resp.StatusCode, truncate(string(body), 300))
	}

	var parsed struct {
		Test         int    `json:"test"`
		TestID       int    `json:"test_id"`
		EngagementID int    `json:"engagement_id"`
		ID           int    `json:"id"`
		URL          string `json:"url"`
		Message      string `json:"message"`
	}
	_ = json.Unmarshal(body, &parsed)
	testID := parsed.Test
	if testID == 0 {
		testID = parsed.TestID
	}
	if testID == 0 {
		testID = parsed.ID
	}
	extID := ""
	extURL := parsed.URL
	if testID > 0 {
		extID = strconv.Itoa(testID)
		if extURL == "" {
			extURL = fmt.Sprintf("%s/test/%d", base, testID)
		}
	}
	return &ImportResult{
		TestID:       testID,
		EngagementID: engagementID,
		ScanType:     "Nmap Scan",
		ExternalID:   extID,
		ExternalURL:  extURL,
		Message:      parsed.Message,
	}, nil
}

// PushFindings sends individual findings with full evidence receipts and deterministic
// unique_id_from_tool deduplication to POST /api/v2/findings/.
func (c *Client) PushFindings(ctx context.Context, cfg *domain.DefectDojoConfig, engagementID int, findings []FindingInput) ([]FindingResult, error) {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("defectdojo URL is not configured")
	}
	if engagementID <= 0 {
		engagementID = cfg.EngagementID
	}
	if engagementID <= 0 {
		engagementID = 1
	}

	base := baseURL(cfg.URL)
	hc := c.httpClient(cfg.VerifyTLS)
	results := make([]FindingResult, 0, len(findings))

	for _, f := range findings {
		sev, numSev := NormalizeSeverity(f.Severity)
		uid := UniqueID(f.HostIP, f.Port, f.Protocol, f.SourceID)
		tags := append([]string{"aegis-asi", "cbi-agh"}, f.Tags...)

		payload := map[string]any{
			"title":               f.Title,
			"description":         f.Description,
			"severity":            sev,
			"numerical_severity":  numSev,
			"active":              true,
			"verified":            false,
			"engagement":          engagementID,
			"found_by":            []int{1},
			"unique_id_from_tool": uid,
			"vuln_id_from_tool":   uid,
			"tags":                tags,
			"date":                time.Now().UTC().Format("2006-01-02"),
		}
		if f.TestID > 0 {
			payload["test"] = f.TestID
		}
		if f.Mitigation != "" {
			payload["mitigation"] = f.Mitigation
		}
		if f.Impact != "" {
			payload["impact"] = f.Impact
		}
		if f.References != "" {
			payload["references"] = f.References
		}
		if f.HostIP != "" {
			payload["component_name"] = f.HostIP
			if f.Port > 0 {
				payload["component_version"] = fmt.Sprintf("%d/%s", f.Port, f.Protocol)
			}
		}

		raw, err := json.Marshal(payload)
		if err != nil {
			results = append(results, FindingResult{
				SourceID: f.SourceID, Title: f.Title, UniqueIDFromTool: uid, Status: "failed", Error: err.Error(),
			})
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v2/findings/", bytes.NewReader(raw))
		if err != nil {
			results = append(results, FindingResult{
				SourceID: f.SourceID, Title: f.Title, UniqueIDFromTool: uid, Status: "failed", Error: err.Error(),
			})
			continue
		}
		c.setHeaders(req, cfg.APIToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := hc.Do(req)
		if err != nil {
			results = append(results, FindingResult{
				SourceID: f.SourceID, Title: f.Title, UniqueIDFromTool: uid, Status: "failed", Error: err.Error(),
			})
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			results = append(results, FindingResult{
				SourceID:         f.SourceID,
				Title:            f.Title,
				UniqueIDFromTool: uid,
				Status:           "failed",
				Error:            fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 250)),
			})
			continue
		}

		var created struct {
			ID  int    `json:"id"`
			URL string `json:"url"`
		}
		_ = json.Unmarshal(body, &created)
		extID := ""
		extURL := created.URL
		if created.ID > 0 {
			extID = strconv.Itoa(created.ID)
			if extURL == "" {
				extURL = fmt.Sprintf("%s/finding/%d", base, created.ID)
			}
		}
		results = append(results, FindingResult{
			SourceID:         f.SourceID,
			Title:            f.Title,
			ExternalID:       extID,
			ExternalURL:      extURL,
			UniqueIDFromTool: uid,
			Status:           "success",
		})
	}
	return results, nil
}

// BuildServiceEvidenceDescription formats an audit-ready Markdown evidence receipt for DefectDojo.
func BuildServiceEvidenceDescription(host *domain.Host, svc *domain.Service) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## AegisASI Attack Surface Evidence Receipt\n\n")
	fmt.Fprintf(&b, "- **Host:** `%s`", svc.HostIP)
	if host != nil && host.Hostname != "" {
		fmt.Fprintf(&b, " (%s)", host.Hostname)
	}
	fmt.Fprintf(&b, "\n- **Service:** `%d/%s` (%s %s %s)\n", svc.Port, svc.Protocol, svc.ServiceName, svc.Product, svc.Version)
	fmt.Fprintf(&b, "- **Interestingness Score:** `%d/100`\n", svc.Interestingness)
	if host != nil {
		fmt.Fprintf(&b, "- **Lifecycle State:** `%s` | **Environment:** `%s`\n", host.LifecycleState, host.Environment)
	}
	if len(svc.Technologies) > 0 {
		fmt.Fprintf(&b, "\n### Detected Technologies (Noisy-OR Confidence)\n")
		for _, t := range svc.Technologies {
			fmt.Fprintf(&b, "- **%s** %s (%s) — Confidence `%d%%`\n", t.Name, t.Version, t.Category, t.Confidence)
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
