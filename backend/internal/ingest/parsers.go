package ingest

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ManualEntryRequest is accepted by POST /api/v1/ingest/manual.
type ManualEntryRequest struct {
	ScanName    string                   `json:"scan_name,omitempty"`
	IP          string                   `json:"ip"`
	Hostname    string                   `json:"hostname,omitempty"`
	Domains     []string                 `json:"domains,omitempty"`
	OSGuess     string                   `json:"os_guess,omitempty"`
	Environment string                   `json:"environment,omitempty"`
	Tags        []string                 `json:"tags,omitempty"`
	Notes       string                   `json:"notes,omitempty"`
	Services    []domain.ObservedService `json:"services,omitempty"`
	// Convenience flat fields if user submits a single service directly in form
	Port        int                     `json:"port,omitempty"`
	Protocol    string                  `json:"protocol,omitempty"`
	ServiceName string                  `json:"service_name,omitempty"`
	Product     string                  `json:"product,omitempty"`
	Version     string                  `json:"version,omitempty"`
	Banner      string                  `json:"banner,omitempty"`
	HTTP        *domain.HTTPFingerprint `json:"http,omitempty"`
}

// ParseManual normalizes a manual form submission into an ObservedHost.
func ParseManual(req ManualEntryRequest) (domain.ObservedHost, error) {
	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		return domain.ObservedHost{}, errors.New("ip is required")
	}
	svcs := append([]domain.ObservedService(nil), req.Services...)
	if len(svcs) == 0 && req.Port > 0 {
		proto := req.Protocol
		if proto == "" {
			proto = "tcp"
		}
		svcs = append(svcs, domain.ObservedService{
			Port:        req.Port,
			Protocol:    proto,
			State:       "open",
			ServiceName: req.ServiceName,
			Product:     req.Product,
			Version:     req.Version,
			Banner:      req.Banner,
			HTTP:        req.HTTP,
			Tags:        req.Tags,
			Notes:       req.Notes,
		})
	}
	return domain.ObservedHost{
		IP:          ip,
		Hostname:    strings.TrimSpace(req.Hostname),
		Domains:     req.Domains,
		OSGuess:     strings.TrimSpace(req.OSGuess),
		IsAlive:     true,
		Environment: strings.TrimSpace(req.Environment),
		Tags:        req.Tags,
		Notes:       strings.TrimSpace(req.Notes),
		ObservedAt:  time.Now().UTC(),
		Services:    svcs,
	}, nil
}

// ParseCSV flexibly parses CSV exports/inventories into grouped ObservedHosts.
// The delimiter (',' ';' or tab) is detected from the header line, so Excel exports with a
// Polish locale (';') and an optional "sep=;" first line work; quotes are parsed leniently.
func ParseCSV(r io.Reader) ([]domain.ObservedHost, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxImportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read csv: %w", err)
	}
	if int64(len(raw)) > MaxImportBytes {
		return nil, ErrImportTooLarge
	}
	raw = bytes.TrimPrefix(raw, []byte("\ufeff"))
	delim := sniffCSVDelimiter(raw)
	if line, rest, ok := bytes.Cut(raw, []byte("\n")); ok || len(line) > 0 {
		if l := bytes.ToLower(bytes.TrimSpace(line)); bytes.HasPrefix(l, []byte("sep=")) {
			if len(l) > 4 {
				delim = rune(l[4])
			}
			raw = rest
		}
	}
	cr := csv.NewReader(bytes.NewReader(raw))
	cr.Comma = delim
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.LazyQuotes = true

	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(records) < 2 {
		return nil, errors.New("csv must contain a header row and at least one data row")
	}

	headers := make([]string, len(records[0]))
	for i, h := range records[0] {
		headers[i] = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))
	}

	now := time.Now().UTC()
	hostMap := make(map[string]*domain.ObservedHost)
	order := make([]string, 0)

	for _, rec := range records[1:] {
		row := make(map[string]string, len(headers))
		for i, h := range headers {
			if i < len(rec) {
				row[h] = strings.TrimSpace(rec[i])
			}
		}
		ip := firstField(row, "ip", "host", "address", "host_ip", "ip_address")
		if ip == "" {
			continue
		}
		h, exists := hostMap[ip]
		if !exists {
			h = &domain.ObservedHost{
				IP:          ip,
				Hostname:    firstField(row, "hostname", "fqdn", "dns_name"),
				Domains:     splitList(firstField(row, "domains", "domain")),
				OSGuess:     firstField(row, "os", "os_guess"),
				IsAlive:     true,
				Environment: firstField(row, "environment", "env"),
				Tags:        splitList(firstField(row, "tags", "tag")),
				Notes:       firstField(row, "notes", "note", "comment"),
				ObservedAt:  now,
			}
			hostMap[ip] = h
			order = append(order, ip)
		}

		portStr := firstField(row, "port", "port_number")
		if portStr == "" {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		proto := firstField(row, "protocol", "proto")
		if proto == "" {
			proto = "tcp"
		}
		state := firstField(row, "state", "port_state")
		if state == "" {
			state = "open"
		}
		svc := domain.ObservedService{
			Port:        port,
			Protocol:    strings.ToLower(proto),
			State:       strings.ToLower(state),
			ServiceName: firstField(row, "service", "service_name"),
			Product:     firstField(row, "product", "software"),
			Version:     firstField(row, "version"),
			Banner:      firstField(row, "banner"),
			Tags:        splitList(firstField(row, "tags", "service_tags")),
			Notes:       firstField(row, "notes", "service_notes"),
		}

		title := firstField(row, "http_title", "title")
		statusStr := firstField(row, "status_code", "http_status", "status")
		headersStr := firstField(row, "headers", "http_headers")
		cookiesStr := firstField(row, "cookies", "http_cookies")
		serverHdr := firstField(row, "server", "server_header")
		urlStr := firstField(row, "url")
		favMMH3 := firstField(row, "favicon_mmh3", "favicon")

		if title != "" || statusStr != "" || headersStr != "" || cookiesStr != "" || serverHdr != "" || urlStr != "" || favMMH3 != "" {
			statusCode, _ := strconv.Atoi(statusStr)
			scheme := firstField(row, "scheme")
			if scheme == "" {
				if port == 443 || port == 8443 {
					scheme = "https"
				} else {
					scheme = "http"
				}
			}
			if urlStr == "" {
				urlStr = fmt.Sprintf("%s://%s:%d", scheme, ip, port)
			}
			fp := &domain.HTTPFingerprint{
				URL:          urlStr,
				Scheme:       scheme,
				StatusCode:   statusCode,
				Title:        title,
				ServerHeader: serverHdr,
				Headers:      parseKeyValMap(headersStr),
				Cookies:      parseCookiesString(cookiesStr),
				FaviconMMH3:  favMMH3,
			}
			svc.HTTP = fp
		}

		h.Services = append(h.Services, svc)
	}

	out := make([]domain.ObservedHost, 0, len(order))
	for _, ip := range order {
		out = append(out, *hostMap[ip])
	}
	if len(out) == 0 {
		return nil, errors.New("no valid host rows found in csv")
	}
	return out, nil
}

// MaxImportBytes bounds a single imported file (CSV / JSON / nmap XML).
const MaxImportBytes int64 = 64 << 20

// ErrImportTooLarge is returned instead of silently truncating an oversized import.
var ErrImportTooLarge = fmt.Errorf("plik importu jest za duży (limit %d MB) / import file too large (limit %d MB)", MaxImportBytes>>20, MaxImportBytes>>20)

// sniffCSVDelimiter picks the most frequent of , ; and TAB in the first non-"sep=" line.
func sniffCSVDelimiter(raw []byte) rune {
	line := raw
	for {
		l, rest, _ := bytes.Cut(line, []byte("\n"))
		if !bytes.HasPrefix(bytes.ToLower(bytes.TrimSpace(l)), []byte("sep=")) || len(rest) == 0 {
			line = l
			break
		}
		line = rest
	}
	best, bestN := ',', 0
	for _, d := range []rune{',', ';', '\t'} {
		if n := bytes.Count(line, []byte(string(d))); n > bestN {
			best, bestN = d, n
		}
	}
	return best
}

// ParseJSON flexibly parses structured ObservedHost arrays, wrapped {hosts/observations},
// or flat JSON records into []domain.ObservedHost.
func ParseJSON(r io.Reader) ([]domain.ObservedHost, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxImportBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > MaxImportBytes {
		return nil, ErrImportTooLarge
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil, errors.New("empty json payload")
	}

	// 1. Try wrapped object {"hosts": [...]} or {"observations": [...]} or {"data": [...]}
	if raw[0] == '{' {
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrapper); err == nil {
			for _, key := range []string{"hosts", "observations", "items", "data"} {
				if sub, ok := wrapper[key]; ok {
					return ParseJSON(strings.NewReader(string(sub)))
				}
			}
			// Single host object
			return ParseJSON(strings.NewReader("[" + string(raw) + "]"))
		}
	}

	// 2. Try array of generic objects so both nested ObservedHost and flat rows work seamlessly
	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("parse json array: %w", err)
	}

	now := time.Now().UTC()
	hostMap := make(map[string]*domain.ObservedHost)
	order := make([]string, 0)

	for _, item := range items {
		// Check if it already matches domain.ObservedHost shape with "services" array
		if _, hasSvcs := item["services"]; hasSvcs {
			b, _ := json.Marshal(item)
			var h domain.ObservedHost
			if err := json.Unmarshal(b, &h); err == nil && strings.TrimSpace(h.IP) != "" {
				h.IP = strings.TrimSpace(h.IP)
				h.IsAlive = true
				if h.ObservedAt.IsZero() {
					h.ObservedAt = now
				}
				if existing, ok := hostMap[h.IP]; ok {
					existing.Services = append(existing.Services, h.Services...)
				} else {
					cp := h
					hostMap[h.IP] = &cp
					order = append(order, h.IP)
				}
				continue
			}
		}

		// Flat record style (like CSV rows in JSON)
		ip := firstAnyString(item, "ip", "host", "address", "host_ip")
		if ip == "" {
			continue
		}
		h, exists := hostMap[ip]
		if !exists {
			h = &domain.ObservedHost{
				IP:          ip,
				Hostname:    firstAnyString(item, "hostname", "fqdn"),
				Domains:     anyToStringSlice(item["domains"]),
				OSGuess:     firstAnyString(item, "os", "os_guess"),
				IsAlive:     true,
				Environment: firstAnyString(item, "environment", "env"),
				Tags:        anyToStringSlice(item["tags"]),
				Notes:       firstAnyString(item, "notes", "note"),
				ObservedAt:  now,
			}
			hostMap[ip] = h
			order = append(order, ip)
		}

		if port := anyToInt(item["port"]); port > 0 {
			proto := firstAnyString(item, "protocol", "proto")
			if proto == "" {
				proto = "tcp"
			}
			svc := domain.ObservedService{
				Port:        port,
				Protocol:    strings.ToLower(proto),
				State:       nonEmpty(strings.ToLower(firstAnyString(item, "state")), "open"),
				ServiceName: firstAnyString(item, "service", "service_name"),
				Product:     firstAnyString(item, "product"),
				Version:     firstAnyString(item, "version"),
				Banner:      firstAnyString(item, "banner"),
				Tags:        anyToStringSlice(item["tags"]),
				Notes:       firstAnyString(item, "notes"),
			}
			if rawHTTP, ok := item["http"]; ok && rawHTTP != nil {
				b, _ := json.Marshal(rawHTTP)
				var fp domain.HTTPFingerprint
				if json.Unmarshal(b, &fp) == nil {
					svc.HTTP = &fp
				}
			} else {
				title := firstAnyString(item, "http_title", "title")
				sc := anyToInt(item["status_code"])
				srvHdr := firstAnyString(item, "server", "server_header")
				if title != "" || sc > 0 || srvHdr != "" || item["headers"] != nil {
					scheme := "http"
					if port == 443 || port == 8443 {
						scheme = "https"
					}
					fp := &domain.HTTPFingerprint{
						URL:          nonEmpty(firstAnyString(item, "url"), fmt.Sprintf("%s://%s:%d", scheme, ip, port)),
						Scheme:       scheme,
						StatusCode:   sc,
						Title:        title,
						ServerHeader: srvHdr,
						FaviconMMH3:  firstAnyString(item, "favicon_mmh3"),
					}
					if hdrMap, ok := item["headers"].(map[string]any); ok {
						fp.Headers = make(map[string]string, len(hdrMap))
						for k, v := range hdrMap {
							fp.Headers[k] = fmt.Sprint(v)
						}
					}
					svc.HTTP = fp
				}
			}
			h.Services = append(h.Services, svc)
		}
	}

	out := make([]domain.ObservedHost, 0, len(order))
	for _, ip := range order {
		out = append(out, *hostMap[ip])
	}
	if len(out) == 0 {
		return nil, errors.New("no valid hosts found in json payload")
	}
	return out, nil
}

func firstField(row map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(row[k]); v != "" {
			return v
		}
	}
	return ""
}

func firstAnyString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func anyToInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

func anyToStringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, it := range t {
			if s := strings.TrimSpace(fmt.Sprint(it)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return splitList(t)
	default:
		return nil
	}
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	sep := ","
	if strings.Contains(raw, ";") {
		sep = ";"
	} else if strings.Contains(raw, "|") {
		sep = "|"
	}
	parts := strings.Split(raw, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseKeyValMap(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "{") {
		var m map[string]string
		if json.Unmarshal([]byte(raw), &m) == nil {
			return m
		}
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ";") {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			if k != "" {
				out[k] = v
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseCookiesString(raw string) []domain.CookieInfo {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []domain.CookieInfo
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		c := domain.CookieInfo{Name: strings.TrimSpace(kv[0])}
		if len(kv) == 2 {
			c.Value = strings.TrimSpace(kv[1])
		}
		if c.Name != "" {
			out = append(out, c)
		}
	}
	return out
}
