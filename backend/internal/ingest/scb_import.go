package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Import of OWASP secureCodeBox findings.json (see scb_export.go for the format).
//
//   - "Host"       (nmap)      -> live host with hostname / OS
//   - "Open Port"  (nmap)      -> open service (port, protocol, service, product, version)
//   - "SSH Service"(ssh-audit) -> ssh service with its banner
//   - any other category whose location names a host:port (sslyze "TLS Service Info",
//     nmap "FTP"/"SMB" script findings, ...) marks that service and tags it
//     "scb:<category>", so the analyst sees what the SCB scanner flagged.
//
// AegisASI's inventory is keyed by IP, so a finding is used only when an IP address can
// be read from attributes.ip_addresses / ip_address or from the location. Names are never
// resolved during import.

const (
	scbMaxBytes    = 32 << 20
	scbMaxFindings = 500000
)

// LooksLikeSCBFindings reports whether data is a JSON array whose first element has the
// secureCodeBox finding shape (name + category + location/attributes).
func LooksLikeSCBFindings(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return false
	}
	if !dec.More() {
		return false
	}
	var first map[string]json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return false
	}
	_, hasName := first["name"]
	_, hasCat := first["category"]
	_, hasLoc := first["location"]
	_, hasAttr := first["attributes"]
	_, hasSvcs := first["services"]
	return hasName && hasCat && (hasLoc || hasAttr) && !hasSvcs
}

type scbRawFinding struct {
	Name       string         `json:"name"`
	Category   string         `json:"category"`
	Severity   string         `json:"severity"`
	Location   string         `json:"location"`
	Attributes map[string]any `json:"attributes"`
	Port       any            `json:"port"`
}

var scbSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

// ParseSCBFindings converts a secureCodeBox findings.json array into observations.
func ParseSCBFindings(r io.Reader) ([]domain.ObservedHost, error) {
	raw, err := io.ReadAll(io.LimitReader(r, scbMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > scbMaxBytes {
		return nil, fmt.Errorf("secureCodeBox findings file exceeds %d MiB", scbMaxBytes>>20)
	}
	var findings []scbRawFinding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("parse secureCodeBox findings: %w", err)
	}
	if len(findings) > scbMaxFindings {
		return nil, fmt.Errorf("too many findings (%d > %d)", len(findings), scbMaxFindings)
	}

	now := time.Now().UTC()
	hosts := map[string]*domain.ObservedHost{}
	var order []string
	getHost := func(ip string) *domain.ObservedHost {
		h, ok := hosts[ip]
		if !ok {
			h = &domain.ObservedHost{IP: ip, IsAlive: true, ObservedAt: now}
			hosts[ip] = h
			order = append(order, ip)
		}
		return h
	}
	svcIdx := map[string]int{} // ip/proto/port -> index in host.Services
	getSvc := func(h *domain.ObservedHost, port int, proto string) *domain.ObservedService {
		key := h.IP + "/" + proto + "/" + strconv.Itoa(port)
		if i, ok := svcIdx[key]; ok {
			return &h.Services[i]
		}
		svcIdx[key] = len(h.Services)
		h.Services = append(h.Services, domain.ObservedService{Port: port, Protocol: proto, State: "open"})
		return &h.Services[len(h.Services)-1]
	}

	for _, f := range findings {
		attrs := f.Attributes
		if attrs == nil {
			attrs = map[string]any{}
		}
		locScheme, locHost, locPort := splitSCBLocation(f.Location)
		ip := scbFindingIP(attrs, locHost)
		if ip == "" {
			continue
		}
		port := scbInt(attrs["port"])
		if port == 0 {
			port = scbInt(f.Port)
		}
		if port == 0 {
			port = locPort
		}
		proto := strings.ToLower(scbString(attrs["protocol"]))
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			proto = "tcp"
			if locScheme == "udp" {
				proto = "udp"
			}
		}

		if port < 0 || port > 65535 || (f.Category == "Open Port" && port == 0) {
			continue // invalid port: do not even register the host
		}
		if f.Category == "Open Port" {
			if st := strings.ToLower(scbString(attrs["state"])); st != "" && st != "open" {
				continue // SCB lists filtered ports as "Open Port"; AegisASI keeps only open ones
			}
		}
		h := getHost(ip)
		hostname := scbString(attrs["hostname"])
		if hostname == "" && locHost != "" && net.ParseIP(locHost) == nil {
			hostname = locHost
		}
		if hostname != "" && validHostname(hostname) {
			if h.Hostname == "" {
				h.Hostname = hostname
			}
			h.Domains = appendUnique(h.Domains, hostname)
		}
		if osName := scbString(attrs["operating_system"]); osName != "" && h.OSGuess == "" {
			h.OSGuess = truncateField(osName, 200)
		}

		switch f.Category {
		case "Host":
			// host already registered above
		case "Open Port":
			s := getSvc(h, port, proto)
			if name := scbString(attrs["service"]); name != "" {
				if strings.EqualFold(scbString(attrs["tunnel"]), "ssl") && name == "http" {
					name = "https"
				}
				s.ServiceName = truncateField(name, 64)
			}
			if v := scbString(attrs["serviceProduct"]); v != "" {
				s.Product = truncateField(v, 200)
			}
			if v := scbString(attrs["serviceVersion"]); v != "" {
				s.Version = truncateField(v, 100)
			}
			if v := scbString(attrs["cpe"]); v != "" {
				s.CPE = truncateField(v, 200)
			}
			if v := scbString(attrs["banner"]); v != "" {
				s.Banner = truncateField(v, 512)
			} else if scripts, ok := attrs["scripts"].(map[string]any); ok {
				if b := scbString(scripts["banner"]); b != "" {
					s.Banner = truncateField(b, 512)
				}
			}
		case "SSH Service":
			if port == 0 {
				port = 22
			}
			s := getSvc(h, port, "tcp")
			s.ServiceName = "ssh"
			if b := scbString(attrs["server_banner"]); b != "" {
				s.Banner = truncateField(b, 512)
			}
		default:
			tag := "scb:" + strings.Trim(scbSlugRe.ReplaceAllString(strings.ToLower(f.Category), "-"), "-")
			if tag == "scb:" {
				continue
			}
			if port > 0 {
				s := getSvc(h, port, proto)
				if len(s.Tags) < 32 {
					s.Tags = appendUnique(s.Tags, tag)
				}
			} else if len(h.Tags) < 32 {
				h.Tags = appendUnique(h.Tags, tag)
			}
		}
	}

	out := make([]domain.ObservedHost, 0, len(order))
	for _, ip := range order {
		h := hosts[ip]
		sort.Slice(h.Services, func(i, j int) bool {
			if h.Services[i].Port != h.Services[j].Port {
				return h.Services[i].Port < h.Services[j].Port
			}
			return h.Services[i].Protocol < h.Services[j].Protocol
		})
		out = append(out, *h)
	}
	if len(out) == 0 {
		return nil, errors.New("no secureCodeBox findings with an IP address (Host / Open Port) found")
	}
	return out, nil
}

// splitSCBLocation reads "tcp://host:port", "ssh://host", "host:port" or "host".
func splitSCBLocation(loc string) (scheme, host string, port int) {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return "", "", 0
	}
	if strings.Contains(loc, "://") {
		if u, err := url.Parse(loc); err == nil {
			p, _ := strconv.Atoi(u.Port())
			return strings.ToLower(u.Scheme), u.Hostname(), p
		}
		// SCB's nmap parser does not bracket IPv6: "tcp://2001:db8::1:22"
		i := strings.Index(loc, "://")
		scheme, loc = strings.ToLower(loc[:i]), loc[i+3:]
	}
	if net.ParseIP(loc) != nil {
		return scheme, loc, 0
	}
	if h, p, err := net.SplitHostPort(loc); err == nil {
		n, _ := strconv.Atoi(p)
		return scheme, h, n
	}
	if i := strings.LastIndex(loc, ":"); i > 0 && net.ParseIP(loc[:i]) != nil {
		n, _ := strconv.Atoi(loc[i+1:])
		return scheme, loc[:i], n
	}
	return scheme, strings.SplitN(loc, "/", 2)[0], 0
}

func scbFindingIP(attrs map[string]any, locHost string) string {
	var candidates []string
	switch v := attrs["ip_addresses"].(type) {
	case []any:
		for _, x := range v {
			candidates = append(candidates, scbString(x))
		}
	case string:
		candidates = append(candidates, v)
	}
	candidates = append(candidates, scbString(attrs["ip_address"]), locHost)
	for _, c := range candidates {
		if ip := net.ParseIP(strings.TrimSpace(c)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func scbString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

func scbInt(v any) int {
	switch t := v.(type) {
	case float64:
		if t >= 0 && t <= 65535 && t == float64(int(t)) {
			return int(t)
		}
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err == nil && n >= 0 && n <= 65535 {
			return n
		}
	}
	return 0
}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_.-]{0,252})$`)

func validHostname(h string) bool { return hostnameRe.MatchString(h) }

func truncateField(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
