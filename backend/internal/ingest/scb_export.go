package ingest

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// OWASP secureCodeBox interoperability: the unified findings.json format
// (https://www.securecodebox.io/docs/api/finding). Hosts and open ports use the exact
// shape of the SCB nmap parser ("Host" / "Open Port" categories), so SCB cascading rules,
// hooks and DefectDojo's secureCodeBox workflow understand a Dzięcioł export, and the
// importer in scb_import.go reads findings produced by an existing SCB installation.

// SCBFinding is one entry of a secureCodeBox findings.json array.
type SCBFinding struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Description  string         `json:"description,omitempty"`
	Category     string         `json:"category"`
	Severity     string         `json:"severity"`
	Mitigation   string         `json:"mitigation,omitempty"`
	OSILayer     string         `json:"osi_layer,omitempty"`
	Location     string         `json:"location,omitempty"`
	Attributes   map[string]any `json:"attributes"`
	IdentifiedAt string         `json:"identified_at,omitempty"`
	ParsedAt     string         `json:"parsed_at"`
	Scan         *SCBScan       `json:"scan,omitempty"`
	// Port is set by some SCB parsers (ssh-audit) at the top level.
	Port any `json:"port,omitempty"`
}

// SCBScan is the "scan" object every SCB finding carries.
type SCBScan struct {
	CreatedAt string `json:"created_at"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	ScanType  string `json:"scan_type"`
}

// scbFindingID is a stable RFC 4122 (v5-style, SHA-1) UUID, so re-exporting the same
// host/port yields the same id and downstream deduplication keeps working.
func scbFindingID(parts ...string) string {
	sum := sha1.Sum([]byte("aegis-asi/scb\x00" + strings.Join(parts, "\x00")))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func scbHostOrIP(h domain.Host) string {
	if h.Hostname != "" {
		return h.Hostname
	}
	return h.IP
}

func scbTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// BuildSCBFindings converts inventory hosts into secureCodeBox findings: one "Host" per
// host, one "Open Port" per open service, plus passive TLS/SSH findings (sslyze /
// ssh-audit categories) derived from data already collected.
func BuildSCBFindings(hosts []domain.Host, now time.Time) []SCBFinding {
	parsedAt := scbTimestamp(now)
	var latest time.Time
	for _, h := range hosts {
		if h.LastSeen.After(latest) {
			latest = h.LastSeen
		}
	}
	if latest.IsZero() {
		latest = now
	}
	scan := &SCBScan{CreatedAt: scbTimestamp(latest), Name: "aegis-asi-inventory", Namespace: "aegis-asi", ScanType: "aegis-asi"}

	out := make([]SCBFinding, 0, len(hosts)*2)
	for _, h := range hosts {
		hostOrIP := scbHostOrIP(h)
		ips := []string{h.IP}
		var osName any
		if h.OSGuess != "" {
			osName = h.OSGuess
		}
		var hostname any
		if h.Hostname != "" {
			hostname = h.Hostname
		}
		aegisHost := map[string]any{
			"host_id":         h.ID,
			"lifecycle_state": h.LifecycleState,
			"first_seen":      scbTimestamp(h.FirstSeen),
			"last_seen":       scbTimestamp(h.LastSeen),
			"stability_score": h.StabilityScore,
			"interestingness": h.Interestingness,
			"tags":            nonNilStrings(h.Tags),
		}
		if h.Environment != "" {
			aegisHost["environment"] = h.Environment
		}
		if h.Owner != "" {
			aegisHost["owner"] = h.Owner
		}
		out = append(out, SCBFinding{
			ID:           scbFindingID("host", h.IP),
			Name:         "Host: " + hostOrIP,
			Description:  "Found a host",
			Category:     "Host",
			Severity:     "INFORMATIONAL",
			OSILayer:     "NETWORK",
			Location:     hostOrIP,
			IdentifiedAt: scbTimestamp(h.LastSeen),
			ParsedAt:     parsedAt,
			Scan:         scan,
			Attributes: map[string]any{
				"ip_addresses":     ips,
				"hostname":         hostname,
				"operating_system": osName,
				"aegis":            aegisHost,
			},
		})

		for _, s := range h.Services {
			state := strings.ToLower(s.State)
			if state == "" {
				state = "open"
			}
			if state != "open" {
				continue
			}
			proto := strings.ToLower(s.Protocol)
			if proto == "" {
				proto = "tcp"
			}
			portStr := strconv.Itoa(s.Port)
			name := "Open Port: " + portStr
			if s.ServiceName != "" {
				name += " (" + s.ServiceName + ")"
			}
			tunnel := "none"
			if (s.HTTP != nil && s.HTTP.TLS != nil) || strings.Contains(strings.ToLower(s.ServiceName), "https") || strings.HasPrefix(strings.ToLower(s.ServiceName), "ssl") {
				tunnel = "ssl"
			}
			hostPort := net.JoinHostPort(hostOrIP, portStr)
			techs := make([]string, 0, len(s.Technologies))
			for _, t := range s.Technologies {
				label := t.Name
				if t.Version != "" {
					label += " " + t.Version
				}
				techs = append(techs, label)
			}
			aegisSvc := map[string]any{
				"service_id":      s.ID,
				"interestingness": s.Interestingness,
				"triage_status":   s.TriageStatus,
				"technologies":    techs,
				"tags":            nonNilStrings(s.Tags),
				"first_seen":      scbTimestamp(s.FirstSeen),
				"last_seen":       scbTimestamp(s.LastSeen),
			}
			if u := ServiceURL(h, s); u != "" {
				aegisSvc["url"] = u
			}
			if s.HTTP != nil && s.HTTP.Title != "" {
				aegisSvc["http_title"] = s.HTTP.Title
			}
			out = append(out, SCBFinding{
				ID:           scbFindingID("port", h.IP, proto, portStr),
				Name:         name,
				Description:  fmt.Sprintf("Port %d is open using %s protocol.", s.Port, proto),
				Category:     "Open Port",
				Severity:     "INFORMATIONAL",
				OSILayer:     "NETWORK",
				Location:     proto + "://" + hostPort,
				IdentifiedAt: scbTimestamp(s.LastSeen),
				ParsedAt:     parsedAt,
				Scan:         scan,
				Attributes: map[string]any{
					"port":             s.Port,
					"state":            state,
					"ip_addresses":     ips,
					"mac_address":      nil,
					"protocol":         proto,
					"hostname":         hostname,
					"method":           nil,
					"operating_system": osName,
					"service":          nilIfEmpty(s.ServiceName),
					"serviceProduct":   nilIfEmpty(s.Product),
					"serviceVersion":   nilIfEmpty(s.Version),
					"scripts":          nil,
					"tunnel":           tunnel,
					"cpe":              nilIfEmpty(s.CPE),
					"banner":           nilIfEmpty(s.Banner),
					"aegis":            aegisSvc,
				},
			})

			var derived []PassiveFinding
			if s.HTTP != nil {
				derived = append(derived, TLSPassiveFindings(s.HTTP.TLS)...)
			}
			derived = append(derived, SSHPassiveFindings(s)...)
			for _, d := range derived {
				loc := hostPort
				if d.Category == "SSH Service" || d.Category == "SSH Policy Violation" {
					loc = "ssh://" + hostPort
				}
				attrs := map[string]any{"hostname": hostname, "ip_addresses": ips, "port": s.Port}
				for k, v := range d.Attributes {
					attrs[k] = v
				}
				out = append(out, SCBFinding{
					ID:           scbFindingID("derived", h.IP, proto, portStr, d.Name),
					Name:         d.Name,
					Description:  d.Description,
					Category:     d.Category,
					Severity:     d.Severity,
					Mitigation:   d.Mitigation,
					OSILayer:     d.OSILayer,
					Location:     loc,
					IdentifiedAt: scbTimestamp(s.LastSeen),
					ParsedAt:     parsedAt,
					Scan:         scan,
					Attributes:   attrs,
				})
			}
		}
	}
	return out
}

// ExportSCB writes the inventory as a secureCodeBox findings.json array.
func ExportSCB(w io.Writer, hosts []domain.Host) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(BuildSCBFindings(hosts, time.Now().UTC()))
}
