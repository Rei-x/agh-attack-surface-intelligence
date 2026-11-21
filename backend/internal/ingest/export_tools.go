package ingest

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// Exports aimed at the tools the security team already runs:
//   - nmap XML  -> DefectDojo "Nmap Scan", Metasploit db_import, nmap-to-anything converters
//   - urls      -> httpx / nuclei / gowitness / ffuf target lists (one URL per line)
//   - ecs       -> NDJSON in Elastic Common Schema, ready for ELK / Splunk HEC ingestion

// HostsToObserved converts inventory hosts back into scanner observations.
func HostsToObserved(hosts []domain.Host) []domain.ObservedHost {
	out := make([]domain.ObservedHost, 0, len(hosts))
	for _, h := range hosts {
		oh := domain.ObservedHost{
			IP:         h.IP,
			Hostname:   h.Hostname,
			Domains:    h.Domains,
			OSGuess:    h.OSGuess,
			IsAlive:    !strings.EqualFold(h.LifecycleState, domain.HostStateMissing) && !strings.EqualFold(h.LifecycleState, domain.HostStateInactive),
			ObservedAt: h.LastSeen,
		}
		for _, s := range h.Services {
			state := s.State
			if state == "" {
				state = "open"
			}
			oh.Services = append(oh.Services, domain.ObservedService{
				Port:        s.Port,
				Protocol:    s.Protocol,
				State:       state,
				ServiceName: s.ServiceName,
				Product:     s.Product,
				Version:     s.Version,
				CPE:         s.CPE,
				Banner:      s.Banner,
			})
		}
		out = append(out, oh)
	}
	return out
}

// ExportNmapXML writes the inventory as a standard nmap XML (-oX) document.
func ExportNmapXML(w io.Writer, hosts []domain.Host) error {
	var first, last time.Time
	for _, h := range hosts {
		if !h.LastSeen.IsZero() && (first.IsZero() || h.LastSeen.Before(first)) {
			first = h.LastSeen
		}
		if h.LastSeen.After(last) {
			last = h.LastSeen
		}
	}
	doc := scanner.GenerateNmapXML(HostsToObserved(hosts), "nmap -sT -sV (Dzięcioł inventory export)", first, last)
	if doc == "" {
		return fmt.Errorf("failed to render nmap xml")
	}
	_, err := io.WriteString(w, doc)
	return err
}

// ServiceURL returns the base URL for a web service, or "" when the service is not HTTP(S).
func ServiceURL(h domain.Host, s domain.Service) string {
	if s.State != "" && !strings.EqualFold(s.State, "open") {
		return ""
	}
	name := strings.ToLower(s.ServiceName)
	scheme := ""
	switch {
	case s.HTTP != nil && s.HTTP.Scheme != "":
		scheme = strings.ToLower(s.HTTP.Scheme)
	case s.HTTP != nil && strings.HasPrefix(strings.ToLower(s.HTTP.URL), "https://"):
		scheme = "https"
	case s.HTTP != nil && s.HTTP.TLS != nil:
		scheme = "https"
	case strings.Contains(name, "https") || strings.Contains(name, "ssl/http") || name == "http-alt-ssl":
		scheme = "https"
	case strings.HasPrefix(name, "http") || s.HTTP != nil:
		scheme = "http"
	case s.Port == 443 || s.Port == 8443:
		scheme = "https"
	case s.Port == 80 || s.Port == 8080 || s.Port == 8000 || s.Port == 8888:
		scheme = "http"
	default:
		return ""
	}
	if scheme != "http" && scheme != "https" {
		return ""
	}
	if h.IP == "" {
		return ""
	}
	if (scheme == "http" && s.Port == 80) || (scheme == "https" && s.Port == 443) {
		return scheme + "://" + hostLiteral(h.IP)
	}
	return scheme + "://" + net.JoinHostPort(h.IP, strconv.Itoa(s.Port))
}

func hostLiteral(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

// ExportURLs writes one deduplicated, sorted base URL per line for every HTTP(S) service.
func ExportURLs(w io.Writer, hosts []domain.Host) error {
	seen := make(map[string]struct{})
	urls := make([]string, 0)
	for _, h := range hosts {
		for _, s := range h.Services {
			u := ServiceURL(h, s)
			if u == "" {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			urls = append(urls, u)
		}
	}
	sort.Strings(urls)
	for _, u := range urls {
		if _, err := io.WriteString(w, u+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// ExportECS writes NDJSON documents in Elastic Common Schema (one per service, or one per
// host without services). event.kind=state marks them as asset inventory snapshots.
func ExportECS(w io.Writer, hosts []domain.Host) error {
	enc := json.NewEncoder(w)
	ingested := time.Now().UTC().Format(time.RFC3339)
	for _, h := range hosts {
		host := map[string]any{"ip": []string{h.IP}}
		if h.Hostname != "" {
			host["name"] = h.Hostname
			host["hostname"] = h.Hostname
		}
		if h.OSGuess != "" {
			host["os"] = map[string]any{"full": h.OSGuess}
		}
		hostDz := map[string]any{
			"host_id":         h.ID,
			"lifecycle_state": h.LifecycleState,
			"host_score":      h.Interestingness,
			"stability_score": h.StabilityScore,
			"first_seen":      h.FirstSeen.UTC().Format(time.RFC3339),
		}
		if h.Environment != "" {
			hostDz["environment"] = h.Environment
		}
		if h.Owner != "" {
			hostDz["owner"] = h.Owner
		}
		ts := h.LastSeen
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		base := func() map[string]any {
			return map[string]any{
				"@timestamp": ts.UTC().Format(time.RFC3339),
				"ecs":        map[string]any{"version": "8.11.0"},
				"event": map[string]any{
					"kind":     "state",
					"category": []string{"host", "network"},
					"type":     []string{"info"},
					"dataset":  "dzieciol.asset",
					"module":   "dzieciol",
					"ingested": ingested,
				},
				"observer": map[string]any{"vendor": "CBI AGH", "product": "Dzięcioł", "type": "scanner"},
				"host":     host,
			}
		}
		if len(h.Services) == 0 {
			doc := base()
			doc["tags"] = nonNilStrings(h.Tags)
			doc["dzieciol"] = hostDz
			if err := enc.Encode(doc); err != nil {
				return err
			}
			continue
		}
		for _, s := range h.Services {
			doc := base()
			proto := s.Protocol
			if proto == "" {
				proto = "tcp"
			}
			network := map[string]any{"transport": strings.ToLower(proto)}
			if s.ServiceName != "" {
				network["protocol"] = strings.ToLower(s.ServiceName)
			}
			doc["network"] = network
			doc["destination"] = map[string]any{"ip": h.IP, "port": s.Port}
			doc["server"] = map[string]any{"ip": h.IP, "port": s.Port}
			svcDz := map[string]any{
				"service_id":         s.ID,
				"state":              s.State,
				"service_score":      s.Interestingness,
				"triage_status":      s.TriageStatus,
				"is_admin_panel":     s.IsAdminPanel,
				"is_staging_env":     s.IsStagingEnv,
				"is_iot":             s.IsIoT,
				"first_seen":         s.FirstSeen.UTC().Format(time.RFC3339),
				"last_seen":          s.LastSeen.UTC().Format(time.RFC3339),
				"matched_signatures": nonNilStrings(s.MatchedSignatures),
			}
			if s.Product != "" {
				svcDz["product"] = s.Product
			}
			if s.Version != "" {
				svcDz["version"] = s.Version
			}
			if s.CPE != "" {
				svcDz["cpe"] = s.CPE
			}
			if s.Banner != "" {
				svcDz["banner"] = s.Banner
			}
			techs := make([]string, 0, len(s.Technologies))
			for _, t := range s.Technologies {
				label := t.Name
				if t.Version != "" {
					label += " " + t.Version
				}
				techs = append(techs, label)
			}
			svcDz["technologies"] = techs
			if u := ServiceURL(h, s); u != "" {
				doc["url"] = map[string]any{"full": u, "scheme": strings.SplitN(u, "://", 2)[0], "port": s.Port}
			}
			if s.HTTP != nil {
				resp := map[string]any{}
				if s.HTTP.StatusCode > 0 {
					resp["status_code"] = s.HTTP.StatusCode
				}
				if len(resp) > 0 {
					doc["http"] = map[string]any{"response": resp}
				}
				if s.HTTP.ServerHeader != "" {
					svcDz["server_header"] = s.HTTP.ServerHeader
				}
				if s.HTTP.Title != "" {
					svcDz["http_title"] = s.HTTP.Title
				}
				if s.HTTP.FaviconMMH3 != "" {
					svcDz["favicon_mmh3"] = s.HTTP.FaviconMMH3
				}
			}
			doc["tags"] = appendUnique(append([]string{}, h.Tags...), s.Tags...)
			doc["dzieciol"] = map[string]any{"host": hostDz, "service": svcDz}
			if err := enc.Encode(doc); err != nil {
				return err
			}
		}
	}
	return nil
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
