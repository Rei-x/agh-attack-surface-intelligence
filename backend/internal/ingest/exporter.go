package ingest

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ExportJSON writes filtered hosts (with services and merged overrides) as pretty JSON.
func ExportJSON(w io.Writer, hosts []domain.Host) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"count": len(hosts),
		"hosts": hosts,
	})
}

// ExportCSV writes flattened host/service inventory rows as RFC 4180 CSV.
func ExportCSV(w io.Writer, hosts []domain.Host) error {
	cw := csv.NewWriter(w)
	header := []string{
		"ip", "hostname", "lifecycle_state", "environment", "owner", "host_score",
		"port", "protocol", "state", "service_name", "product", "version",
		"http_status", "http_title", "server_header", "favicon_mmh3",
		"technologies", "is_admin_panel", "is_staging_env", "is_iot",
		"service_score", "triage_status", "tags", "notes",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, h := range hosts {
		if len(h.Services) == 0 {
			row := []string{
				h.IP, h.Hostname, h.LifecycleState, h.Environment, h.Owner, strconv.Itoa(h.Interestingness),
				"", "", "", "", "", "",
				"", "", "", "",
				"", "false", "false", "false",
				"0", "", strings.Join(h.Tags, ";"), h.Notes,
			}
			if err := cw.Write(row); err != nil {
				return err
			}
			continue
		}
		for _, s := range h.Services {
			httpStatus, httpTitle, srvHdr, fav := "", "", "", ""
			if s.HTTP != nil {
				if s.HTTP.StatusCode > 0 {
					httpStatus = strconv.Itoa(s.HTTP.StatusCode)
				}
				httpTitle = s.HTTP.Title
				srvHdr = s.HTTP.ServerHeader
				fav = s.HTTP.FaviconMMH3
			}
			techNames := make([]string, 0, len(s.Technologies))
			for _, t := range s.Technologies {
				label := t.Name
				if t.Version != "" {
					label += " " + t.Version
				}
				techNames = append(techNames, label)
			}
			tags := appendUnique(append([]string(nil), h.Tags...), s.Tags...)
			notes := s.Notes
			if notes == "" {
				notes = h.Notes
			}
			row := []string{
				h.IP, h.Hostname, h.LifecycleState, h.Environment, h.Owner, strconv.Itoa(h.Interestingness),
				strconv.Itoa(s.Port), s.Protocol, s.State, s.ServiceName, s.Product, s.Version,
				httpStatus, httpTitle, srvHdr, fav,
				strings.Join(techNames, ";"),
				strconv.FormatBool(s.IsAdminPanel),
				strconv.FormatBool(s.IsStagingEnv),
				strconv.FormatBool(s.IsIoT),
				strconv.Itoa(s.Interestingness), s.TriageStatus,
				strings.Join(tags, ";"), notes,
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}
