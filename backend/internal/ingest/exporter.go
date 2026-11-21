package ingest

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ExportJSON writes filtered hosts (with services and merged overrides) as pretty JSON.
// Hosts are encoded one at a time, so a large inventory is streamed instead of being
// marshalled into one buffer first.
func ExportJSON(w io.Writer, hosts []domain.Host) error {
	bw := bufio.NewWriterSize(w, 64<<10)
	if _, err := fmt.Fprintf(bw, "{\n  \"count\": %d,\n  \"hosts\": [", len(hosts)); err != nil {
		return err
	}
	for i := range hosts {
		b, err := json.MarshalIndent(&hosts[i], "    ", "  ")
		if err != nil {
			return err
		}
		sep := ",\n    "
		if i == 0 {
			sep = "\n    "
		}
		if _, err := bw.WriteString(sep); err != nil {
			return err
		}
		if _, err := bw.Write(b); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString("\n  ]\n}\n"); err != nil {
		return err
	}
	return bw.Flush()
}

// csvSafe neutralizes spreadsheet formula injection: banners, titles and server headers come
// from scanned (potentially hostile) hosts, and a cell starting with = + - @ would be executed
// by Excel/LibreOffice when an analyst opens the export.
func csvSafe(row []string) []string {
	for i, v := range row {
		if v == "" {
			continue
		}
		switch v[0] {
		case '=', '+', '-', '@', '\t', '\r':
			if _, err := strconv.ParseFloat(v, 64); err != nil {
				row[i] = "'" + v
			}
		}
	}
	return row
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
			if err := cw.Write(csvSafe(row)); err != nil {
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
			if err := cw.Write(csvSafe(row)); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}
