package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

func (s *Server) handleIngestManual(w http.ResponseWriter, r *http.Request) {
	var req ingest.ManualEntryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	obs, err := ingest.ParseManual(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if ingest.NormalizeIP(obs.IP) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q nie jest poprawnym adresem IPv4/IPv6 / not a valid IP address", obs.IP))
		return
	}
	for _, svc := range obs.Services {
		if svc.Port < 1 || svc.Port > 65535 {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("port %d poza zakresem 1-65535 / port out of range", svc.Port))
			return
		}
	}
	clean, _, err := ingest.SanitizeObservations([]domain.ObservedHost{obs})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	obs = clean[0]
	res, err := s.pipeline.ProcessObservations(r.Context(), ingest.IngestRequest{
		RunType:      domain.ScanTypeManual,
		ScanName:     nonEmptyStr(req.ScanName, "Manual Entry "+obs.IP),
		Notes:        req.Notes,
		TriggeredBy:  currentUsername(r),
		Observations: []domain.ObservedHost{obs},
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleIngestImport(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	var format, scanName string
	var data []byte

	if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			if isBodyTooLarge(err) {
				writeErr(w, http.StatusRequestEntityTooLarge, ingest.ErrImportTooLarge.Error())
				return
			}
			writeErr(w, http.StatusBadRequest, "failed to parse multipart form: "+err.Error())
			return
		}
		defer func() {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll() // temp files of large uploads
			}
		}()
		format = strings.ToLower(strings.TrimSpace(r.FormValue("format")))
		scanName = strings.TrimSpace(r.FormValue("scan_name"))
		file, hdr, err := r.FormFile("file")
		if err != nil {
			writeErr(w, http.StatusBadRequest, "missing 'file' upload field")
			return
		}
		defer file.Close()
		if format == "" && hdr != nil {
			switch fn := strings.ToLower(hdr.Filename); {
			case strings.HasSuffix(fn, ".csv"):
				format = "csv"
			case strings.HasSuffix(fn, ".xml"):
				format = "nmap"
			default:
				format = "json"
			}
		}
		data, err = io.ReadAll(io.LimitReader(file, maxImportFileBytes+1))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "nie udało się odczytać pliku / failed reading uploaded file")
			return
		}
	} else {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			if isBodyTooLarge(err) {
				writeErr(w, http.StatusRequestEntityTooLarge, ingest.ErrImportTooLarge.Error())
				return
			}
			writeErr(w, http.StatusBadRequest, "failed reading body")
			return
		}
		var env struct {
			Format       string          `json:"format"`
			ScanName     string          `json:"scan_name"`
			Content      string          `json:"content"`
			Observations json.RawMessage `json:"observations"`
			Hosts        json.RawMessage `json:"hosts"`
		}
		if err := json.Unmarshal(raw, &env); err == nil && (env.Format != "" || len(env.Observations) > 0 || len(env.Hosts) > 0 || env.Content != "") {
			format = strings.ToLower(strings.TrimSpace(env.Format))
			scanName = strings.TrimSpace(env.ScanName)
			switch {
			case env.Content != "":
				data = []byte(env.Content)
			case len(env.Observations) > 0:
				data = env.Observations
			case len(env.Hosts) > 0:
				data = env.Hosts
			default:
				data = raw
			}
		} else {
			format = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
			scanName = strings.TrimSpace(r.URL.Query().Get("scan_name"))
			data = raw
		}
	}

	if int64(len(data)) > maxImportFileBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, ingest.ErrImportTooLarge.Error())
		return
	}
	data = ingest.StripNUL(ingest.DecodeText(data))
	if len(bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\ufeff")))) == 0 {
		writeErr(w, http.StatusBadRequest, "plik jest pusty / the file is empty")
		return
	}

	if format == "" {
		trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\ufeff")))
		if len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{') {
			format = "json"
		} else if len(trimmed) > 0 && trimmed[0] == '<' {
			format = "nmap"
		} else {
			format = "csv"
		}
	}

	var observations []domain.ObservedHost
	var err error
	runType := domain.ScanTypeImportJSON
	rawXML := ""

	switch format {
	case "csv":
		runType = domain.ScanTypeImportCSV
		observations, err = ingest.ParseCSV(bytes.NewReader(data))
	case "json", "scb":
		// secureCodeBox findings.json is auto-detected inside the json format too.
		runType = domain.ScanTypeImportJSON
		if format == "scb" || ingest.LooksLikeSCBFindings(data) {
			observations, err = ingest.ParseSCBFindings(bytes.NewReader(data))
		} else {
			observations, err = ingest.ParseJSON(bytes.NewReader(data))
		}
	case "passive":
		runType = domain.ScanTypePassive
		observations, err = ingest.ParseJSON(bytes.NewReader(data))
	case "nmap", "xml":
		// Raw nmap -oX output: same parser the live scanner uses, and the XML is kept on the
		// run so it can be downloaded again or pushed to DefectDojo like a scanned run.
		runType = domain.ScanTypeImportNmap
		rawXML = string(data)
		observations, err = scanner.ParseNmapXML(data)
		if err == nil && len(observations) == 0 {
			err = fmt.Errorf("nmap xml contains no hosts")
		}
	default:
		writeErr(w, http.StatusBadRequest, "unsupported import format (use csv, json, nmap, scb, or passive)")
		return
	}
	skipped := 0
	if err == nil {
		observations, skipped, err = ingest.SanitizeObservations(observations)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	res, err := s.pipeline.ProcessObservations(r.Context(), ingest.IngestRequest{
		RunType:      runType,
		ScanName:     scanName,
		TriggeredBy:  currentUsername(r),
		RawNmapXML:   rawXML,
		Observations: observations,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		*ingest.IngestResult
		SkippedRecords int `json:"skipped_records"`
	}{res, skipped})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format == "" {
		format = "json"
	}

	var hosts []domain.Host
	var err error
	scanID := strings.TrimSpace(q.Get("scan_id"))
	if scanID != "" {
		hosts, err = s.store.GetScanSnapshot(ctx, scanID)
		if err != nil {
			hosts, _, err = s.store.ListHosts(ctx, db.HostFilter{
				State: q.Get("state"),
				Tag:   q.Get("tag"),
			})
		} else {
			// Apply state/tag filters on snapshot hosts too
			stateFilter := q.Get("state")
			tagFilter := q.Get("tag")
			if stateFilter != "" || tagFilter != "" {
				filtered := make([]domain.Host, 0, len(hosts))
				for _, h := range hosts {
					if stateFilter != "" && !strings.EqualFold(h.LifecycleState, stateFilter) {
						continue
					}
					if tagFilter != "" && !hostHasTag(h, tagFilter) {
						continue
					}
					filtered = append(filtered, h)
				}
				hosts = filtered
			}
		}
	} else {
		hosts, _, err = s.store.ListHosts(ctx, db.HostFilter{
			State: q.Get("state"),
			Tag:   q.Get("tag"),
		})
	}
	if err != nil {
		writeStoreErr(w, err)
		return
	}

	eol.AnnotateHosts(hosts, time.Now().UTC())
	stamp := time.Now().UTC().Format("20060102-150405")
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dzieciol-%s.csv"`, stamp))
		_ = ingest.ExportCSV(w, hosts)
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dzieciol-%s.json"`, stamp))
		_ = ingest.ExportJSON(w, hosts)
	case "nmap", "xml":
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dzieciol-%s-nmap.xml"`, stamp))
		_ = ingest.ExportNmapXML(w, hosts)
	case "urls":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dzieciol-%s-urls.txt"`, stamp))
		_ = ingest.ExportURLs(w, hosts)
	case "ecs", "ndjson":
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dzieciol-%s-ecs.ndjson"`, stamp))
		_ = ingest.ExportECS(w, hosts)
	case "scb", "securecodebox":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dzieciol-%s-scb-findings.json"`, stamp))
		_ = ingest.ExportSCB(w, hosts)
	default:
		writeErr(w, http.StatusBadRequest, "format must be json, csv, nmap, urls, ecs or scb")
	}
}

func hostHasTag(h domain.Host, tag string) bool {
	for _, t := range h.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	for _, s := range h.Services {
		for _, t := range s.Tags {
			if strings.EqualFold(t, tag) {
				return true
			}
		}
	}
	return false
}

// handleScanNmapXML serves the merged raw nmap XML (-oX) of a single run, exactly as produced
// by the chunk workers (or as uploaded for IMPORT_NMAP runs).
func (s *Server) handleScanNmapXML(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetScanRun(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if strings.TrimSpace(run.RawNmapXML) == "" {
		writeErr(w, http.StatusNotFound, "this run has no nmap xml")
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dzieciol-run-%s-nmap.xml"`, run.ID))
	_, _ = io.WriteString(w, run.RawNmapXML)
}
