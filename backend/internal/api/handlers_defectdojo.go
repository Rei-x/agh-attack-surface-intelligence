package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
)

func (s *Server) handleGetDefectDojoConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := db.LoadDefectDojoConfig(r.Context(), s.store)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	// Never return plaintext API token back to client
	safe := *cfg
	safe.APIToken = ""
	writeJSON(w, http.StatusOK, safe)
}

const errDojoURL = "DefectDojo URL must be an absolute http(s) URL, e.g. https://dojo.example:8443"

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func (s *Server) handleSaveDefectDojoConfig(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	var cfg domain.DefectDojoConfig
	var opt struct {
		AutoPushFindings *bool `json:"auto_push_findings"`
	}
	if err := decodeJSON(r, &raw); err != nil || json.Unmarshal(raw, &cfg) != nil || json.Unmarshal(raw, &opt) != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	// auto_push_findings lives in the settings store; omitted = keep the current value.
	if opt.AutoPushFindings == nil {
		if cur, err := db.LoadDefectDojoConfig(r.Context(), s.store); err == nil && cur != nil {
			cfg.AutoPushFindings = cur.AutoPushFindings
		}
	} else {
		cfg.AutoPushFindings = *opt.AutoPushFindings
	}
	cfg.URL = strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if cfg.URL != "" && !isHTTPURL(cfg.URL) {
		writeErr(w, http.StatusBadRequest, errDojoURL)
		return
	}
	if cfg.ProductID < 0 || cfg.EngagementID < 0 {
		writeErr(w, http.StatusBadRequest, "product_id / engagement_id must not be negative")
		return
	}
	if err := s.store.SaveDefectDojoConfig(r.Context(), &cfg); err != nil {
		writeStoreErr(w, err)
		return
	}
	if err := db.SaveDefectDojoOptions(r.Context(), s.store, &cfg); err != nil {
		writeStoreErr(w, err)
		return
	}
	saved, err := db.LoadDefectDojoConfig(r.Context(), s.store)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	saved.APIToken = ""
	writeJSON(w, http.StatusOK, saved)
}

// handleSaveDefectDojoLogin stores the DefectDojo account the header chip shows to everyone
// signed in. Both fields empty clears it.
func (s *Server) handleSaveDefectDojoLogin(w http.ResponseWriter, r *http.Request) {
	var req domain.DefectDojoLogin
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" && req.Password == "" {
		s.handleClearDefectDojoLogin(w, r)
		return
	}
	switch {
	case req.Username == "" || req.Password == "":
		writeErr(w, http.StatusBadRequest, "username and password are both required (send both empty to clear the login)")
		return
	case len(req.Username) > 150 || len(req.Password) > 256: // 150: Django's username limit
		writeErr(w, http.StatusBadRequest, "username must be at most 150 characters and password at most 256")
		return
	case strings.ContainsFunc(req.Username+req.Password, unicode.IsControl):
		writeErr(w, http.StatusBadRequest, "username and password must not contain control characters or line breaks")
		return
	}
	if err := db.SaveDefectDojoLogin(r.Context(), s.store, &req); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"login": req})
}

func (s *Server) handleClearDefectDojoLogin(w http.ResponseWriter, r *http.Request) {
	if err := db.SaveDefectDojoLogin(r.Context(), s.store, nil); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"login": nil})
}

func (s *Server) handleTestDefectDojo(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetDefectDojoConfig(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var override domain.DefectDojoConfig
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &override); err == nil {
			if strings.TrimSpace(override.URL) != "" {
				cfg.URL = override.URL
			}
			if strings.TrimSpace(override.APIToken) != "" {
				cfg.APIToken = override.APIToken
			}
			if override.EngagementID > 0 {
				cfg.EngagementID = override.EngagementID
			}
		}
	}
	if strings.TrimSpace(cfg.URL) == "" || !isHTTPURL(strings.TrimSpace(cfg.URL)) {
		writeErr(w, http.StatusBadRequest, errDojoURL)
		return
	}
	st, err := s.dojo.TestConnection(r.Context(), cfg)
	if err != nil && st == nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if !st.OK {
		writeJSON(w, http.StatusBadGateway, st)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handlePushDefectDojoFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		ServiceIDs   []string `json:"service_ids"`
		ChangeIDs    []string `json:"change_ids"`
		EngagementID int      `json:"engagement_id"`
		Severity     string   `json:"severity"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	cfg, err := s.store.GetDefectDojoConfig(ctx)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if strings.TrimSpace(cfg.URL) == "" {
		writeErr(w, http.StatusBadRequest, "DefectDojo integration is not configured")
		return
	}

	var inputs []defectdojo.FindingInput
	for _, sid := range req.ServiceIDs {
		svc, err := s.store.GetService(ctx, sid)
		if err != nil {
			continue
		}
		host, _ := s.store.GetHost(ctx, svc.HostID)
		eol.Annotate(svc, time.Now().UTC())
		sev := req.Severity
		if sev == "" {
			// From the recalibrated score; an exposed console or a staging instance is at
			// least Medium whatever else is (not) known about it.
			sev = domain.ScoreSeverity(svc.Interestingness)
			if (svc.IsAdminPanel || svc.IsStagingEnv) && (sev == "Low" || sev == "Info") {
				sev = "Medium"
			}
		}
		title := fmt.Sprintf("Exposed Service %s:%d/%s (%s)", svc.HostIP, svc.Port, svc.Protocol, nonEmptyStr(svc.Product, svc.ServiceName))
		if svc.IsAdminPanel {
			title = fmt.Sprintf("Exposed Admin Panel on %s:%d (%s)", svc.HostIP, svc.Port, svc.ServiceName)
		}
		inputs = append(inputs, defectdojo.FindingInput{
			SourceID:    svc.ID,
			HostIP:      svc.HostIP,
			Port:        svc.Port,
			Protocol:    svc.Protocol,
			Title:       title,
			Description: defectdojo.BuildServiceEvidenceDescription(host, svc),
			Severity:    sev,
			Tags:        svc.Tags,
		})
	}

	if len(req.ChangeIDs) > 0 {
		allChanges, _ := s.store.ListChangeEvents(ctx, db.ChangeFilter{Limit: 500})
		changeByID := make(map[string]domain.ChangeEvent, len(allChanges))
		for _, c := range allChanges {
			changeByID[c.ID] = c
		}
		for _, cid := range req.ChangeIDs {
			ev, ok := changeByID[cid]
			if !ok {
				continue
			}
			sev := nonEmptyStr(req.Severity, ev.Severity)
			owner, _ := ev.After["owner"].(string)
			if owner == "" && ev.HostID != "" {
				if h, herr := s.store.GetHost(ctx, ev.HostID); herr == nil {
					owner = h.Owner
				}
			}
			inputs = append(inputs, defectdojo.FindingInput{
				SourceID:    ev.ID,
				HostIP:      ev.HostIP,
				Port:        ev.Port,
				Protocol:    "tcp",
				Title:       fmt.Sprintf("[%s] %s", ev.EventType, ev.Summary),
				Description: fmt.Sprintf("## Attack Surface Change Detected\n\n- **Host:** `%s`\n- **Event:** `%s`\n- **Time Slot:** `%s`\n- **Summary:** %s\n- **Owner (CIDR rule):** %s\n", ev.HostIP, ev.EventType, ev.TimeSlot, ev.Summary, nonEmptyStr(owner, "none")),
				Severity:    sev,
				Tags:        []string{strings.ToLower(ev.EventType)},
			})
		}
	}

	if len(inputs) == 0 {
		writeErr(w, http.StatusBadRequest, "no valid service_ids or change_ids selected")
		return
	}

	results, err := s.dojo.PushFindings(ctx, cfg, req.EngagementID, inputs)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	user := currentUsername(r)
	succeeded := 0
	for _, res := range results {
		if res.Status == "success" {
			succeeded++
		}
		_ = s.store.AddDefectDojoExport(ctx, &domain.DefectDojoExport{
			ExportType:   "finding",
			SourceID:     res.SourceID,
			Title:        res.Title,
			ExternalID:   res.ExternalID,
			ExternalURL:  res.ExternalURL,
			Status:       res.Status,
			ErrorMessage: res.Error,
			ExportedBy:   user,
			CreatedAt:    time.Now().UTC(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pushed":  succeeded,
		"total":   len(results),
		"results": results,
	})
}

func (s *Server) handlePushDefectDojoNmap(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		ScanRunID    string `json:"scan_run_id"`
		EngagementID int    `json:"engagement_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	cfg, err := s.store.GetDefectDojoConfig(ctx)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	run, err := s.store.GetScanRun(ctx, req.ScanRunID)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if strings.TrimSpace(run.RawNmapXML) == "" {
		writeErr(w, http.StatusBadRequest, "scan run does not contain raw Nmap XML")
		return
	}

	// One DefectDojo test per scan profile: each run reimports into it, so DefectDojo
	// closes services that disappeared since the previous run of the same profile.
	profileName := ""
	if run.ProfileID != "" {
		if p, perr := s.store.GetProfile(ctx, run.ProfileID); perr == nil && p != nil {
			profileName = p.Name
		}
	}
	if profileName == "" {
		profileName = run.Name
	}
	imp, err := s.dojo.ImportNmapXML(ctx, cfg, req.EngagementID, defectdojo.NmapTestTitle(profileName), run.Name, run.RawNmapXML)
	exp := &domain.DefectDojoExport{
		ExportType: "nmap_xml",
		SourceID:   run.ID,
		Title:      "Nmap Scan: " + run.Name,
		ExportedBy: currentUsername(r),
		CreatedAt:  time.Now().UTC(),
	}
	if err != nil {
		exp.Status = "failed"
		exp.ErrorMessage = err.Error()
		_ = s.store.AddDefectDojoExport(ctx, exp)
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	exp.Status = "success"
	exp.ExternalID = imp.ExternalID
	exp.ExternalURL = imp.ExternalURL
	_ = s.store.AddDefectDojoExport(ctx, exp)
	writeJSON(w, http.StatusOK, imp)
}

func (s *Server) handleDefectDojoHistory(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListDefectDojoExports(r.Context(), queryInt(r, "limit", 100))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exports": items, "history": items})
}
