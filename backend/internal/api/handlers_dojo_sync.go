package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// DefectDojo sync status: header chip, per-service "in DefectDojo" status, "push now".

// handleDefectDojoStatus returns what the header chip shows: configured or not, automatic
// push switches, the last sync (time, result, findings, links), the last export and the
// DefectDojo login set in Admin, if any.
func (s *Server) handleDefectDojoStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := db.LoadDefectDojoConfig(ctx, s.store)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	st := db.LoadDefectDojoSync(ctx, s.store)
	st.FindingsByKey = nil // large; served per host by /services
	configured := strings.TrimSpace(cfg.URL) != "" && cfg.HasAPIToken
	out := map[string]any{
		"configured":         configured,
		"url":                cfg.URL,
		"auto_push_nmap":     cfg.AutoPushNmap,
		"auto_push_findings": cfg.AutoPushFindings,
		"sync":               st,
	}
	if items, err := s.store.ListDefectDojoExports(ctx, 1); err == nil && len(items) > 0 {
		out["last_export"] = items[0]
	}
	// Deliberately readable by everyone who sees the chip: the admin put it there for them.
	if login, err := db.LoadDefectDojoLogin(ctx, s.store); err == nil && login != nil {
		out["login"] = login
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDefectDojoServiceStatus returns the DefectDojo findings linked to services (and
// host-level findings), optionally for one host: ?host_id=<id>. Automatic change findings
// come from the last sync; manual pushes from the export history.
//
//	{"services": {"<service_id>": [ref...]}, "hosts": {"<host_id>": [ref...]}}
func (s *Server) handleDefectDojoServiceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := strings.TrimSpace(r.URL.Query().Get("host_id"))
	var serviceIDs map[string]bool
	if hostID != "" {
		h, err := s.store.GetHost(ctx, hostID)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		serviceIDs = make(map[string]bool, len(h.Services))
		for _, sv := range h.Services {
			serviceIDs[sv.ID] = true
		}
	}
	services := map[string][]domain.DefectDojoFindingRef{}
	hosts := map[string][]domain.DefectDojoFindingRef{}
	st := db.LoadDefectDojoSync(ctx, s.store)
	for key, refs := range st.FindingsByKey {
		switch {
		case strings.HasPrefix(key, "service:"):
			id := strings.TrimPrefix(key, "service:")
			if serviceIDs == nil || serviceIDs[id] {
				services[id] = append(services[id], refs...)
			}
		case strings.HasPrefix(key, "host:"):
			id := strings.TrimPrefix(key, "host:")
			if hostID == "" || id == hostID {
				hosts[id] = append(hosts[id], refs...)
			}
		}
	}
	// Manual pushes ("Dzięcioł observations" test), newest first; keep the latest per service.
	if exports, err := s.store.ListDefectDojoExports(ctx, 500); err == nil {
		seen := map[string]bool{}
		for _, e := range exports {
			if e.ExportType != "finding" || e.Status != "success" || seen[e.SourceID] {
				continue
			}
			if serviceIDs != nil && !serviceIDs[e.SourceID] {
				continue
			}
			seen[e.SourceID] = true
			ref := domain.DefectDojoFindingRef{ServiceID: e.SourceID, Kind: "observation", Title: e.Title, URL: e.ExternalURL, State: defectdojo.DojoStateActive, PushedAt: e.CreatedAt}
			if e.ExternalID != "" {
				ref.FindingID = atoiSafe(e.ExternalID)
			}
			services[e.SourceID] = append(services[e.SourceID], ref)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": services, "hosts": hosts, "last_sync_at": st.LastSyncAt})
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// handleDefectDojoSyncNow pushes the change findings of the whole inventory and syncs triage
// right away (the automatic push does the same after each completed run).
func (s *Server) handleDefectDojoSyncNow(w http.ResponseWriter, r *http.Request) {
	cfg, err := db.LoadDefectDojoConfig(r.Context(), s.store)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if strings.TrimSpace(cfg.URL) == "" {
		writeErr(w, http.StatusBadRequest, "DefectDojo integration is not configured")
		return
	}
	// A sync can outlive the request (the first one after an upgrade retires the old
	// per-profile tests): finish it even when the browser or a proxy gives up waiting.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 20*time.Minute)
	defer cancel()
	res, err := defectdojo.SyncNow(ctx, s.store, s.dojo, cfg, currentUsername(r))
	results := []*defectdojo.ChangeSyncResult{res}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "results": results})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// queueDojoSync mirrors analyst triage to DefectDojo a few seconds after the last override
// change (debounced), when automatic findings push is on. Errors are only logged.
func (s *Server) queueDojoSync() {
	s.dojoSyncMu.Lock()
	defer s.dojoSyncMu.Unlock()
	if s.dojoSyncTimer != nil {
		s.dojoSyncTimer.Stop()
	}
	s.dojoSyncTimer = time.AfterFunc(5*time.Second, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		cfg, err := db.LoadDefectDojoConfig(ctx, s.store)
		if err != nil || cfg == nil || strings.TrimSpace(cfg.URL) == "" || !cfg.HasAPIToken || !cfg.AutoPushFindings {
			return
		}
		if _, err := defectdojo.SyncNow(ctx, s.store, s.dojo, cfg, "triage-sync"); err != nil {
			log.Printf("[WARN] DefectDojo triage sync failed: %v", err)
		}
	})
}
