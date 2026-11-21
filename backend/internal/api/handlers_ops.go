package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/notify"
)

// Daily-operations endpoints: triage decisions with expiry, host timeline, CIDR tag rules
// and the alert webhook.

// ---------- Triage (accepted risk / false positive with expiry) ----------

const maxTriageReason = 2000

// applyTriagePatch interprets the "triage" (and legacy "triage_status") keys of an overrides
// PATCH body. Decisions that hide a finding (accepted_risk / false_positive) require a reason;
// author and timestamp are always set server-side. isService enables the legacy
// new/triaged workflow statuses which only exist on services.
func applyTriagePatch(body, patch map[string]any, unlock *[]string, username string, isService bool, now time.Time) error {
	if legacy, ok := body["triage_status"]; ok && isService {
		st, _ := legacy.(string)
		if _, hasTriage := body["triage"]; !hasTriage {
			if st == domain.TriageAcceptedRisk || st == domain.TriageFalsePositive {
				return errors.New(`accepted_risk / false_positive require a reason: send {"triage": {"status", "reason", "expires_at"}}`)
			}
			// Moving back to a workflow status clears an earlier acceptance.
			*unlock = append(*unlock, "triage")
		}
	}
	raw, ok := body["triage"]
	if !ok {
		return nil
	}
	delete(patch, "triage")
	if raw == nil {
		*unlock = append(*unlock, "triage")
		return nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return errors.New("triage must be an object or null")
	}
	status := strings.ToLower(strings.TrimSpace(fmt.Sprint(obj["status"])))
	switch status {
	case domain.TriageAcceptedRisk, domain.TriageFalsePositive:
	case domain.TriageNew, domain.TriageTriaged, "", "<nil>":
		*unlock = append(*unlock, "triage")
		if isService && (status == domain.TriageNew || status == domain.TriageTriaged) {
			patch["triage_status"] = status
		}
		return nil
	default:
		return fmt.Errorf("unknown triage status %q", status)
	}
	reason, _ := obj["reason"].(string)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return errors.New("triage reason is required for accepted_risk / false_positive")
	}
	if len(reason) > maxTriageReason {
		return fmt.Errorf("triage reason too long (max %d chars)", maxTriageReason)
	}
	info := domain.TriageInfo{Status: status, Reason: reason, By: username, At: now.UTC()}
	if expRaw, _ := obj["expires_at"].(string); strings.TrimSpace(expRaw) != "" {
		exp, err := parseExpiry(strings.TrimSpace(expRaw))
		if err != nil {
			return err
		}
		if !exp.After(now) {
			return errors.New("expires_at must be in the future")
		}
		info.ExpiresAt = &exp
	}
	patch["triage"] = info
	if isService {
		// One source of truth: the decision replaces a pinned legacy workflow status.
		*unlock = append(*unlock, "triage_status")
		delete(patch, "triage_status")
	}
	return nil
}

// parseExpiry accepts RFC3339 or a plain date (valid through the end of that day, UTC).
func parseExpiry(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if d, err := time.Parse("2006-01-02", s); err == nil {
		return d.Add(24 * time.Hour).UTC(), nil
	}
	return time.Time{}, errors.New("expires_at must be RFC3339 or YYYY-MM-DD")
}

// ---------- Host timeline ----------

func (s *Server) handleHostTimeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host, err := s.store.GetHost(ctx, r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	portFilter := queryInt(r, "port", 0)
	limit := queryInt(r, "limit", 500)
	if limit <= 0 || limit > 5000 {
		limit = 500
	}

	entries := make([]domain.HostTimelineEntry, 0)
	events, err := s.store.ListChangeEvents(ctx, db.ChangeFilter{HostID: host.ID, Limit: limit})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	sawNewHost := false
	for _, ev := range events {
		if ev.HostID != host.ID {
			continue
		}
		if ev.EventType == "NEW_HOST" {
			sawNewHost = true
		}
		if portFilter > 0 && ev.Port != portFilter {
			continue
		}
		details := map[string]any{}
		if len(ev.Before) > 0 {
			details["before"] = ev.Before
		}
		if len(ev.After) > 0 {
			details["after"] = ev.After
		}
		if ev.IsTimeAnomaly {
			details["time_anomaly"] = true
		}
		entries = append(entries, domain.HostTimelineEntry{
			Kind:      "change",
			At:        ev.CreatedAt,
			EventType: ev.EventType,
			Severity:  ev.Severity,
			Summary:   ev.Summary,
			ServiceID: ev.ServiceID,
			Port:      ev.Port,
			ScanRunID: ev.ScanRunID,
			Details:   details,
		})
	}

	// Observations collapsed into spans of identical state/product/version, so 30 daily scans
	// of an unchanged service are one row ("seen 30x between ... and ...").
	for _, svc := range host.Services {
		if portFilter > 0 && svc.Port != portFilter {
			continue
		}
		obs, err := s.store.ListServiceObservations(ctx, svc.ID, limit)
		if err != nil {
			continue
		}
		sort.Slice(obs, func(i, j int) bool { return obs[i].ObservedAt.Before(obs[j].ObservedAt) })
		var cur *domain.HostTimelineEntry
		var curKey string
		flush := func() {
			if cur != nil {
				entries = append(entries, *cur)
				cur = nil
			}
		}
		for _, o := range obs {
			title := ""
			if o.HTTP != nil {
				title = o.HTTP.Title
			}
			key := o.State + "|" + o.Product + "|" + o.Version + "|" + title
			if cur != nil && key == curKey {
				cur.Count++
				until := o.ObservedAt
				cur.Until = &until
				continue
			}
			flush()
			curKey = key
			desc := strings.TrimSpace(strings.Join([]string{o.ServiceName, o.Product, o.Version}, " "))
			summary := fmt.Sprintf("%d/%s %s · %s", o.Port, o.Protocol, o.State, desc)
			if title != "" {
				summary += fmt.Sprintf(" · %q", title)
			}
			cur = &domain.HostTimelineEntry{
				Kind:      "observation",
				At:        o.ObservedAt,
				Count:     1,
				Summary:   summary,
				ServiceID: o.ServiceID,
				Port:      o.Port,
				Protocol:  o.Protocol,
				ScanRunID: o.ScanRunID,
				Details: map[string]any{
					"state":   o.State,
					"service": o.ServiceName,
					"product": o.Product,
					"version": o.Version,
					"title":   title,
				},
			}
		}
		flush()
	}

	if !sawNewHost && portFilter == 0 && !host.FirstSeen.IsZero() {
		entries = append(entries, domain.HostTimelineEntry{
			Kind:    "first_seen",
			At:      host.FirstSeen,
			Summary: fmt.Sprintf("Host %s first seen", host.IP),
		})
	}

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].At.After(entries[j].At) })
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id":    host.ID,
		"host_ip":    host.IP,
		"first_seen": host.FirstSeen,
		"entries":    entries,
	})
}

// ---------- CIDR tag rules (ownership) ----------

func (s *Server) settingsStore(w http.ResponseWriter) (db.SettingsStore, bool) {
	ss, ok := s.store.(db.SettingsStore)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "store backend does not support settings")
	}
	return ss, ok
}

func (s *Server) handleListTagRules(w http.ResponseWriter, r *http.Request) {
	rules := ingest.LoadTagRules(r.Context(), s.store)
	if rules == nil {
		rules = []domain.TagRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// handleSaveTagRules replaces the full rule list (the UI edits it as one table).
func (s *Server) handleSaveTagRules(w http.ResponseWriter, r *http.Request) {
	ss, ok := s.settingsStore(w)
	if !ok {
		return
	}
	var raw struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if err := decodeJSON(r, &raw); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	var body struct{ Rules []domain.TagRule }
	for _, rr := range raw.Rules {
		var rule domain.TagRule
		var fields map[string]json.RawMessage
		if json.Unmarshal(rr, &rule) != nil || json.Unmarshal(rr, &fields) != nil {
			writeErr(w, http.StatusBadRequest, "invalid rule")
			return
		}
		// A rule sent without "enabled" is meant to be active; silently storing it disabled
		// made API-created rules look broken.
		if _, set := fields["enabled"]; !set {
			rule.Enabled = true
		}
		body.Rules = append(body.Rules, rule)
	}
	if len(body.Rules) > 1000 {
		writeErr(w, http.StatusBadRequest, "too many rules (max 1000)")
		return
	}
	prev := map[string]domain.TagRule{}
	for _, p := range ingest.LoadTagRules(r.Context(), s.store) {
		prev[p.ID] = p
	}
	now := time.Now().UTC()
	user := currentUsername(r)
	for i := range body.Rules {
		rule := &body.Rules[i]
		if err := ingest.NormalizeTagRule(rule); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if old, ok := prev[rule.ID]; ok && rule.ID != "" {
			rule.CreatedBy, rule.CreatedAt = old.CreatedBy, old.CreatedAt
		} else {
			rule.ID = db.NewID()
			rule.CreatedBy, rule.CreatedAt = user, now
		}
	}
	if err := ss.SaveSetting(r.Context(), db.SettingTagRules, body.Rules); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": body.Rules})
}

// handleApplyTagRules applies the rules to the existing inventory right away (normally they
// apply on the next ingest of each host).
func (s *Server) handleApplyTagRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rules := ingest.LoadTagRules(ctx, s.store)
	if len(rules) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"updated": 0, "checked": 0})
		return
	}
	hosts, _, err := s.store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	updated := 0
	for i := range hosts {
		h := hosts[i]
		observedView(&h)
		if !ingest.ApplyTagRules(&h, rules) {
			continue
		}
		h.Services = nil
		if _, err := s.store.UpsertObservedHost(ctx, &h); err != nil {
			writeStoreErr(w, err)
			return
		}
		updated++
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": updated, "checked": len(hosts)})
}

// observedView undoes the analyst-override merge on a listed host for the fields a tag rule
// may touch, so re-upserting it does not copy override values into the observed record.
func observedView(h *domain.Host) {
	for _, f := range h.LockedFields {
		v, has := h.ScannerObserved[f]
		switch f {
		case "owner":
			h.Owner, _ = v.(string)
		case "environment":
			h.Environment, _ = v.(string)
		case "tags":
			if t, ok := v.([]string); has && ok {
				h.Tags = append([]string(nil), t...)
			}
		case "hostname":
			if sv, ok := v.(string); has && ok {
				h.Hostname = sv
			}
		case "notes":
			if sv, ok := v.(string); has && ok {
				h.Notes = sv
			}
		case "lifecycle_state":
			if sv, ok := v.(string); has && ok {
				h.LifecycleState = sv
			}
		}
	}
}

// ---------- Alert webhook ----------

func (s *Server) handleGetWebhook(w http.ResponseWriter, r *http.Request) {
	cfg, err := notify.LoadConfig(r.Context(), s.store)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, notify.Public(cfg))
}

func (s *Server) handleSaveWebhook(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.settingsStore(w); !ok {
		return
	}
	var body struct {
		URL                *string `json:"url"`
		ClearURL           bool    `json:"clear_url"`
		Enabled            *bool   `json:"enabled"`
		MinSeverity        *string `json:"min_severity"`
		NotifyStateChanges *bool   `json:"notify_state_changes"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	cfg, err := notify.LoadConfig(r.Context(), s.store)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	// An empty / omitted URL keeps the stored secret (the UI never receives it back).
	if body.URL != nil && strings.TrimSpace(*body.URL) != "" {
		u := strings.TrimSpace(*body.URL)
		if err := notify.ValidateURL(u); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		cfg.URL = u
	}
	if body.ClearURL {
		cfg.URL = ""
		cfg.Enabled = false
	}
	if body.Enabled != nil {
		cfg.Enabled = *body.Enabled
	}
	if body.MinSeverity != nil {
		sev := strings.ToLower(strings.TrimSpace(*body.MinSeverity))
		if !notify.ValidSeverity(sev) {
			writeErr(w, http.StatusBadRequest, "min_severity must be info, low, medium or high")
			return
		}
		cfg.MinSeverity = sev
	}
	if body.NotifyStateChanges != nil {
		cfg.NotifyStateChanges = *body.NotifyStateChanges
	}
	if cfg.Enabled && cfg.URL == "" {
		writeErr(w, http.StatusBadRequest, "set a webhook URL before enabling")
		return
	}
	if err := notify.SaveConfig(r.Context(), s.store, cfg); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, notify.Public(cfg))
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	_ = decodeJSON(r, &body) // optional: test an unsaved URL
	if err := s.notifier.SendTest(r.Context(), strings.TrimSpace(body.URL)); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
