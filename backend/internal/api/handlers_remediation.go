package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/auth"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/digest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/outbound"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/remediation"
)

// Closed-loop remediation (tickets to owners, verified by scans) and the morning digest.
// Wiring lives here so server.go only needs two calls: initRemediation and
// registerRemediationRoutes.

func (s *Server) initRemediation() {
	deliver := outbound.NewDeliverer(s.store, s.notifier)
	s.remediation = remediation.NewService(s.store, deliver)
	s.remediation.Audit = s.auditFromContext
	s.remediation.Publish = s.hub.Publish
	s.remediation.OnVerifiedFix = s.reflectFixInDefectDojo
	s.digest = digest.NewService(s.store, s.remediation.Repo, deliver)
	s.digest.Audit = s.auditFromContext
	s.digest.Publish = s.hub.Publish
	go s.digest.Run(context.Background())
	go s.watchCompletedScans()
}

// auditFromContext stores an audit entry, filling user, role and IP from the request
// context when there is one.
func (s *Server) auditFromContext(ctx context.Context, entry *domain.AuditLog) {
	if u := auth.UserFromContext(ctx); u != nil {
		entry.UserID, entry.Username, entry.RoleSlug = u.ID, u.Username, u.RoleSlug
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	_ = s.store.AddAuditLog(context.WithoutCancel(ctx), entry)
}

// watchCompletedScans listens on the live event hub for scan.completed (local engine,
// remote agents relayed by agenthub, imports) and runs ticket verification and the digest
// for each completed run once.
func (s *Server) watchCompletedScans() {
	events := s.hub.Subscribe()
	work := make(chan string, 64)
	go func() {
		var mu sync.Mutex
		done := map[string]time.Time{}
		for id := range work {
			mu.Lock()
			if at, ok := done[id]; ok && time.Since(at) < 10*time.Minute {
				mu.Unlock()
				continue
			}
			done[id] = time.Now()
			for k, at := range done {
				if time.Since(at) > time.Hour {
					delete(done, k)
				}
			}
			mu.Unlock()
			s.afterScanCompleted(id)
		}
	}()
	for ev := range events {
		if ev.Type != "scan.completed" || ev.ScanRunID == "" {
			continue
		}
		select {
		case work <- ev.ScanRunID:
		default:
			log.Printf("[WARN] remediation: verification queue full, skipped scan %s", ev.ScanRunID)
		}
	}
}

// afterScanCompleted waits for the run's final status write (the local engine emits
// scan.completed just before it), then verifies tickets and builds the digest.
func (s *Server) afterScanCompleted(runID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var run *domain.ScanRun
	deadline := time.Now().Add(2 * time.Minute)
	for {
		r, err := s.store.GetScanRun(ctx, runID)
		if err == nil && r != nil {
			switch r.Status {
			case domain.ScanStatusCompleted:
				run = r
			case domain.ScanStatusFailed, domain.ScanStatusStopped:
				return
			}
		}
		if run != nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if run == nil {
		return
	}
	if _, err := s.remediation.VerifyScan(ctx, run.ID); err != nil {
		log.Printf("[WARN] remediation: verification after scan %s failed: %v", run.ID, err)
	}
	s.digest.OnScanCompleted(ctx, run)
}

func (s *Server) registerRemediationRoutes() {
	mw := s.authMW
	s.handle("GET /api/v1/remediation/tickets", mw.RequirePerm(domain.PermAssetsRead, s.handleListTickets))
	s.handle("POST /api/v1/remediation/tickets", mw.RequirePerm(domain.PermAssetsWrite, s.handleCreateTicket))
	s.handle("GET /api/v1/remediation/tickets/{id}", mw.RequirePerm(domain.PermAssetsRead, s.handleGetTicket))
	s.handle("POST /api/v1/remediation/tickets/{id}/notify", mw.RequirePerm(domain.PermAssetsWrite, s.handleNotifyTicket))
	s.handle("POST /api/v1/remediation/tickets/{id}/status", mw.RequirePerm(domain.PermAssetsWrite, s.handleTicketStatus))
	s.handle("GET /api/v1/remediation/draft", mw.RequirePerm(domain.PermAssetsRead, s.handleRemediationDraft))
	s.handle("POST /api/v1/remediation/verify", mw.RequirePerm(domain.PermAssetsWrite, s.handleVerifyTickets))
	s.handle("GET /api/v1/remediation/channels", mw.RequirePerm(domain.PermAssetsRead, s.handleGetChannels))
	s.handle("PUT /api/v1/remediation/channels", mw.RequirePerm(domain.PermAdminSettings, s.handleSaveChannels))
	s.handle("POST /api/v1/remediation/channels/test", mw.RequirePerm(domain.PermAdminSettings, s.handleTestChannels))

	s.handle("GET /api/v1/digest", mw.RequirePerm(domain.PermDashboardRead, s.handleListDigests))
	s.handle("GET /api/v1/digest/latest", mw.RequirePerm(domain.PermDashboardRead, s.handleLatestDigest))
	s.handle("POST /api/v1/digest/build", mw.RequirePerm(domain.PermAssetsWrite, s.handleBuildDigest))
	s.handle("GET /api/v1/digest/settings", mw.RequirePerm(domain.PermDashboardRead, s.handleGetDigestSettings))
	s.handle("PUT /api/v1/digest/settings", mw.RequirePerm(domain.PermAdminSettings, s.handleSaveDigestSettings))
	s.handle("GET /api/v1/digest/{id}", mw.RequirePerm(domain.PermDashboardRead, s.handleGetDigest))
	s.handle("GET /api/v1/digest/{id}/markdown", mw.RequirePerm(domain.PermDashboardRead, s.handleDigestMarkdown))
	s.handle("POST /api/v1/digest/{id}/deliver", mw.RequirePerm(domain.PermAssetsWrite, s.handleDeliverDigest))
}

func writeRemediationErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, remediation.ErrNotFound):
		writeErr(w, http.StatusNotFound, "ticket not found")
	case errors.Is(err, remediation.ErrInvalid):
		writeErr(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), remediation.ErrInvalid.Error()+": "))
	default:
		writeStoreErr(w, err)
	}
}

// ticketView adds derived fields for the UI.
type ticketView struct {
	remediation.Ticket
	AgeDays int  `json:"age_days"`
	PastDue bool `json:"past_due"`
	// DueDate is the due day in the instance timezone (YYYY-MM-DD).
	DueDate string `json:"due_date,omitempty"`
	// FixOutcome is the label of a closed fix ("Fixed: upgraded to nginx 1.30.1").
	FixOutcome string `json:"fix_outcome,omitempty"`
}

func viewTicket(t remediation.Ticket, now time.Time, loc *time.Location) ticketView {
	v := ticketView{Ticket: t, AgeDays: t.AgeDays(now), PastDue: t.PastDue(now), FixOutcome: t.FixOutcome()}
	if t.DueAt != nil {
		v.DueDate = locale.DueDay(*t.DueAt, loc)
	}
	return v
}

func (s *Server) handleListTickets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.remediation.Repo.List(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	now := time.Now().UTC()
	loc := s.remediation.Prefs(r.Context()).Loc
	q := r.URL.Query()
	status, owner, hostID := q.Get("status"), strings.TrimSpace(q.Get("owner")), q.Get("host_id")
	activeOnly := queryBool(r, "active")
	owners := map[string]bool{}
	out := make([]ticketView, 0, len(ts))
	for _, t := range ts {
		owners[t.Owner] = true
		switch {
		case status == "overdue" && !(t.Overdue || t.PastDue(now)):
			continue
		case status != "" && status != "overdue" && t.Status != status:
			continue
		case owner != "" && !strings.EqualFold(t.Owner, owner):
			continue
		case hostID != "" && t.HostID != hostID:
			continue
		case activeOnly && !t.Active():
			continue
		}
		out = append(out, viewTicket(t, now, loc))
	}
	ownerList := make([]string, 0, len(owners))
	for o := range owners {
		if o != "" {
			ownerList = append(ownerList, o)
		}
	}
	sort.Strings(ownerList)
	writeJSON(w, http.StatusOK, map[string]any{
		"tickets":  out,
		"stats":    remediation.ComputeStats(ts, now),
		"owners":   ownerList,
		"timezone": loc.String(),
	})
}

func (s *Server) handleGetTicket(w http.ResponseWriter, r *http.Request) {
	t, err := s.remediation.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeRemediationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewTicket(*t, time.Now().UTC(), s.remediation.Prefs(r.Context()).Loc))
}

func (s *Server) handleRemediationDraft(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("host_id") == "" {
		writeErr(w, http.StatusBadRequest, "host_id is required")
		return
	}
	d, err := s.remediation.Draft(r.Context(), q.Get("host_id"), q.Get("service_id"), q.Get("issue_key"), q.Get("lang"))
	if err != nil {
		writeRemediationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleCreateTicket(w http.ResponseWriter, r *http.Request) {
	var req remediation.CreateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.HostID == "" {
		writeErr(w, http.StatusBadRequest, "host_id is required")
		return
	}
	if len(req.Body) > 20000 || len(req.Subject) > 300 {
		writeErr(w, http.StatusBadRequest, "message is too long")
		return
	}
	res, err := s.remediation.Create(r.Context(), req, currentUsername(r))
	if err != nil {
		writeRemediationErr(w, err)
		return
	}
	status := http.StatusOK
	if res.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, res)
}

func (s *Server) handleNotifyTicket(w http.ResponseWriter, r *http.Request) {
	var req remediation.NotifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	res, err := s.remediation.Notify(r.Context(), r.PathValue("id"), req, currentUsername(r))
	if err != nil {
		writeRemediationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleTicketStatus(w http.ResponseWriter, r *http.Request) {
	var req remediation.StatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Status == remediation.StatusAcceptedRisk && strings.TrimSpace(req.Note) == "" {
		writeErr(w, http.StatusBadRequest, "accepting a risk needs a reason")
		return
	}
	t, err := s.remediation.UpdateStatus(r.Context(), r.PathValue("id"), req, currentUsername(r))
	if err != nil {
		writeRemediationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// handleVerifyTickets re-checks all tickets against the current inventory (the same
// check that runs after every completed scan).
func (s *Server) handleVerifyTickets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScanRunID string `json:"scan_run_id"`
	}
	_ = decodeJSON(r, &req)
	scanID := strings.TrimSpace(req.ScanRunID)
	if scanID == "" {
		if runs, err := s.store.ListScanRuns(r.Context(), 20); err == nil {
			for _, run := range runs {
				if run.Status == domain.ScanStatusCompleted {
					scanID = run.ID
					break
				}
			}
		}
	}
	out, err := s.remediation.VerifyScan(r.Context(), scanID)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if out == nil {
		out = []remediation.Outcome{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan_run_id": scanID, "outcomes": out})
}

// noticeView is the non-secret notice configuration every reader may see (the dialog and
// the board format dates with it).
type noticeView struct {
	Language   string          `json:"notice_language"`
	Languages  []string        `json:"languages"`
	Timezone   string          `json:"timezone"`
	SLADays    remediation.SLA `json:"sla_days"`
	DefaultSLA remediation.SLA `json:"default_sla_days"`
}

func (s *Server) handleGetChannels(w http.ResponseWriter, r *http.Request) {
	st := outbound.Load(r.Context(), s.store)
	resp := map[string]any{
		"available": s.remediation.Deliver.Channels(r.Context()),
		"notices": noticeView{
			Language: st.Language(), Languages: locale.Languages, Timezone: st.Location().String(),
			SLADays: remediation.EffectiveSLA(st.SLADays), DefaultSLA: remediation.DefaultSLA,
		},
	}
	if u := auth.UserFromContext(r.Context()); u != nil && auth.HasPermission(u.Permissions, domain.PermAdminSettings) {
		resp["settings"] = outbound.Public(st)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSaveChannels(w http.ResponseWriter, r *http.Request) {
	var req struct {
		outbound.Settings
		ClearPassword bool `json:"clear_password"`
		ClearWebhook  bool `json:"clear_webhook"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := outbound.Save(r.Context(), s.store, &req.Settings, req.ClearPassword, req.ClearWebhook); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditFromContext(r.Context(), &domain.AuditLog{Action: "remediation.channels.update", Resource: "settings", Status: "success", IPAddress: agenthub.RemoteIP(r)})
	s.handleGetChannels(w, r)
}

func (s *Server) handleTestChannels(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To      string `json:"to"`
		Channel string `json:"channel"`
	}
	_ = decodeJSON(r, &req)
	subject, body := remediation.TestMessage(outbound.Load(r.Context(), s.store).Language())
	msg := outbound.Message{Subject: subject, Body: body}
	if req.To != "" {
		msg.To = []string{req.To}
	}
	res := s.remediation.Deliver.Deliver(r.Context(), nonEmptyStr(req.Channel, outbound.ChannelAuto), msg, "", "")
	writeJSON(w, http.StatusOK, res)
}

type digestSummary struct {
	ID        string        `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	Headline  string        `json:"headline"`
	Counts    digest.Counts `json:"counts"`
	Delivered bool          `json:"delivered"`
	ScanName  string        `json:"scan_name,omitempty"`
}

func (s *Server) handleListDigests(w http.ResponseWriter, r *http.Request) {
	ds, err := s.digest.List(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	out := make([]digestSummary, 0, len(ds))
	for _, d := range ds {
		out = append(out, digestSummary{ID: d.ID, CreatedAt: d.CreatedAt, Headline: d.Headline, Counts: d.Counts, Delivered: d.Delivered, ScanName: d.ScanName})
	}
	writeJSON(w, http.StatusOK, map[string]any{"digests": out})
}

// latestDigest returns the newest stored digest, or a live preview when none exists yet.
func (s *Server) latestDigest(ctx context.Context) (*digest.Digest, error) {
	ds, err := s.digest.List(ctx)
	if err != nil {
		return nil, err
	}
	if len(ds) > 0 {
		return &ds[0], nil
	}
	d, err := s.digest.Compose(ctx, nil)
	if err != nil {
		return nil, err
	}
	d.Preview = true
	return d, nil
}

func (s *Server) handleLatestDigest(w http.ResponseWriter, r *http.Request) {
	d, err := s.latestDigest(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleGetDigest(w http.ResponseWriter, r *http.Request) {
	d, err := s.digest.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDigestMarkdown(w http.ResponseWriter, r *http.Request) {
	var d *digest.Digest
	var err error
	if id := r.PathValue("id"); id == "latest" {
		d, err = s.latestDigest(r.Context())
	} else {
		d, err = s.digest.Get(r.Context(), id)
	}
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="dzieciol-digest-`+d.Day()+`.md"`)
	_, _ = w.Write([]byte(d.Markdown()))
}

func (s *Server) handleBuildDigest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Deliver bool `json:"deliver"`
	}
	_ = decodeJSON(r, &req)
	d, err := s.digest.BuildAndStore(r.Context(), nil)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if req.Deliver {
		if dd, err := s.digest.Deliver(r.Context(), d.ID); err == nil {
			d = dd
		}
	}
	s.auditFromContext(r.Context(), &domain.AuditLog{Action: "digest.build", Resource: "digest", ResourceID: d.ID, Status: "success", IPAddress: agenthub.RemoteIP(r)})
	writeJSON(w, http.StatusCreated, d)
}

func (s *Server) handleDeliverDigest(w http.ResponseWriter, r *http.Request) {
	d, err := s.digest.Deliver(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleGetDigestSettings(w http.ResponseWriter, r *http.Request) {
	st := s.digest.LoadSettings(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":  st.Public(),
		"available": s.remediation.Deliver.Channels(r.Context()),
	})
}

func (s *Server) handleSaveDigestSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		digest.Settings
		ClearWebhook bool `json:"clear_webhook"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if _, err := s.digest.SaveSettings(r.Context(), &req.Settings, req.ClearWebhook); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditFromContext(r.Context(), &domain.AuditLog{Action: "digest.settings.update", Resource: "settings", Status: "success", IPAddress: agenthub.RemoteIP(r)})
	s.handleGetDigestSettings(w, r)
}
