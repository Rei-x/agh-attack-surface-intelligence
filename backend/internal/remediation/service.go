package remediation

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/outbound"
)

// ErrInvalid marks a bad request (unknown host, bad status move).
var ErrInvalid = errors.New("invalid request")

// Service wires tickets, delivery, audit and verification.
type Service struct {
	Repo    *Repo
	store   db.Store
	Deliver *outbound.Deliverer
	// Audit records one audit log entry (may be nil).
	Audit func(ctx context.Context, entry *domain.AuditLog)
	// OnVerifiedFix is called for every ticket a scan verified as fixed. The API layer
	// uses it to reflect the fix in DefectDojo.
	OnVerifiedFix func(ctx context.Context, t Ticket, scanID string)
	// Publish pushes a live event to the UI (may be nil).
	Publish func(ev domain.LiveEvent)
	Now     func() time.Time
}

// NewService returns a service on store.
func NewService(store db.Store, deliver *outbound.Deliverer) *Service {
	return &Service{Repo: NewRepo(store), store: store, Deliver: deliver, Now: func() time.Time { return time.Now().UTC() }}
}

// Prefs are the instance's notice settings (outbound.Settings): default notice language,
// timezone and SLA table.
type Prefs struct {
	Lang string
	Loc  *time.Location
	SLA  SLA
}

// Prefs loads the notice settings.
func (s *Service) Prefs(ctx context.Context) Prefs {
	st := outbound.Load(ctx, s.store)
	return Prefs{Lang: st.Language(), Loc: st.Location(), SLA: EffectiveSLA(st.SLADays)}
}

// OwnerFor resolves the owner of a host (host owner or the most specific CIDR rule) and a
// contact email from the owner text or the matching rule descriptions.
func (s *Service) OwnerFor(ctx context.Context, host *domain.Host) (string, string) {
	rules := ingest.LoadTagRules(ctx, s.store)
	cp := domain.Host{IP: host.IP, Owner: host.Owner}
	ingest.ApplyTagRules(&cp, rules)
	texts := []string{cp.Owner}
	for _, r := range rules {
		if r.Enabled && r.Owner != "" && strings.EqualFold(r.Owner, cp.Owner) {
			texts = append(texts, r.Description)
		}
	}
	return cp.Owner, ExtractEmail(texts...)
}

// DraftResponse prefills the "Notify owner" dialog.
type DraftResponse struct {
	HostID     string    `json:"host_id"`
	HostIP     string    `json:"host_ip"`
	Hostname   string    `json:"hostname,omitempty"`
	ServiceID  string    `json:"service_id,omitempty"`
	Port       int       `json:"port,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	Service    string    `json:"service,omitempty"`
	Owner      string    `json:"owner"`
	OwnerEmail string    `json:"owner_email"`
	Issues     []Issue   `json:"issues"`
	IssueKey   string    `json:"issue_key"`
	Action     string    `json:"action"`
	DueAt      time.Time `json:"due_at"`
	// DueDate is the due day in the instance timezone (YYYY-MM-DD): what the dialog shows
	// and sends back.
	DueDate string  `json:"due_date"`
	SLA     SLAInfo `json:"sla"`
	Subject string  `json:"subject"`
	Body    string  `json:"body"`
	// Language is the language of Subject and Body; DefaultLanguage is the instance setting.
	Language        string             `json:"language"`
	DefaultLanguage string             `json:"default_language"`
	Languages       []string           `json:"languages"`
	Timezone        string             `json:"timezone"`
	Channels        outbound.Available `json:"channels"`
	Existing        *Ticket            `json:"existing,omitempty"`
}

type target struct {
	host *domain.Host
	svc  *domain.Service
}

func (s *Service) loadTarget(ctx context.Context, hostID, serviceID string) (*target, error) {
	host, err := s.store.GetHost(ctx, hostID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, fmt.Errorf("%w: host not found", ErrInvalid)
		}
		return nil, err
	}
	tg := &target{host: host}
	if serviceID != "" {
		for i := range host.Services {
			if host.Services[i].ID == serviceID {
				tg.svc = &host.Services[i]
				if tg.svc.HostIP == "" {
					tg.svc.HostIP = host.IP
				}
			}
		}
		if tg.svc == nil {
			return nil, fmt.Errorf("%w: service not found on host", ErrInvalid)
		}
	}
	return tg, nil
}

// issues lists the target's issues in lang with the configured SLA days.
func (tg *target) issues(now time.Time, lang string, sla SLA) []Issue {
	var out []Issue
	if tg.svc != nil {
		out = ServiceIssuesIn(tg.svc, now, lang)
	}
	out = append(out, GenericIssueIn(tg.svc, tg.host, lang))
	for i := range out {
		out[i].DueDays = sla.Days(out[i].Severity)
	}
	return out
}

// notice is the Notice for issue key of the target in lang.
func (tg *target) notice(now time.Time, key string, p Prefs, lang string) Notice {
	local := pickIssue(tg.issues(now, lang, p.SLA), key)
	return Notice{Lang: lang, Loc: p.Loc, Title: local.Title, Evidence: local.Evidence, Advice: local.Advice, FirstSeen: firstSeen(tg)}
}

func pickIssue(issues []Issue, key string) Issue {
	for _, is := range issues {
		if is.Key == key {
			return is
		}
	}
	return issues[0]
}

// newTicket fills a ticket from the target and issue (not saved). The due date is the
// DefectDojo SLA expiry of the same finding (see DueFor).
func (s *Service) newTicket(ctx context.Context, tg *target, is Issue, now time.Time, p Prefs) (*Ticket, SLAInfo) {
	owner, email := s.OwnerFor(ctx, tg.host)
	t := &Ticket{
		HostID: tg.host.ID, HostIP: tg.host.IP, Hostname: tg.host.Hostname,
		Kind: is.Kind, IssueKey: is.Key, Title: is.Title, Evidence: is.Evidence,
		Action: is.Action, Severity: is.Severity, Owner: owner, OwnerEmail: email,
		Status: StatusOpen,
	}
	if tg.svc != nil {
		t.ServiceID, t.Port, t.Protocol = tg.svc.ID, tg.svc.Port, nonEmpty(tg.svc.Protocol, "tcp")
		t.Service = strings.TrimSpace(strings.Join([]string{tg.svc.ServiceName, tg.svc.Product, tg.svc.Version}, " "))
		t.DefectDojoUniqueID = ddUniqueID(tg.svc, is)
	}
	findingDate := ""
	if t.DefectDojoUniqueID != "" {
		findingDate = defectdojo.FindingDate(tg.svc.FirstSeen, now)
	}
	due, info := DueFor(p.SLA, is.Severity, findingDate, now, p.Loc)
	t.DueAt = &due
	return t, info
}

// ddUniqueID mirrors the unique_id_from_tool of internal/defectdojo change findings.
func ddUniqueID(svc *domain.Service, is Issue) string {
	kind := is.Kind
	suffix := ""
	switch is.Kind {
	case KindEOL, KindKnownVuln:
		suffix = strings.TrimPrefix(is.Key, is.Kind)
	case KindCleartextAdmin:
		if _, ok := ingest.RiskyExposure(svc.Port, svc.ServiceName); !ok {
			return ""
		}
		kind = defectdojo.KindExposure
	case KindOther:
		return ""
	}
	return defectdojo.UniqueID(svc.HostIP, svc.Port, nonEmpty(svc.Protocol, "tcp"), "dz-change:"+kind+suffix)
}

// findActive returns the active ticket for the same host, service and issue.
func findActive(ts []Ticket, hostID, serviceID, key string) *Ticket {
	for i := range ts {
		t := &ts[i]
		if t.Active() && t.HostID == hostID && t.ServiceID == serviceID && t.IssueKey == key {
			return t
		}
	}
	return nil
}

// Draft prepares the owner message for a host or service. issueKey picks one of the
// detected issues (default: the most urgent); lang the notice language ("": the instance
// default). The issue list stays in English (the analyst UI).
func (s *Service) Draft(ctx context.Context, hostID, serviceID, issueKey, lang string) (*DraftResponse, error) {
	now := s.Now()
	tg, err := s.loadTarget(ctx, hostID, serviceID)
	if err != nil {
		return nil, err
	}
	p := s.Prefs(ctx)
	lang = nonEmpty(locale.Lang(lang), p.Lang)
	issues := tg.issues(now, locale.EN, p.SLA)
	is := pickIssue(issues, issueKey)
	t, sla := s.newTicket(ctx, tg, is, now, p)
	var existing *Ticket
	if ts, err := s.Repo.List(ctx); err == nil {
		existing = findActive(ts, hostID, serviceID, is.Key)
	}
	// A ticket already open for this issue keeps its due date.
	if existing != nil && existing.DueAt != nil {
		due := *existing.DueAt
		t.DueAt = &due
	}
	d := BuildDraft(t, tg.notice(now, is.Key, p, lang))
	resp := &DraftResponse{
		HostID: t.HostID, HostIP: t.HostIP, Hostname: t.Hostname, ServiceID: t.ServiceID,
		Port: t.Port, Protocol: t.Protocol, Service: t.Service, Owner: t.Owner, OwnerEmail: t.OwnerEmail,
		Issues: issues, IssueKey: is.Key, Action: is.Action, DueAt: *t.DueAt,
		DueDate: locale.DueDay(*t.DueAt, p.Loc), SLA: sla,
		Subject: d.Subject, Body: d.Body,
		Language: lang, DefaultLanguage: p.Lang, Languages: locale.Languages, Timezone: p.Loc.String(),
		Existing: existing,
	}
	if s.Deliver != nil {
		resp.Channels = s.Deliver.Channels(ctx)
	}
	return resp, nil
}

func firstSeen(tg *target) time.Time {
	if tg.svc != nil {
		return tg.svc.FirstSeen
	}
	return tg.host.FirstSeen
}

// CreateRequest opens (or re-sends) a ticket from the dialog.
type CreateRequest struct {
	HostID     string `json:"host_id"`
	ServiceID  string `json:"service_id"`
	IssueKey   string `json:"issue_key"`
	Owner      string `json:"owner"`
	OwnerEmail string `json:"owner_email"`
	Action     string `json:"action"`
	Subject    string `json:"subject"`
	Body       string `json:"body"`
	// Language is the language of Subject and Body (pl, en); "" is the instance default.
	Language string `json:"language"`
	// DueDate (YYYY-MM-DD, instance timezone) wins over DueAt.
	DueDate string     `json:"due_date"`
	DueAt   *time.Time `json:"due_at"`
	// Channel is auto (email, else webhook), email, webhook, manual (the analyst copied the
	// message or used the mail app) or none (only record the ticket).
	Channel string `json:"channel"`
}

// SendResult is returned by Create and Notify.
type SendResult struct {
	Ticket   *Ticket         `json:"ticket"`
	Delivery outbound.Result `json:"delivery"`
	Created  bool            `json:"created"`
}

// Create opens a ticket for the request (reusing an active one for the same issue) and
// delivers the message.
func (s *Service) Create(ctx context.Context, req CreateRequest, by string) (*SendResult, error) {
	now := s.Now()
	tg, err := s.loadTarget(ctx, req.HostID, req.ServiceID)
	if err != nil {
		return nil, err
	}
	p := s.Prefs(ctx)
	lang := nonEmpty(locale.Lang(req.Language), p.Lang)
	is := pickIssue(tg.issues(now, locale.EN, p.SLA), req.IssueKey)
	fresh, _ := s.newTicket(ctx, tg, is, now, p)
	n := tg.notice(now, is.Key, p, lang)
	if err := applyEdits(fresh, req, n); err != nil {
		return nil, err
	}

	var id string
	created := false
	err = s.Repo.Update(ctx, func(ts []Ticket) ([]Ticket, error) {
		if ex := findActive(ts, fresh.HostID, fresh.ServiceID, fresh.IssueKey); ex != nil {
			if err := applyEdits(ex, req, n); err != nil {
				return nil, err
			}
			ex.UpdatedAt = now
			id = ex.ID
			return ts, nil
		}
		fresh.ID = db.NewID()
		fresh.CreatedBy, fresh.CreatedAt, fresh.UpdatedAt = by, now, now
		fresh.History = []HistoryEntry{{At: now, By: by, Action: "created", To: StatusOpen, Note: fresh.Title}}
		id, created = fresh.ID, true
		return append(ts, *fresh), nil
	})
	if err != nil {
		return nil, err
	}
	if created {
		s.audit(ctx, by, "remediation.create", fresh, map[string]any{"issue": fresh.IssueKey, "owner": fresh.Owner})
	}
	res, err := s.Notify(ctx, id, NotifyRequest{Channel: req.Channel}, by)
	if err != nil {
		return nil, err
	}
	res.Created = created
	return res, nil
}

// applyEdits copies the dialog's edits onto t. n is the notice used when the request
// carries no subject or body.
func applyEdits(t *Ticket, req CreateRequest, n Notice) error {
	if v := strings.TrimSpace(req.Owner); v != "" {
		t.Owner = v
	}
	if v := strings.TrimSpace(req.OwnerEmail); v != "" {
		t.OwnerEmail = v
	}
	switch req.Action {
	case ActionPatch, ActionRemove, ActionRestrict:
		t.Action = req.Action
	}
	if strings.TrimSpace(req.Subject) != "" {
		t.Subject = strings.TrimSpace(req.Subject)
		t.Language = n.Lang
	}
	if strings.TrimSpace(req.Body) != "" {
		t.Body = req.Body
		t.Language = n.Lang
	}
	if due, err := requestedDue(req.DueDate, req.DueAt, n.Loc); err != nil {
		return err
	} else if due != nil {
		t.DueAt = due
	}
	if t.Subject == "" || t.Body == "" {
		d := BuildDraft(t, n)
		if t.Subject == "" {
			t.Subject = d.Subject
		}
		if t.Body == "" {
			t.Body = d.Body
		}
		t.Language = n.Lang
	}
	return nil
}

// requestedDue is the due time a request asks for: a YYYY-MM-DD day (23:59 in loc) or an
// absolute time; nil when neither is set.
func requestedDue(day string, at *time.Time, loc *time.Location) (*time.Time, error) {
	if strings.TrimSpace(day) != "" {
		d, err := locale.EndOfDay(day, loc)
		if err != nil {
			return nil, fmt.Errorf("%w: due %v", ErrInvalid, err)
		}
		return &d, nil
	}
	if at != nil && !at.IsZero() {
		d := at.UTC()
		return &d, nil
	}
	return nil, nil
}

// NotifyRequest re-sends the stored (or edited) message.
type NotifyRequest struct {
	Channel string `json:"channel"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	// Language is the language of an edited Subject or Body; "" leaves it unchanged.
	Language string `json:"language"`
	To       string `json:"to"`
}

// Notify delivers the ticket message. A delivered message (or a manual send confirmed by
// the analyst) moves the ticket to notified; a failed one leaves the status alone and
// returns the manual fallback.
func (s *Service) Notify(ctx context.Context, id string, req NotifyRequest, by string) (*SendResult, error) {
	t, err := s.Repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !t.Active() {
		return nil, fmt.Errorf("%w: ticket is %s; reopen it first", ErrInvalid, t.Status)
	}
	if strings.TrimSpace(req.Subject) != "" {
		t.Subject = strings.TrimSpace(req.Subject)
	}
	if strings.TrimSpace(req.Body) != "" {
		t.Body = req.Body
	}
	if strings.TrimSpace(req.To) != "" {
		t.OwnerEmail = strings.TrimSpace(req.To)
	}
	if l := locale.Lang(req.Language); l != "" && (strings.TrimSpace(req.Subject) != "" || strings.TrimSpace(req.Body) != "") {
		t.Language = l
	}
	// Card facts follow the message language; a ticket without one is English.
	tx := textFor(nonEmpty(t.Language, locale.EN))
	loc := s.Prefs(ctx).Loc
	msg := outbound.Message{
		Subject: t.Subject,
		Body:    t.Body,
		Facts: [][2]string{
			{tx.factWhere, t.Where()}, {tx.factOwner, nonEmpty(t.Owner, tx.ownerUnknown)}, {tx.factDue, dueText(t, tx, loc)},
		},
		Data: map[string]any{
			"ticket_id": t.ID, "host_ip": t.HostIP, "port": t.Port, "kind": t.Kind, "severity": t.Severity,
			"owner": t.Owner, "due_at": t.DueAt, "due_date": dueText(t, tx, loc), "language": nonEmpty(t.Language, locale.EN),
		},
	}
	if t.OwnerEmail != "" {
		msg.To = []string{t.OwnerEmail}
	}
	channel := strings.TrimSpace(req.Channel)
	var res outbound.Result
	switch channel {
	case "none":
		res = outbound.Result{Channel: "none"}
	case outbound.ChannelManual:
		res = outbound.Result{Channel: outbound.ChannelManual, Delivered: true, Mailto: outbound.Mailto(msg.To, msg.Subject, msg.Body)}
	default:
		if s.Deliver == nil {
			res = outbound.Result{Channel: outbound.ChannelManual, Mailto: outbound.Mailto(msg.To, msg.Subject, msg.Body)}
		} else {
			res = s.Deliver.Deliver(ctx, channel, msg, "", "")
		}
	}
	now := s.Now()
	var saved Ticket
	err = s.Repo.Update(ctx, func(ts []Ticket) ([]Ticket, error) {
		for i := range ts {
			if ts[i].ID != id {
				continue
			}
			cur := &ts[i]
			cur.Subject, cur.Body, cur.OwnerEmail, cur.Language = t.Subject, t.Body, t.OwnerEmail, t.Language
			cur.UpdatedAt = now
			if res.Delivered {
				cur.Channel = res.Channel
				note := "sent by " + res.Channel
				if res.Target != "" {
					note += " to " + res.Target
				}
				if res.Channel == outbound.ChannelManual {
					note = "sent manually by the analyst"
				}
				if err := cur.SetStatus(StatusNotified, by, note, "", now); err != nil {
					return nil, err
				}
			} else if res.Channel != "none" && res.Error != "" {
				cur.History = append(cur.History, HistoryEntry{At: now, By: by, Action: "delivery_failed", Note: res.Error})
			}
			saved = *cur
			return ts, nil
		}
		return nil, ErrNotFound
	})
	if err != nil {
		return nil, err
	}
	if res.Delivered {
		s.audit(ctx, by, "remediation.notify", &saved, map[string]any{"channel": res.Channel, "target": res.Target})
	}
	s.publish(saved.ID)
	return &SendResult{Ticket: &saved, Delivery: res}, nil
}

func dueText(t *Ticket, tx *texts, loc *time.Location) string {
	if t.DueAt == nil {
		return tx.dueNotSet
	}
	return locale.DueDay(*t.DueAt, loc)
}

// StatusRequest changes status, due date or adds a note.
type StatusRequest struct {
	Status string `json:"status"`
	Note   string `json:"note"`
	// DueDate (YYYY-MM-DD, instance timezone) wins over DueAt.
	DueDate string     `json:"due_date"`
	DueAt   *time.Time `json:"due_at"`
}

// UpdateStatus applies a manual status change and/or a new due date.
func (s *Service) UpdateStatus(ctx context.Context, id string, req StatusRequest, by string) (*Ticket, error) {
	now := s.Now()
	loc := s.Prefs(ctx).Loc
	due, err := requestedDue(req.DueDate, req.DueAt, loc)
	if err != nil {
		return nil, err
	}
	var saved Ticket
	var from string
	err = s.Repo.Update(ctx, func(ts []Ticket) ([]Ticket, error) {
		for i := range ts {
			if ts[i].ID != id {
				continue
			}
			t := &ts[i]
			from = t.Status
			if due != nil {
				t.DueAt = due
				t.Overdue = t.PastDue(now)
				t.History = append(t.History, HistoryEntry{At: now, By: by, Action: "due_changed", Note: "due " + locale.DueDay(*due, loc)})
				t.UpdatedAt = now
			}
			if req.Status != "" && req.Status != t.Status {
				if err := t.SetStatus(req.Status, by, strings.TrimSpace(req.Note), "", now); err != nil {
					return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
				}
			} else if strings.TrimSpace(req.Note) != "" {
				t.History = append(t.History, HistoryEntry{At: now, By: by, Action: "note", Note: strings.TrimSpace(req.Note)})
				t.UpdatedAt = now
			}
			saved = *t
			return ts, nil
		}
		return nil, ErrNotFound
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, by, "remediation.status", &saved, map[string]any{"from": from, "to": saved.Status, "note": req.Note})
	s.publish(saved.ID)
	return &saved, nil
}

// VerifyScan checks every ticket against the inventory after scan scanID completed.
func (s *Service) VerifyScan(ctx context.Context, scanID string) ([]Outcome, error) {
	now := s.Now()
	loc := s.Prefs(ctx).Loc
	var outcomes []Outcome
	byID := map[string]Ticket{}
	err := s.Repo.Update(ctx, func(ts []Ticket) ([]Ticket, error) {
		if len(ts) == 0 {
			return ts, nil
		}
		outcomes = Verify(ts, func(hostID string) (*domain.Host, bool) {
			h, err := s.store.GetHost(ctx, hostID)
			if err != nil {
				if errors.Is(err, db.ErrNotFound) {
					return nil, true
				}
				return nil, false
			}
			return h, true
		}, scanID, now, loc)
		for _, t := range ts {
			byID[t.ID] = t
		}
		return ts, nil
	})
	if err != nil {
		return nil, err
	}
	for _, o := range outcomes {
		t := byID[o.TicketID]
		details := map[string]any{"scan_run_id": scanID, "reason": o.Reason}
		if o.FixedReason != "" {
			details["fixed_reason"] = o.FixedReason
			details["outcome"] = t.FixOutcome()
		}
		s.audit(ctx, SystemUser, "remediation."+o.Action, &t, details)
		if o.Action == "verified_fixed" && s.OnVerifiedFix != nil {
			s.OnVerifiedFix(ctx, t, scanID)
		}
	}
	if len(outcomes) > 0 {
		log.Printf("[INFO] remediation: scan %s verified %d ticket change(s)", scanID, len(outcomes))
		s.publish("")
	}
	return outcomes, nil
}

func (s *Service) audit(ctx context.Context, by, action string, t *Ticket, details map[string]any) {
	if s.Audit == nil || t == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	details["where"] = t.Where()
	details["title"] = t.Title
	s.Audit(ctx, &domain.AuditLog{
		Username: by, Action: action, Resource: "remediation", ResourceID: t.ID,
		Status: "success", Details: details, CreatedAt: s.Now(),
	})
}

func (s *Service) publish(id string) {
	if s.Publish == nil {
		return
	}
	s.Publish(domain.LiveEvent{Type: "remediation.updated", Timestamp: s.Now(), Payload: map[string]any{"ticket_id": id}})
}

// Stats summarises tickets for the board and the digest.
type Stats struct {
	Open         int            `json:"open"` // all active
	Overdue      int            `json:"overdue"`
	Fixed        int            `json:"fixed"`
	FixedLast24h int            `json:"fixed_last_24h"`
	AcceptedRisk int            `json:"accepted_risk"`
	ByStatus     map[string]int `json:"by_status"`
	// FixedBy counts fixed tickets by outcome (Fixed* constants).
	FixedBy    map[string]int `json:"fixed_by"`
	MedianDays float64        `json:"median_days_to_fix"`
}

// ComputeStats counts tickets at now.
func ComputeStats(ts []Ticket, now time.Time) Stats {
	st := Stats{ByStatus: map[string]int{}, FixedBy: map[string]int{}}
	var days []float64
	for i := range ts {
		t := &ts[i]
		st.ByStatus[t.Status]++
		switch {
		case t.Active():
			st.Open++
			if t.Overdue || t.PastDue(now) {
				st.Overdue++
			}
		case t.Status == StatusFixed:
			st.Fixed++
			st.FixedBy[nonEmpty(t.FixedReason, FixedManual)]++
			if t.FixedAt != nil {
				if now.Sub(*t.FixedAt) <= 24*time.Hour {
					st.FixedLast24h++
				}
				days = append(days, t.FixedAt.Sub(t.CreatedAt).Hours()/24)
			}
		case t.Status == StatusAcceptedRisk:
			st.AcceptedRisk++
		}
	}
	if len(days) > 0 {
		sort.Float64s(days)
		st.MedianDays = float64(int(days[len(days)/2]*10)) / 10
	}
	return st
}
