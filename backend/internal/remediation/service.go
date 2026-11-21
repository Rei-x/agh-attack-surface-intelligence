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
	HostID     string             `json:"host_id"`
	HostIP     string             `json:"host_ip"`
	Hostname   string             `json:"hostname,omitempty"`
	ServiceID  string             `json:"service_id,omitempty"`
	Port       int                `json:"port,omitempty"`
	Protocol   string             `json:"protocol,omitempty"`
	Service    string             `json:"service,omitempty"`
	Owner      string             `json:"owner"`
	OwnerEmail string             `json:"owner_email"`
	Issues     []Issue            `json:"issues"`
	IssueKey   string             `json:"issue_key"`
	Action     string             `json:"action"`
	DueAt      time.Time          `json:"due_at"`
	Subject    string             `json:"subject"`
	Body       string             `json:"body"`
	Channels   outbound.Available `json:"channels"`
	Existing   *Ticket            `json:"existing,omitempty"`
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

func (tg *target) issues(now time.Time) []Issue {
	var out []Issue
	if tg.svc != nil {
		out = ServiceIssues(tg.svc, now)
	}
	return append(out, GenericIssue(tg.svc, tg.host))
}

func pickIssue(issues []Issue, key string) Issue {
	for _, is := range issues {
		if is.Key == key {
			return is
		}
	}
	return issues[0]
}

// newTicket fills a ticket from the target and issue (not saved).
func (s *Service) newTicket(ctx context.Context, tg *target, is Issue, now time.Time) *Ticket {
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
	due := now.AddDate(0, 0, is.DueDays)
	due = time.Date(due.Year(), due.Month(), due.Day(), 23, 59, 0, 0, time.UTC)
	t.DueAt = &due
	return t
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
// detected issues (default: the most urgent).
func (s *Service) Draft(ctx context.Context, hostID, serviceID, issueKey string) (*DraftResponse, error) {
	now := s.Now()
	tg, err := s.loadTarget(ctx, hostID, serviceID)
	if err != nil {
		return nil, err
	}
	issues := tg.issues(now)
	is := pickIssue(issues, issueKey)
	t := s.newTicket(ctx, tg, is, now)
	d := BuildDraft(t, is.Advice, firstSeen(tg))
	resp := &DraftResponse{
		HostID: t.HostID, HostIP: t.HostIP, Hostname: t.Hostname, ServiceID: t.ServiceID,
		Port: t.Port, Protocol: t.Protocol, Service: t.Service, Owner: t.Owner, OwnerEmail: t.OwnerEmail,
		Issues: issues, IssueKey: is.Key, Action: is.Action, DueAt: *t.DueAt,
		Subject: d.Subject, Body: d.Body,
	}
	if s.Deliver != nil {
		resp.Channels = s.Deliver.Channels(ctx)
	}
	if ts, err := s.Repo.List(ctx); err == nil {
		if ex := findActive(ts, hostID, serviceID, is.Key); ex != nil {
			resp.Existing = ex
		}
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
	HostID     string     `json:"host_id"`
	ServiceID  string     `json:"service_id"`
	IssueKey   string     `json:"issue_key"`
	Owner      string     `json:"owner"`
	OwnerEmail string     `json:"owner_email"`
	Action     string     `json:"action"`
	Subject    string     `json:"subject"`
	Body       string     `json:"body"`
	DueAt      *time.Time `json:"due_at"`
	// Channel: auto (email, else webhook), email, webhook, manual (the analyst copied the
	// message or used the mail app), none (only record the ticket).
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
	is := pickIssue(tg.issues(now), req.IssueKey)
	fresh := s.newTicket(ctx, tg, is, now)
	applyEdits(fresh, req)

	var id string
	created := false
	err = s.Repo.Update(ctx, func(ts []Ticket) ([]Ticket, error) {
		if ex := findActive(ts, fresh.HostID, fresh.ServiceID, fresh.IssueKey); ex != nil {
			applyEdits(ex, req)
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

func applyEdits(t *Ticket, req CreateRequest) {
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
	}
	if strings.TrimSpace(req.Body) != "" {
		t.Body = req.Body
	}
	if req.DueAt != nil && !req.DueAt.IsZero() {
		d := req.DueAt.UTC()
		t.DueAt = &d
	}
	if t.Subject == "" || t.Body == "" {
		d := BuildDraft(t, "", time.Time{})
		if t.Subject == "" {
			t.Subject = d.Subject
		}
		if t.Body == "" {
			t.Body = d.Body
		}
	}
}

// NotifyRequest re-sends the stored (or edited) message.
type NotifyRequest struct {
	Channel string `json:"channel"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	To      string `json:"to"`
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
	msg := outbound.Message{
		Subject: t.Subject,
		Body:    t.Body,
		Facts: [][2]string{
			{"Where", t.Where()}, {"Owner", nonEmpty(t.Owner, "unknown")}, {"Due", dueText(t)},
		},
		Data: map[string]any{"ticket_id": t.ID, "host_ip": t.HostIP, "port": t.Port, "kind": t.Kind, "owner": t.Owner, "due_at": t.DueAt},
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
			cur.Subject, cur.Body, cur.OwnerEmail = t.Subject, t.Body, t.OwnerEmail
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

func dueText(t *Ticket) string {
	if t.DueAt == nil {
		return "not set"
	}
	return t.DueAt.Format("2006-01-02")
}

// StatusRequest changes status, due date or adds a note.
type StatusRequest struct {
	Status string     `json:"status"`
	Note   string     `json:"note"`
	DueAt  *time.Time `json:"due_at"`
}

// UpdateStatus applies a manual status change and/or a new due date.
func (s *Service) UpdateStatus(ctx context.Context, id string, req StatusRequest, by string) (*Ticket, error) {
	now := s.Now()
	var saved Ticket
	var from string
	err := s.Repo.Update(ctx, func(ts []Ticket) ([]Ticket, error) {
		for i := range ts {
			if ts[i].ID != id {
				continue
			}
			t := &ts[i]
			from = t.Status
			if req.DueAt != nil && !req.DueAt.IsZero() {
				d := req.DueAt.UTC()
				t.DueAt = &d
				t.Overdue = t.PastDue(now)
				t.History = append(t.History, HistoryEntry{At: now, By: by, Action: "due_changed", Note: "due " + d.Format("2006-01-02")})
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
		}, scanID, now)
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
		s.audit(ctx, SystemUser, "remediation."+o.Action, &t, map[string]any{"scan_run_id": scanID, "reason": o.Reason})
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
	MedianDays   float64        `json:"median_days_to_fix"`
}

// ComputeStats counts tickets at now.
func ComputeStats(ts []Ticket, now time.Time) Stats {
	st := Stats{ByStatus: map[string]int{}}
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
