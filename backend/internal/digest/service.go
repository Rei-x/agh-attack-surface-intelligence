package digest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/notify"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/outbound"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/remediation"
)

// Settings documents.
const (
	SettingDigests  = "digests"
	SettingSettings = "digest_settings"
	keepDigests     = 30
	// TriggeredByScheduler matches scheduler.TriggeredByScheduler (not imported to keep
	// this package free of the scheduler's dependencies).
	TriggeredByScheduler = "scheduler"
)

// Settings controls building and delivery.
type Settings struct {
	Enabled       bool     `json:"enabled"` // deliver digests
	Recipients    []string `json:"recipients"`
	WebhookURL    string   `json:"webhook_url,omitempty"` // empty: the delivery channels webhook
	HasWebhookURL bool     `json:"has_webhook_url"`
	WebhookMasked string   `json:"webhook_masked,omitempty"`
	WebhookFormat string   `json:"webhook_format,omitempty"`
	SendAt        string   `json:"send_at"` // HH:MM local time; empty: right after the scan
	Timezone      string   `json:"timezone"`
	// OnlyScheduled builds digests only after cron-fired runs (default true).
	OnlyScheduled bool `json:"only_scheduled"`
	// AppURL links the full digest from messages (optional).
	AppURL string `json:"app_url,omitempty"`
	// LastDeliveredDay is the local date of the last delivery (YYYY-MM-DD).
	LastDeliveredDay string `json:"last_delivered_day,omitempty"`
}

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// Validate normalises and checks the settings.
func (s *Settings) Validate() error {
	s.SendAt = strings.TrimSpace(s.SendAt)
	if s.SendAt != "" && !hhmm.MatchString(s.SendAt) {
		return errors.New("send time must be HH:MM")
	}
	if s.Timezone == "" {
		s.Timezone = "Europe/Warsaw"
	}
	if _, err := time.LoadLocation(s.Timezone); err != nil {
		return fmt.Errorf("unknown timezone %q", s.Timezone)
	}
	clean := make([]string, 0, len(s.Recipients))
	for _, r := range s.Recipients {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, err := mail.ParseAddress(r); err != nil {
			return fmt.Errorf("invalid recipient %q", r)
		}
		clean = append(clean, r)
	}
	s.Recipients = clean
	if s.WebhookURL != "" {
		if err := notify.ValidateURL(s.WebhookURL); err != nil {
			return err
		}
	}
	switch s.WebhookFormat {
	case "", outbound.FormatSlack, outbound.FormatTeams, outbound.FormatGeneric:
	default:
		return fmt.Errorf("unknown webhook format %q", s.WebhookFormat)
	}
	return nil
}

// Public hides the webhook secret.
func (s *Settings) Public() *Settings {
	cp := *s
	cp.HasWebhookURL = s.WebhookURL != ""
	cp.WebhookMasked = notify.MaskURL(s.WebhookURL)
	cp.WebhookURL = ""
	return &cp
}

// Service builds, stores and delivers digests.
type Service struct {
	store   db.Store
	tickets *remediation.Repo
	deliver *outbound.Deliverer
	mu      sync.Mutex
	Audit   func(ctx context.Context, entry *domain.AuditLog)
	Publish func(ev domain.LiveEvent)
	Now     func() time.Time
}

// NewService returns a digest service.
func NewService(store db.Store, tickets *remediation.Repo, deliver *outbound.Deliverer) *Service {
	return &Service{store: store, tickets: tickets, deliver: deliver, Now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) settingsStore() (db.SettingsStore, error) {
	ss, ok := s.store.(db.SettingsStore)
	if !ok {
		return nil, errors.New("store does not support settings")
	}
	return ss, nil
}

// LoadSettings returns the settings with defaults.
func (s *Service) LoadSettings(ctx context.Context) *Settings {
	st := &Settings{OnlyScheduled: true, SendAt: "07:00", Timezone: "Europe/Warsaw", WebhookFormat: ""}
	if ss, err := s.settingsStore(); err == nil {
		_, _ = ss.GetSetting(ctx, SettingSettings, st)
	}
	if st.Timezone == "" {
		st.Timezone = "Europe/Warsaw"
	}
	return st
}

// SaveSettings validates and stores settings; an empty webhook keeps the stored one unless
// clearWebhook is set.
func (s *Service) SaveSettings(ctx context.Context, in *Settings, clearWebhook bool) (*Settings, error) {
	ss, err := s.settingsStore()
	if err != nil {
		return nil, err
	}
	cur := s.LoadSettings(ctx)
	out := *in
	out.HasWebhookURL, out.WebhookMasked = false, ""
	out.LastDeliveredDay = cur.LastDeliveredDay
	if out.WebhookURL == "" && !clearWebhook {
		out.WebhookURL = cur.WebhookURL
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	if err := ss.SaveSetting(ctx, SettingSettings, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type digestDoc struct {
	Digests []Digest `json:"digests"`
}

// List returns stored digests, newest first.
func (s *Service) List(ctx context.Context) ([]Digest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(ctx)
}

func (s *Service) loadLocked(ctx context.Context) ([]Digest, error) {
	ss, err := s.settingsStore()
	if err != nil {
		return nil, err
	}
	var doc digestDoc
	if _, err := ss.GetSetting(ctx, SettingDigests, &doc); err != nil {
		return nil, err
	}
	return doc.Digests, nil
}

func (s *Service) updateLocked(ctx context.Context, fn func([]Digest) []Digest) error {
	ds, err := s.loadLocked(ctx)
	if err != nil {
		return err
	}
	ds = fn(ds)
	if len(ds) > keepDigests {
		ds = ds[:keepDigests]
	}
	ss, err := s.settingsStore()
	if err != nil {
		return err
	}
	return ss.SaveSetting(ctx, SettingDigests, &digestDoc{Digests: ds})
}

// Get returns one stored digest.
func (s *Service) Get(ctx context.Context, id string) (*Digest, error) {
	ds, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range ds {
		if ds[i].ID == id {
			return &ds[i], nil
		}
	}
	return nil, db.ErrNotFound
}

// Compose builds a digest for now without saving it. The window starts at the previous
// stored digest (or 24 hours back).
func (s *Service) Compose(ctx context.Context, run *domain.ScanRun) (*Digest, error) {
	now := s.Now()
	since := now.Add(-24 * time.Hour)
	if ds, err := s.List(ctx); err == nil && len(ds) > 0 && ds[0].CreatedAt.After(since) && ds[0].CreatedAt.Before(now) {
		since = ds[0].CreatedAt
	}
	changes, err := s.store.ListChangeEvents(ctx, db.ChangeFilter{Limit: 5000})
	if err != nil {
		return nil, err
	}
	hosts, _, err := s.store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		return nil, err
	}
	var tickets []remediation.Ticket
	if s.tickets != nil {
		tickets, _ = s.tickets.List(ctx)
	}
	d := Build(Input{Now: now, Since: since, Run: run, Changes: changes, Hosts: hosts, Tickets: tickets})
	return d, nil
}

// BuildAndStore composes and saves a digest.
func (s *Service) BuildAndStore(ctx context.Context, run *domain.ScanRun) (*Digest, error) {
	d, err := s.Compose(ctx, run)
	if err != nil {
		return nil, err
	}
	d.ID = db.NewID()
	s.mu.Lock()
	err = s.updateLocked(ctx, func(ds []Digest) []Digest { return append([]Digest{*d}, ds...) })
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if s.Publish != nil {
		s.Publish(domain.LiveEvent{Type: "digest.created", Timestamp: s.Now(), Payload: map[string]any{"digest_id": d.ID, "headline": d.Headline}})
	}
	return d, nil
}

// OnScanCompleted builds a digest after a completed run (only cron-fired runs unless
// OnlyScheduled is off) and delivers it when it is time.
func (s *Service) OnScanCompleted(ctx context.Context, run *domain.ScanRun) {
	if run == nil || run.Status != domain.ScanStatusCompleted {
		return
	}
	st := s.LoadSettings(ctx)
	if st.OnlyScheduled && run.TriggeredBy != TriggeredByScheduler {
		return
	}
	if _, err := s.BuildAndStore(ctx, run); err != nil {
		log.Printf("[WARN] digest: build failed: %v", err)
		return
	}
	s.Tick(ctx)
}

// Tick delivers the newest undelivered digest once per local day, at or after SendAt.
func (s *Service) Tick(ctx context.Context) {
	st := s.LoadSettings(ctx)
	if !st.Enabled {
		return
	}
	loc, err := time.LoadLocation(st.Timezone)
	if err != nil {
		loc = time.UTC
	}
	local := s.Now().In(loc)
	day := local.Format("2006-01-02")
	if st.LastDeliveredDay == day {
		return
	}
	if st.SendAt != "" && local.Format("15:04") < st.SendAt {
		return
	}
	ds, err := s.List(ctx)
	if err != nil || len(ds) == 0 || ds[0].Delivered {
		return
	}
	if _, err := s.Deliver(ctx, ds[0].ID); err != nil {
		log.Printf("[WARN] digest: delivery failed: %v", err)
	}
}

// Deliver sends one digest to the recipients (email) and the webhook.
func (s *Service) Deliver(ctx context.Context, id string) (*Digest, error) {
	d, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	st := s.LoadSettings(ctx)
	link := ""
	if st.AppURL != "" {
		link = strings.TrimRight(st.AppURL, "/") + "/digest?id=" + d.ID
	}
	msg := d.Message(link)
	var notes []string
	delivered := false
	if s.deliver != nil {
		viaWebhook := false
		if len(st.Recipients) > 0 {
			msg.To = st.Recipients
			r := s.deliver.Deliver(ctx, outbound.ChannelEmail, msg, st.WebhookURL, st.WebhookFormat)
			notes = append(notes, describe(r))
			delivered = r.Delivered
			// Without SMTP the email attempt already falls through to the webhook.
			viaWebhook = r.Delivered && r.Channel == outbound.ChannelWebhook
		}
		if !viaWebhook {
			msg.To = nil
			r := s.deliver.Deliver(ctx, outbound.ChannelWebhook, msg, st.WebhookURL, st.WebhookFormat)
			if r.Delivered || r.Error != "" {
				notes = append(notes, describe(r))
			}
			delivered = delivered || r.Delivered
		}
	}
	if !delivered && len(notes) == 0 {
		notes = append(notes, "no channel configured: download the Markdown or set SMTP / a webhook")
	}
	now := s.Now()
	s.mu.Lock()
	err = s.updateLocked(ctx, func(ds []Digest) []Digest {
		for i := range ds {
			if ds[i].ID == id {
				ds[i].Delivered = delivered
				ds[i].Delivery = notes
				if delivered {
					ds[i].DeliveredAt = &now
				}
				*d = ds[i]
			}
		}
		return ds
	})
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if delivered {
		loc, lerr := time.LoadLocation(st.Timezone)
		if lerr != nil {
			loc = time.UTC
		}
		st.LastDeliveredDay = now.In(loc).Format("2006-01-02")
		if ss, err := s.settingsStore(); err == nil {
			_ = ss.SaveSetting(ctx, SettingSettings, st)
		}
	}
	if s.Audit != nil {
		status := "success"
		if !delivered {
			status = "error"
		}
		s.Audit(ctx, &domain.AuditLog{Username: "digest", Action: "digest.deliver", Resource: "digest", ResourceID: d.ID, Status: status, Details: map[string]any{"delivery": notes}, CreatedAt: now})
	}
	return d, nil
}

func describe(r outbound.Result) string {
	switch {
	case r.Delivered:
		return "sent by " + r.Channel + " to " + r.Target
	case r.Error != "":
		return "delivery failed: " + r.Error
	default:
		return "no email or webhook channel configured"
	}
}

// Run calls Tick every minute until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}
