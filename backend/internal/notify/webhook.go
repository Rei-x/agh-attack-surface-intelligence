// Package notify implements the single outbound alert webhook: after each ingest (scan
// segment, import, manual entry) the high-severity new exposures and host state changes are
// posted as one JSON message that Slack, Discord, Microsoft Teams (incoming webhook) and
// generic receivers (n8n, SOAR, Mattermost) all accept.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// MaxListedEvents caps the human-readable list in one message.
const MaxListedEvents = 15

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// SeverityRank returns the ordinal of a severity (unknown -> 0).
func SeverityRank(s string) int { return severityRank[strings.ToLower(s)] }

// ValidSeverity reports whether s is a known severity.
func ValidSeverity(s string) bool {
	_, ok := severityRank[strings.ToLower(s)]
	return ok
}

var stateEventTypes = map[string]bool{
	"HOST_STATE_CHANGED": true,
	"HOST_MISSING":       true,
	"HOST_INACTIVE":      true,
	"HOST_REACTIVATED":   true,
	"TIME_ANOMALY":       true,
}

// IsStateEvent reports whether an event is an alert-worthy host lifecycle state change.
// The routine NEW -> ACTIVE confirmation on the second sighting is not.
func IsStateEvent(ev domain.ChangeEvent) bool {
	if !stateEventTypes[ev.EventType] {
		return false
	}
	if ev.EventType == "HOST_STATE_CHANGED" {
		after, _ := ev.After["lifecycle_state"].(string)
		return after != domain.HostStateActive && after != domain.HostStateNew
	}
	return true
}

// LoadConfig returns the stored webhook config (zero value + defaults when unset).
func LoadConfig(ctx context.Context, store db.Store) (*domain.WebhookConfig, error) {
	cfg := &domain.WebhookConfig{MinSeverity: "high", NotifyStateChanges: true}
	ss, ok := store.(db.SettingsStore)
	if !ok {
		return cfg, nil
	}
	if _, err := ss.GetSetting(ctx, db.SettingWebhook, cfg); err != nil {
		return nil, err
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = "high"
	}
	cfg.HasURL = cfg.URL != ""
	cfg.URLMasked = MaskURL(cfg.URL)
	return cfg, nil
}

// SaveConfig persists the config (the URL is encrypted at rest with the settings document).
func SaveConfig(ctx context.Context, store db.Store, cfg *domain.WebhookConfig) error {
	ss, ok := store.(db.SettingsStore)
	if !ok {
		return errors.New("store does not support settings")
	}
	cp := *cfg
	cp.HasURL = false
	cp.URLMasked = ""
	return ss.SaveSetting(ctx, db.SettingWebhook, &cp)
}

// Public returns a copy safe for API responses (secret URL removed, masked form kept).
func Public(cfg *domain.WebhookConfig) *domain.WebhookConfig {
	cp := *cfg
	cp.HasURL = cfg.URL != ""
	cp.URLMasked = MaskURL(cfg.URL)
	cp.URL = ""
	return &cp
}

// ValidateURL accepts absolute http(s) URLs only.
func ValidateURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("webhook URL must be an absolute http(s) URL")
	}
	return nil
}

// MaskURL keeps scheme + host and hides the path (which carries the channel token).
func MaskURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "***"
	}
	return u.Scheme + "://" + u.Host + "/***"
}

// SelectEvents picks the events worth alerting on: severity >= MinSeverity, plus host state
// changes when NotifyStateChanges is on.
func SelectEvents(cfg *domain.WebhookConfig, changes []domain.ChangeEvent) []domain.ChangeEvent {
	min := SeverityRank(cfg.MinSeverity)
	out := make([]domain.ChangeEvent, 0)
	for _, ev := range changes {
		if SeverityRank(ev.Severity) >= min || (cfg.NotifyStateChanges && IsStateEvent(ev)) {
			out = append(out, ev)
		}
	}
	return out
}

// BuildPayload renders one message. "text" is read by Slack and Teams, "content" by Discord
// (2000 char limit), "events" carries structured data for generic consumers.
func BuildPayload(run *domain.ScanRun, events []domain.ChangeEvent, title string) map[string]any {
	var b strings.Builder
	if title == "" {
		title = fmt.Sprintf("AegisASI: %d alert(s)", len(events))
		if run != nil && run.Name != "" {
			title += fmt.Sprintf(" after scan %q", run.Name)
		}
	}
	b.WriteString("*" + title + "*\n")
	for i, ev := range events {
		if i >= MaxListedEvents {
			fmt.Fprintf(&b, "... and %d more\n", len(events)-MaxListedEvents)
			break
		}
		fmt.Fprintf(&b, "- [%s] %s: %s\n", strings.ToUpper(ev.Severity), ev.EventType, ev.Summary)
	}
	text := strings.TrimRight(b.String(), "\n")
	content := text
	if len(content) > 1900 {
		content = content[:1900] + "..."
	}
	structured := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		structured = append(structured, map[string]any{
			"id":         ev.ID,
			"event_type": ev.EventType,
			"severity":   ev.Severity,
			"host_id":    ev.HostID,
			"host_ip":    ev.HostIP,
			"port":       ev.Port,
			"summary":    ev.Summary,
			"created_at": ev.CreatedAt,
		})
	}
	payload := map[string]any{
		"text":     text,
		"content":  content,
		"username": "AegisASI",
		"source":   "aegis-asi",
		"events":   structured,
	}
	if run != nil {
		payload["scan_run"] = map[string]any{"id": run.ID, "name": run.Name, "run_type": run.RunType}
	}
	return payload
}

// Notifier implements ingest.ChangeNotifier.
type Notifier struct {
	store  db.Store
	client *http.Client
	// Async sends in a goroutine (default) so a slow receiver never delays ingest.
	Async bool
	wg    sync.WaitGroup
	mu    sync.Mutex // serialises status write-backs
}

// New returns an async notifier with a 10s HTTP timeout.
func New(store db.Store) *Notifier {
	return &Notifier{store: store, client: &http.Client{Timeout: 10 * time.Second}, Async: true}
}

// Wait blocks until in-flight async sends finished (tests, graceful shutdown).
func (n *Notifier) Wait() { n.wg.Wait() }

// NotifyChanges filters the run's changes and posts them when the webhook is enabled.
func (n *Notifier) NotifyChanges(ctx context.Context, run *domain.ScanRun, changes []domain.ChangeEvent) {
	cfg, err := LoadConfig(ctx, n.store)
	if err != nil || cfg == nil || !cfg.Enabled || cfg.URL == "" {
		return
	}
	events := n.dropSuppressed(ctx, SelectEvents(cfg, changes))
	if len(events) == 0 {
		return
	}
	payload := BuildPayload(run, events, "")
	send := func() {
		sendCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := n.Send(sendCtx, cfg.URL, payload)
		n.recordResult(err)
		if err != nil {
			log.Printf("[WARN] alert webhook failed: %v", err)
		}
	}
	if n.Async {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			send()
		}()
		return
	}
	send()
}

// dropSuppressed removes events for hosts/services with an active accepted-risk or
// false-positive decision.
func (n *Notifier) dropSuppressed(ctx context.Context, events []domain.ChangeEvent) []domain.ChangeEvent {
	now := time.Now()
	hosts := map[string]*domain.Host{}
	out := events[:0:0]
	for _, ev := range events {
		h, ok := hosts[ev.HostID]
		if !ok && ev.HostID != "" {
			h, _ = n.store.GetHost(ctx, ev.HostID)
			hosts[ev.HostID] = h
		}
		if h != nil {
			if h.Triage.IsSuppressing(now) {
				continue
			}
			suppressed := false
			if ev.ServiceID != "" {
				for i := range h.Services {
					if h.Services[i].ID == ev.ServiceID && h.Services[i].Triage.IsSuppressing(now) {
						suppressed = true
						break
					}
				}
			}
			if suppressed {
				continue
			}
		}
		out = append(out, ev)
	}
	return out
}

func (n *Notifier) recordResult(sendErr error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, err := LoadConfig(ctx, n.store)
	if err != nil || cfg == nil {
		return
	}
	now := time.Now().UTC()
	cfg.LastSentAt = &now
	if sendErr != nil {
		cfg.LastStatus, cfg.LastError = "failed", sendErr.Error()
	} else {
		cfg.LastStatus, cfg.LastError = "ok", ""
	}
	_ = SaveConfig(ctx, n.store, cfg)
}

// SendTest posts a test message to url (or the stored URL when empty) synchronously.
func (n *Notifier) SendTest(ctx context.Context, rawURL string) error {
	if rawURL == "" {
		cfg, err := LoadConfig(ctx, n.store)
		if err != nil {
			return err
		}
		rawURL = cfg.URL
	}
	if rawURL == "" {
		return errors.New("no webhook URL configured")
	}
	if err := ValidateURL(rawURL); err != nil {
		return err
	}
	now := time.Now().UTC()
	payload := BuildPayload(nil, []domain.ChangeEvent{{
		EventType: "TEST",
		Severity:  "info",
		HostIP:    "192.0.2.1",
		Summary:   "Test notification from AegisASI - the webhook works.",
		CreatedAt: now,
	}}, "AegisASI: test webhook")
	err := n.Send(ctx, rawURL, payload)
	n.recordResult(err)
	return err
}

// Send POSTs the JSON payload and treats any non-2xx answer as an error.
func (n *Notifier) Send(ctx context.Context, rawURL string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AegisASI-Webhook/1.0")
	client := n.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		// Never leak the secret URL (it carries the channel token) into logs / API errors.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return fmt.Errorf("webhook request to %s failed: %v", MaskURL(rawURL), uerr.Err)
		}
		return fmt.Errorf("webhook request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("webhook answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}
