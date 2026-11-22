// Package outbound delivers human messages (owner notifications, the morning digest) over
// the channels the operator configured: SMTP email, a chat webhook (Slack, Teams,
// Mattermost, Discord or a generic JSON receiver) or, when nothing is configured, a manual
// fallback (mailto link and copy to clipboard). Nothing here fails hard because a channel
// is missing.
package outbound

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/notify"
)

// SettingDelivery is the encrypted settings document with the delivery channels.
const SettingDelivery = "delivery_channels"

// Channels.
const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
	ChannelManual  = "manual"
	ChannelAuto    = "auto"
)

// Webhook payload formats.
const (
	FormatSlack   = "slack"   // {"text": ...}; also read by Mattermost and Discord ("content")
	FormatTeams   = "teams"   // Office 365 connector MessageCard
	FormatGeneric = "generic" // text plus structured fields
)

// SMTPSettings configures outgoing email.
type SMTPSettings struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	HasPassword bool   `json:"has_password"`
	From        string `json:"from"`
}

// Settings holds the delivery channels. Password and webhook URL are secrets: API
// responses only carry HasPassword / WebhookMasked.
type Settings struct {
	SMTP          SMTPSettings `json:"smtp"`
	SMTPFromEnv   bool         `json:"smtp_from_env"`
	WebhookURL    string       `json:"webhook_url,omitempty"`
	HasWebhookURL bool         `json:"has_webhook_url"`
	WebhookMasked string       `json:"webhook_masked,omitempty"`
	WebhookFormat string       `json:"webhook_format"`
	// UseAlertWebhook falls back to the alert webhook (Admin > Integrations) when no
	// dedicated webhook is set.
	UseAlertWebhook bool `json:"use_alert_webhook"`

	// NoticeLanguage is the default language of owner notices: "pl" (new installs) or
	// "en". The analyst can switch it per message.
	NoticeLanguage string `json:"notice_language"`
	// Timezone is the instance timezone (IANA name, default Europe/Warsaw): every date in
	// notices, ticket history and the digest is written in it.
	Timezone string `json:"timezone"`
	// SLADays overrides the days to fix per severity ("critical", "high", "medium",
	// "low"). Missing keys use the DefectDojo default SLA table in internal/remediation,
	// so ticket due dates, the notice "patch by" date and DefectDojo agree.
	SLADays map[string]int `json:"sla_days,omitempty"`
}

// SLASeverities are the keys SLADays accepts.
var SLASeverities = []string{"critical", "high", "medium", "low"}

// Location is the instance timezone.
func (s *Settings) Location() *time.Location { return locale.Location(s.Timezone) }

// Language is the default notice language.
func (s *Settings) Language() string {
	if l := locale.Lang(s.NoticeLanguage); l != "" {
		return l
	}
	return locale.PL
}

// defaultLanguage: a delivery document saved by an older version (found, no language)
// keeps the English notices it always sent; a new install starts in Polish.
func defaultLanguage(found bool) string {
	if found {
		return locale.EN
	}
	return locale.PL
}

// EmailReady reports whether SMTP can send.
func (s *Settings) EmailReady() bool {
	return strings.TrimSpace(s.SMTP.Host) != "" && strings.TrimSpace(s.SMTP.From) != ""
}

// Load returns the stored settings with DZIECIOL_SMTP_* environment values on top. alert
// is consulted for the alert webhook fallback.
func Load(ctx context.Context, store db.Store) *Settings {
	s := &Settings{WebhookFormat: FormatSlack, UseAlertWebhook: true}
	found := false
	if ss, ok := store.(db.SettingsStore); ok {
		found, _ = ss.GetSetting(ctx, SettingDelivery, s)
	}
	if s.WebhookFormat == "" {
		s.WebhookFormat = FormatSlack
	}
	if s.NoticeLanguage = locale.Lang(s.NoticeLanguage); s.NoticeLanguage == "" {
		s.NoticeLanguage = defaultLanguage(found)
	}
	if strings.TrimSpace(s.Timezone) == "" || locale.ValidTimezone(s.Timezone) != nil {
		s.Timezone = locale.DefaultTimezone
	}
	applyEnv(s)
	return s
}

func applyEnv(s *Settings) {
	host := strings.TrimSpace(os.Getenv("DZIECIOL_SMTP_HOST"))
	if host == "" {
		return
	}
	s.SMTPFromEnv = true
	s.SMTP.Host = host
	s.SMTP.Port, _ = strconv.Atoi(os.Getenv("DZIECIOL_SMTP_PORT"))
	s.SMTP.Username = os.Getenv("DZIECIOL_SMTP_USERNAME")
	s.SMTP.Password = os.Getenv("DZIECIOL_SMTP_PASSWORD")
	s.SMTP.From = os.Getenv("DZIECIOL_SMTP_FROM")
}

// Save persists settings. Empty secrets keep the stored value unless clear is set.
func Save(ctx context.Context, store db.Store, in *Settings, clearPassword, clearWebhook bool) error {
	ss, ok := store.(db.SettingsStore)
	if !ok {
		return errors.New("store does not support settings")
	}
	var cur Settings
	found, _ := ss.GetSetting(ctx, SettingDelivery, &cur)
	out := *in
	out.SMTPFromEnv, out.HasWebhookURL, out.WebhookMasked, out.SMTP.HasPassword = false, false, "", false
	if out.SMTP.Password == "" && !clearPassword {
		out.SMTP.Password = cur.SMTP.Password
	}
	if out.WebhookURL == "" && !clearWebhook {
		out.WebhookURL = cur.WebhookURL
	}
	if out.WebhookURL != "" {
		if err := notify.ValidateURL(out.WebhookURL); err != nil {
			return err
		}
	}
	if out.SMTP.From != "" {
		if _, err := mail.ParseAddress(out.SMTP.From); err != nil {
			return fmt.Errorf("invalid sender address: %v", err)
		}
	}
	switch out.WebhookFormat {
	case FormatSlack, FormatTeams, FormatGeneric:
	case "":
		out.WebhookFormat = FormatSlack
	default:
		return fmt.Errorf("unknown webhook format %q", out.WebhookFormat)
	}
	// Fields an older client does not send keep their stored value.
	switch {
	case strings.TrimSpace(out.NoticeLanguage) == "":
		out.NoticeLanguage = nonEmptyStr(locale.Lang(cur.NoticeLanguage), defaultLanguage(found))
	case locale.Lang(out.NoticeLanguage) == "":
		return fmt.Errorf("unknown notice language %q (use pl or en)", out.NoticeLanguage)
	default:
		out.NoticeLanguage = locale.Lang(out.NoticeLanguage)
	}
	out.Timezone = strings.TrimSpace(out.Timezone)
	if out.Timezone == "" {
		out.Timezone = nonEmptyStr(cur.Timezone, locale.DefaultTimezone)
	}
	if err := locale.ValidTimezone(out.Timezone); err != nil {
		return err
	}
	if out.SLADays == nil {
		out.SLADays = cur.SLADays
	}
	if err := validSLA(out.SLADays); err != nil {
		return err
	}
	return ss.SaveSetting(ctx, SettingDelivery, &out)
}

func validSLA(m map[string]int) error {
	for k, v := range m {
		known := false
		for _, s := range SLASeverities {
			known = known || k == s
		}
		if !known {
			return fmt.Errorf("unknown SLA severity %q (use critical, high, medium, low)", k)
		}
		if v < 1 || v > 3650 {
			return fmt.Errorf("SLA days for %s must be between 1 and 3650", k)
		}
	}
	return nil
}

func nonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// Public returns a copy without secrets.
func Public(s *Settings) *Settings {
	cp := *s
	cp.SMTP.HasPassword = s.SMTP.Password != ""
	cp.SMTP.Password = ""
	cp.HasWebhookURL = s.WebhookURL != ""
	cp.WebhookMasked = notify.MaskURL(s.WebhookURL)
	cp.WebhookURL = ""
	return &cp
}

// Message is one human message.
type Message struct {
	To      []string
	Subject string
	Body    string // plain text
	// Facts are short key/value lines rendered as a table by Teams.
	Facts [][2]string
	// Data is attached as "data" to generic webhook payloads.
	Data any
}

// Result is the outcome of one delivery.
type Result struct {
	Channel   string    `json:"channel"` // email, webhook, manual
	Delivered bool      `json:"delivered"`
	Target    string    `json:"target,omitempty"` // recipients or masked webhook
	Error     string    `json:"error,omitempty"`
	Mailto    string    `json:"mailto,omitempty"` // manual fallback
	Attempts  []Attempt `json:"attempts,omitempty"`
}

// Attempt records one tried channel.
type Attempt struct {
	Channel string `json:"channel"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// Available lists usable channels.
type Available struct {
	Email         bool   `json:"email"`
	Webhook       bool   `json:"webhook"`
	WebhookSource string `json:"webhook_source,omitempty"` // dedicated, alert
	WebhookFormat string `json:"webhook_format"`
}

// Deliverer sends messages.
type Deliverer struct {
	store    db.Store
	notifier *notify.Notifier
	// SendMail is replaceable in tests.
	SendMail func(s SMTPSettings, to []string, msg []byte) error
}

// NewDeliverer returns a deliverer using notifier for webhook POSTs.
func NewDeliverer(store db.Store, notifier *notify.Notifier) *Deliverer {
	if notifier == nil {
		notifier = notify.New(store)
	}
	return &Deliverer{store: store, notifier: notifier, SendMail: sendSMTP}
}

// webhook resolves the webhook URL and its source.
func (d *Deliverer) webhook(ctx context.Context, s *Settings) (string, string) {
	if s.WebhookURL != "" {
		return s.WebhookURL, "dedicated"
	}
	if s.UseAlertWebhook {
		if cfg, err := notify.LoadConfig(ctx, d.store); err == nil && cfg != nil && cfg.URL != "" {
			return cfg.URL, "alert"
		}
	}
	return "", ""
}

// Channels reports what is configured.
func (d *Deliverer) Channels(ctx context.Context) Available {
	s := Load(ctx, d.store)
	u, src := d.webhook(ctx, s)
	return Available{Email: s.EmailReady(), Webhook: u != "", WebhookSource: src, WebhookFormat: s.WebhookFormat}
}

// Deliver sends msg on channel (auto: email when recipients and SMTP exist, else webhook,
// else manual). webhookOverride, when set, replaces the configured webhook (digest has
// its own). A failed channel falls through to the next one; the manual fallback always
// "succeeds" with a mailto link and Delivered=false.
func (d *Deliverer) Deliver(ctx context.Context, channel string, msg Message, webhookOverride, formatOverride string) Result {
	s := Load(ctx, d.store)
	hookURL, _ := d.webhook(ctx, s)
	if webhookOverride != "" {
		hookURL = webhookOverride
	}
	format := s.WebhookFormat
	if formatOverride != "" {
		format = formatOverride
	}
	var order []string
	switch channel {
	case ChannelEmail:
		order = []string{ChannelEmail, ChannelWebhook}
	case ChannelWebhook:
		order = []string{ChannelWebhook}
	case ChannelManual:
		order = nil
	default:
		order = []string{ChannelEmail, ChannelWebhook}
	}
	res := Result{}
	for _, ch := range order {
		switch ch {
		case ChannelEmail:
			if !s.EmailReady() || len(validRecipients(msg.To)) == 0 {
				continue
			}
			to := validRecipients(msg.To)
			err := d.SendMail(s.SMTP, to, BuildMIME(s.SMTP.From, to, msg.Subject, msg.Body, time.Now()))
			res.Attempts = append(res.Attempts, attempt(ch, err))
			if err == nil {
				res.Channel, res.Delivered, res.Target = ChannelEmail, true, strings.Join(to, ", ")
				return res
			}
			res.Error = err.Error()
		case ChannelWebhook:
			if hookURL == "" {
				continue
			}
			sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := d.notifier.Send(sendCtx, hookURL, WebhookPayload(format, msg))
			cancel()
			res.Attempts = append(res.Attempts, attempt(ch, err))
			if err == nil {
				res.Channel, res.Delivered, res.Target, res.Error = ChannelWebhook, true, notify.MaskURL(hookURL), ""
				return res
			}
			res.Error = err.Error()
		}
	}
	res.Channel = ChannelManual
	res.Mailto = Mailto(msg.To, msg.Subject, msg.Body)
	return res
}

func attempt(ch string, err error) Attempt {
	if err != nil {
		return Attempt{Channel: ch, Error: err.Error()}
	}
	return Attempt{Channel: ch, OK: true}
}

func validRecipients(to []string) []string {
	var out []string
	for _, t := range to {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if a, err := mail.ParseAddress(t); err == nil {
			out = append(out, a.Address)
		}
	}
	return out
}

// Mailto builds a mailto: link (body capped so mail clients accept it).
func Mailto(to []string, subject, body string) string {
	if len(body) > 1800 {
		body = body[:1800] + "\n..."
	}
	q := url.Values{}
	q.Set("subject", subject)
	q.Set("body", body)
	enc := strings.ReplaceAll(q.Encode(), "+", "%20")
	return "mailto:" + strings.Join(validRecipients(to), ",") + "?" + enc
}

// BuildMIME renders a plain text UTF-8 email.
func BuildMIME(from string, to []string, subject, body string, now time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mimeHeader(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("X-Mailer: Dzieciol\r\n\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	b.WriteString("\r\n")
	return []byte(b.String())
}

func mimeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?UTF-8?B?" + base64Std(s) + "?="
		}
	}
	return s
}
