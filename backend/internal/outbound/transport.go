package outbound

import (
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// WebhookPayload renders msg for the chosen chat format.
func WebhookPayload(format string, msg Message) map[string]any {
	text := msg.Body
	switch format {
	case FormatTeams:
		facts := make([]map[string]string, 0, len(msg.Facts))
		for _, f := range msg.Facts {
			facts = append(facts, map[string]string{"name": f[0], "value": f[1]})
		}
		card := map[string]any{
			"@type":      "MessageCard",
			"@context":   "https://schema.org/extensions",
			"summary":    msg.Subject,
			"themeColor": "C62F26",
			"title":      msg.Subject,
			// Teams renders Markdown: two spaces before a newline keep line breaks.
			"text": strings.ReplaceAll(text, "\n", "  \n"),
		}
		if len(facts) > 0 {
			card["sections"] = []map[string]any{{"facts": facts}}
		}
		return card
	case FormatGeneric:
		p := map[string]any{
			"text":     "*" + msg.Subject + "*\n" + text,
			"subject":  msg.Subject,
			"body":     text,
			"to":       msg.To,
			"source":   "dzieciol",
			"username": "Dzięcioł",
		}
		if msg.Data != nil {
			p["data"] = msg.Data
		}
		return p
	default: // slack, mattermost, discord
		full := "*" + msg.Subject + "*\n" + text
		content := full
		if len(content) > 1900 {
			content = content[:1900] + "..."
		}
		return map[string]any{"text": full, "content": content, "username": "Dzięcioł"}
	}
}

const smtpTimeout = 20 * time.Second

// sendSMTP sends with STARTTLS when the server offers it (ports 25/587) or implicit TLS
// (port 465). Every step has a deadline so a dead server never hangs a request.
func sendSMTP(s SMTPSettings, to []string, msg []byte) error {
	port := s.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(port))
	from := s.From
	if a, err := mail.ParseAddress(from); err == nil {
		from = a.Address
	}
	dialer := &net.Dialer{Timeout: smtpTimeout}
	tlsCfg := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return err
			}
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
