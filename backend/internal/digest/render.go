package digest

import (
	"fmt"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/outbound"
)

const listCap = 10

// Title is the digest subject line.
func (d *Digest) Title() string {
	return "Dzięcioł digest " + d.CreatedAt.Format("2006-01-02")
}

// Markdown renders the full digest.
func (d *Digest) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", d.Title())
	fmt.Fprintf(&b, "%s\n\n", d.Headline)
	fmt.Fprintf(&b, "Window: %s to %s UTC", d.Since.UTC().Format("2006-01-02 15:04"), d.CreatedAt.UTC().Format("2006-01-02 15:04"))
	if d.ScanName != "" {
		fmt.Fprintf(&b, " (after scan %q)", d.ScanName)
	}
	b.WriteString("\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString("| | Count |\n|---|---:|\n")
	rows := [][2]any{
		{"New risky exposures", d.Counts.Risky}, {"New services", d.Counts.NewServices},
		{"Closed services", d.Counts.ClosedServices}, {"New hosts", d.Counts.NewHosts},
		{"Hosts gone", d.Counts.GoneHosts}, {"Fixes verified", d.Counts.Fixed},
		{"Overdue tickets", d.Counts.Overdue}, {"Open tickets", d.Counts.OpenTickets},
	}
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %v |\n", r[0], r[1])
	}
	b.WriteString("\n")

	if len(d.TopRisks) > 0 {
		b.WriteString("## Top risks\n\n")
		for i, r := range d.TopRisks {
			fmt.Fprintf(&b, "%d. **%s** (score %d, owner: %s)%s\n", i+1, r.Title, r.Score, ownerText(r.Owner), ticketText(r.Ticket))
		}
		b.WriteString("\n")
	}
	if len(d.Risky) > 0 {
		b.WriteString("## New risky exposures\n\n")
		for _, r := range capRisk(d.Risky) {
			fmt.Fprintf(&b, "- %s (owner: %s)%s\n", r.Title, ownerText(r.Owner), ticketText(r.Ticket))
		}
		if n := len(d.Risky) - listCap; n > 0 {
			fmt.Fprintf(&b, "- and %d more\n", n)
		}
		b.WriteString("\n")
	}
	if len(d.Fixed) > 0 || len(d.Overdue) > 0 {
		b.WriteString("## Remediation\n\n")
		for _, t := range d.Fixed {
			fmt.Fprintf(&b, "- Fixed: %s on %s (owner: %s)", t.Title, t.Where, ownerText(t.Owner))
			if t.Note != "" {
				fmt.Fprintf(&b, ", %s", t.Note)
			}
			b.WriteString("\n")
		}
		for _, t := range d.Overdue {
			due := ""
			if t.DueAt != nil {
				due = ", due " + t.DueAt.Format("2006-01-02")
			}
			fmt.Fprintf(&b, "- Overdue: %s on %s (owner: %s%s)\n", t.Title, t.Where, ownerText(t.Owner), due)
		}
		b.WriteString("\n")
	}
	if len(d.Owners) > 0 {
		b.WriteString("## By owner\n\n")
		for _, g := range d.Owners {
			fmt.Fprintf(&b, "### %s\n\n", g.Owner)
			for _, r := range g.Risky {
				fmt.Fprintf(&b, "- Risky: %s\n", r.Title)
			}
			for _, s := range g.NewServices {
				fmt.Fprintf(&b, "- New service: %s:%d %s\n", s.IP, s.Port, s.Service)
			}
			for _, h := range g.NewHosts {
				fmt.Fprintf(&b, "- New host: %s %s\n", h.IP, h.Hostname)
			}
			for _, h := range g.GoneHosts {
				fmt.Fprintf(&b, "- Host gone: %s %s\n", h.IP, h.Hostname)
			}
			for _, t := range g.Fixed {
				fmt.Fprintf(&b, "- Fixed: %s\n", t.Title)
			}
			for _, t := range g.Overdue {
				fmt.Fprintf(&b, "- Overdue: %s\n", t.Title)
			}
			b.WriteString("\n")
		}
	}
	if len(d.ClosedServices) > 0 {
		b.WriteString("## Closed services\n\n")
		for i, s := range d.ClosedServices {
			if i >= listCap {
				fmt.Fprintf(&b, "- and %d more\n", len(d.ClosedServices)-listCap)
				break
			}
			fmt.Fprintf(&b, "- %s:%d %s (owner: %s)\n", s.IP, s.Port, s.Service, ownerText(s.Owner))
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// Message is the short chat/email version.
func (d *Digest) Message(link string) outbound.Message {
	var b strings.Builder
	b.WriteString(d.Headline + "\n")
	if len(d.TopRisks) > 0 {
		b.WriteString("\nTop risks:\n")
		for i, r := range d.TopRisks {
			fmt.Fprintf(&b, "%d. %s (owner: %s)%s\n", i+1, r.Title, ownerText(r.Owner), ticketText(r.Ticket))
		}
	}
	if len(d.Risky) > 0 {
		b.WriteString("\nNew risky exposures:\n")
		for _, r := range capRisk(d.Risky) {
			fmt.Fprintf(&b, "- %s (owner: %s)\n", r.Title, ownerText(r.Owner))
		}
	}
	if len(d.Fixed) > 0 {
		fmt.Fprintf(&b, "\nFixed overnight: %d\n", len(d.Fixed))
		for _, t := range d.Fixed {
			fmt.Fprintf(&b, "- %s on %s\n", t.Title, t.Where)
		}
	}
	if len(d.Overdue) > 0 {
		fmt.Fprintf(&b, "\nOverdue: %d\n", len(d.Overdue))
		for _, t := range d.Overdue {
			fmt.Fprintf(&b, "- %s (owner: %s)\n", t.Title, ownerText(t.Owner))
		}
	}
	if link != "" {
		b.WriteString("\nFull digest: " + link + "\n")
	}
	return outbound.Message{
		Subject: d.Title(),
		Body:    strings.TrimRight(b.String(), "\n"),
		Facts: [][2]string{
			{"New risky exposures", fmt.Sprint(d.Counts.Risky)},
			{"New services", fmt.Sprint(d.Counts.NewServices)},
			{"Hosts new / gone", fmt.Sprintf("%d / %d", d.Counts.NewHosts, d.Counts.GoneHosts)},
			{"Fixed / overdue", fmt.Sprintf("%d / %d", d.Counts.Fixed, d.Counts.Overdue)},
		},
		Data: d,
	}
}

func capRisk(r []RiskItem) []RiskItem {
	if len(r) > listCap {
		return r[:listCap]
	}
	return r
}

func ownerText(o string) string {
	if strings.TrimSpace(o) == "" {
		return "unknown"
	}
	return o
}

func ticketText(status string) string {
	if status == "" {
		return ""
	}
	return " [ticket: " + strings.ReplaceAll(status, "_", " ") + "]"
}
