package remediation

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
)

// Draft is the editable message the analyst sends to the owner.
type Draft struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// Notice is what BuildDraft needs besides the ticket: the language, the instance
// timezone and the issue texts in that language.
type Notice struct {
	Lang string
	Loc  *time.Location
	// Title, Evidence and Advice of the issue in Lang; empty Title / Evidence fall back to
	// the ticket's (English) ones.
	Title, Evidence, Advice string
	// FirstSeen of the service or host (may be zero).
	FirstSeen time.Time
}

// BuildDraft writes the default owner message for a ticket. Every date is an ISO day in
// the instance timezone.
func BuildDraft(t *Ticket, n Notice) Draft {
	tx := textFor(n.Lang)
	loc := n.Loc
	if loc == nil {
		loc = locale.Location("")
	}
	title := nonEmpty(n.Title, t.Title)
	evidence := nonEmpty(n.Evidence, t.Evidence)
	where := t.Where()
	if t.Hostname != "" {
		where += " (" + t.Hostname + ")"
	}
	subject := truncateRunes(fmt.Sprintf(tx.subject, title), 160)
	var b strings.Builder
	// English greets the owner by name ("Hello WI IT,"); Polish keeps the formal greeting
	// and names the owner in the first sentence instead.
	name := ownerName(t.Owner)
	b.WriteString(withName(tx.greeting, tx.greetingNamed, name) + "\n\n")
	b.WriteString(withName(tx.intro, tx.introFor, name) + "\n\n")
	fmt.Fprintf(&b, "%s: %s\n", tx.fWhat, title)
	fmt.Fprintf(&b, "%s: %s\n", tx.fWhere, where)
	if t.Service != "" {
		fmt.Fprintf(&b, "%s: %s\n", tx.fService, t.Service)
	}
	if evidence != "" {
		fmt.Fprintf(&b, "%s: %s\n", tx.fEvidence, evidence)
	}
	if !n.FirstSeen.IsZero() {
		fmt.Fprintf(&b, "%s: %s\n", tx.fFirstSeen, locale.Date(n.FirstSeen, loc))
	}
	b.WriteString("\n")
	if n.Advice != "" {
		fmt.Fprintf(&b, "%s: %s\n", tx.fTodo, n.Advice)
	}
	action := t.Action
	if _, ok := tx.askBy[action]; !ok {
		action = ""
	}
	if t.DueAt != nil {
		fmt.Fprintf(&b, tx.askBy[action], locale.DueDay(*t.DueAt, loc))
	} else {
		b.WriteString(tx.ask[action])
	}
	b.WriteString(" " + tx.recheck + "\n\n")
	b.WriteString(tx.notYours + "\n\n")
	b.WriteString(tx.signoff)
	return Draft{Subject: subject, Body: b.String()}
}

// withName is named (a format with one %s) filled with name, or plain without a name.
func withName(plain, named, name string) string {
	if name == "" || !strings.Contains(named, "%s") {
		return plain
	}
	return fmt.Sprintf(named, name)
}

// truncateRunes cuts s to at most max bytes on a character boundary ("..." appended), so
// a Polish subject never ends in half a letter.
func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// ownerName turns "WI IT <admin@wi.agh.edu.pl>" into "WI IT"; plain emails give "".
func ownerName(owner string) string {
	owner = strings.TrimSpace(owner)
	if i := strings.Index(owner, "<"); i >= 0 {
		owner = strings.TrimSpace(owner[:i])
	}
	if owner == "" || strings.Contains(owner, "@") {
		return ""
	}
	return owner
}
