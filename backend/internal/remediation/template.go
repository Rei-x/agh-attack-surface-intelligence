package remediation

import (
	"fmt"
	"strings"
	"time"
)

// actionVerb is the plain request for each action.
var actionVerb = map[string]string{
	ActionPatch:    "patch",
	ActionRemove:   "remove",
	ActionRestrict: "restrict access to",
}

// Draft is the editable message the analyst sends to the owner.
type Draft struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// BuildDraft writes the default owner message for a ticket. advice is the "what to do"
// line; firstSeen may be zero.
func BuildDraft(t *Ticket, advice string, firstSeen time.Time) Draft {
	where := t.Where()
	if t.Hostname != "" {
		where += " (" + t.Hostname + ")"
	}
	subject := fmt.Sprintf("[CBI AGH] Action needed: %s", t.Title)
	if len(subject) > 160 {
		subject = subject[:157] + "..."
	}
	var b strings.Builder
	greet := "Hello"
	if name := ownerName(t.Owner); name != "" {
		greet += " " + name
	}
	b.WriteString(greet + ",\n\n")
	b.WriteString("Our network monitoring found an issue on a host you manage.\n\n")
	fmt.Fprintf(&b, "What: %s\n", t.Title)
	fmt.Fprintf(&b, "Where: %s\n", where)
	if t.Service != "" {
		fmt.Fprintf(&b, "Service: %s\n", t.Service)
	}
	if t.Evidence != "" {
		fmt.Fprintf(&b, "Evidence: %s\n", t.Evidence)
	}
	if !firstSeen.IsZero() {
		fmt.Fprintf(&b, "First seen: %s\n", firstSeen.UTC().Format("2006-01-02"))
	}
	b.WriteString("\n")
	if advice != "" {
		fmt.Fprintf(&b, "What to do: %s\n", advice)
	}
	verb := actionVerb[t.Action]
	if verb == "" {
		verb = "fix"
	}
	if t.DueAt != nil {
		fmt.Fprintf(&b, "Please %s it by %s and reply when done. ", verb, t.DueAt.Format("2006-01-02"))
	} else {
		fmt.Fprintf(&b, "Please %s it and reply when done. ", verb)
	}
	b.WriteString("We check again after every scan and close this request once the issue is gone.\n\n")
	b.WriteString("If this host is not yours, please tell us who manages it.\n\n")
	b.WriteString("CBI AGH security team")
	return Draft{Subject: subject, Body: b.String()}
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
