// Package digest builds the morning digest: what changed on the network since the last
// digest (new and gone hosts and services, new risky exposures), the top risks, everything
// grouped per owner, and remediation progress (fixed overnight, overdue).
package digest

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/remediation"
)

// Unassigned groups items without an owner.
const Unassigned = "Unassigned"

// HostItem is a host that appeared or disappeared.
type HostItem struct {
	HostID   string `json:"host_id"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

// ServiceItem is a service that appeared or closed.
type ServiceItem struct {
	HostID    string `json:"host_id"`
	ServiceID string `json:"service_id,omitempty"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Service   string `json:"service,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Severity  string `json:"severity,omitempty"`
}

// RiskItem is one risky exposure.
type RiskItem struct {
	HostID    string `json:"host_id"`
	ServiceID string `json:"service_id,omitempty"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	Owner     string `json:"owner,omitempty"`
	Score     int    `json:"score"`
	Ticket    string `json:"ticket_status,omitempty"` // status of the remediation ticket, if any
}

// TicketItem is a ticket in the remediation section.
type TicketItem struct {
	ID     string     `json:"id"`
	HostID string     `json:"host_id"`
	Where  string     `json:"where"`
	Title  string     `json:"title"`
	Owner  string     `json:"owner,omitempty"`
	DueAt  *time.Time `json:"due_at,omitempty"`
	// DueDate is the due day in the instance timezone.
	DueDate string `json:"due_date,omitempty"`
	Note    string `json:"note,omitempty"`
	// FixedReason / Outcome say what closed a fixed ticket: a removed (unreachable)
	// service is not an upgrade.
	FixedReason string `json:"fixed_reason,omitempty"`
	Outcome     string `json:"outcome,omitempty"`
}

// OwnerGroup is everything that concerns one owner.
type OwnerGroup struct {
	Owner       string        `json:"owner"`
	NewHosts    []HostItem    `json:"new_hosts,omitempty"`
	GoneHosts   []HostItem    `json:"gone_hosts,omitempty"`
	NewServices []ServiceItem `json:"new_services,omitempty"`
	Risky       []RiskItem    `json:"risky,omitempty"`
	Fixed       []TicketItem  `json:"fixed,omitempty"`
	Overdue     []TicketItem  `json:"overdue,omitempty"`
}

// Counts are the headline numbers.
type Counts struct {
	NewHosts       int `json:"new_hosts"`
	GoneHosts      int `json:"gone_hosts"`
	NewServices    int `json:"new_services"`
	ClosedServices int `json:"closed_services"`
	Risky          int `json:"risky"`
	Fixed          int `json:"fixed"`
	Overdue        int `json:"overdue"`
	OpenTickets    int `json:"open_tickets"`
}

// Digest is one morning digest.
type Digest struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Since     time.Time `json:"since"`
	// Timezone the digest's dates are written in (the instance timezone when it was built).
	Timezone       string        `json:"timezone,omitempty"`
	ScanRunID      string        `json:"scan_run_id,omitempty"`
	ScanName       string        `json:"scan_name,omitempty"`
	Headline       string        `json:"headline"`
	Counts         Counts        `json:"counts"`
	NewHosts       []HostItem    `json:"new_hosts"`
	GoneHosts      []HostItem    `json:"gone_hosts"`
	NewServices    []ServiceItem `json:"new_services"`
	ClosedServices []ServiceItem `json:"closed_services"`
	Risky          []RiskItem    `json:"risky"`
	TopRisks       []RiskItem    `json:"top_risks"`
	Owners         []OwnerGroup  `json:"owners"`
	Fixed          []TicketItem  `json:"fixed"`
	Overdue        []TicketItem  `json:"overdue"`
	Preview        bool          `json:"preview,omitempty"`
	Delivered      bool          `json:"delivered"`
	DeliveredAt    *time.Time    `json:"delivered_at,omitempty"`
	Delivery       []string      `json:"delivery,omitempty"` // human notes per channel
}

// Input is everything Build needs.
type Input struct {
	Now   time.Time
	Since time.Time
	// Timezone of the instance ("": Europe/Warsaw).
	Timezone string
	Run      *domain.ScanRun
	Changes  []domain.ChangeEvent
	Hosts    []domain.Host // with services
	Tickets  []remediation.Ticket
}

// riskyEventTypes are the change types whose service is checked for issues.
var riskyEventTypes = map[string]bool{
	"NEW_SERVICE": true, "ADMIN_PANEL_EXPOSED": true, "SERVICE_CHANGED": true, "OUTDATED_VERSION": true,
}

// Build assembles the digest. It is pure: same input, same digest.
func Build(in Input) *Digest {
	d := &Digest{CreatedAt: in.Now, Since: in.Since, Timezone: locale.Location(in.Timezone).String()}
	loc := d.loc()
	if in.Run != nil {
		d.ScanRunID, d.ScanName = in.Run.ID, in.Run.Name
	}
	hosts := make(map[string]*domain.Host, len(in.Hosts))
	for i := range in.Hosts {
		hosts[in.Hosts[i].ID] = &in.Hosts[i]
	}
	ownerOf := func(hostID string, ev *domain.ChangeEvent) string {
		if h := hosts[hostID]; h != nil && h.Owner != "" {
			return h.Owner
		}
		if ev != nil {
			if o, _ := ev.After["owner"].(string); o != "" {
				return o
			}
		}
		return ""
	}
	ticketFor := map[string]string{} // host|service|kind -> status
	for _, t := range in.Tickets {
		if t.Active() || t.Status == remediation.StatusFixed {
			ticketFor[t.HostID+"|"+t.ServiceID+"|"+t.Kind] = t.Status
		}
	}

	seenHost := map[string]bool{}
	seenSvc := map[string]bool{}
	seenRisk := map[string]bool{}
	riskCandidates := map[string]bool{}
	changes := append([]domain.ChangeEvent(nil), in.Changes...)
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].CreatedAt.Before(changes[j].CreatedAt) })
	for i := range changes {
		ev := &changes[i]
		if ev.CreatedAt.Before(in.Since) || ev.CreatedAt.After(in.Now) {
			continue
		}
		switch ev.EventType {
		case "NEW_HOST":
			if !seenHost["new|"+ev.HostID] {
				seenHost["new|"+ev.HostID] = true
				d.NewHosts = append(d.NewHosts, hostItem(hosts[ev.HostID], ev, ownerOf(ev.HostID, ev)))
			}
		case "HOST_MISSING", "HOST_INACTIVE":
			if !seenHost["gone|"+ev.HostID] {
				seenHost["gone|"+ev.HostID] = true
				d.GoneHosts = append(d.GoneHosts, hostItem(hosts[ev.HostID], ev, ownerOf(ev.HostID, ev)))
			}
		case "SERVICE_CLOSED":
			key := "closed|" + ev.HostID + "|" + fmt.Sprint(ev.Port)
			if !seenSvc[key] {
				seenSvc[key] = true
				d.ClosedServices = append(d.ClosedServices, serviceItem(ev, ownerOf(ev.HostID, ev)))
			}
		}
		if ev.EventType == "NEW_SERVICE" || ev.EventType == "ADMIN_PANEL_EXPOSED" {
			key := "new|" + ev.HostID + "|" + fmt.Sprint(ev.Port)
			if !seenSvc[key] {
				seenSvc[key] = true
				d.NewServices = append(d.NewServices, serviceItem(ev, ownerOf(ev.HostID, ev)))
			}
		}
		if riskyEventTypes[ev.EventType] && ev.ServiceID != "" {
			riskCandidates[ev.HostID+"|"+ev.ServiceID] = true
		}
	}

	// New risky exposures: services touched in the window that have an issue now.
	var top []RiskItem
	for _, h := range in.Hosts {
		h := h
		gone := h.LifecycleState == domain.HostStateInactive || h.LifecycleState == domain.HostStateMissing
		if gone || h.Triage.IsSuppressing(in.Now) {
			continue
		}
		for j := range h.Services {
			s := h.Services[j]
			if (s.State != "" && s.State != "open") || s.Triage.IsSuppressing(in.Now) {
				continue
			}
			if s.HostIP == "" {
				s.HostIP = h.IP
			}
			issues := remediation.ServiceIssues(&s, in.Now)
			if riskCandidates[h.ID+"|"+s.ID] {
				for _, is := range issues {
					key := h.ID + "|" + s.ID + "|" + is.Key
					if seenRisk[key] {
						continue
					}
					seenRisk[key] = true
					d.Risky = append(d.Risky, RiskItem{
						HostID: h.ID, ServiceID: s.ID, IP: h.IP, Port: s.Port, Kind: is.Kind, Title: is.Title,
						Owner: h.Owner, Score: s.Interestingness, Ticket: ticketFor[h.ID+"|"+s.ID+"|"+is.Kind],
					})
				}
			}
			if s.Interestingness > 0 || len(issues) > 0 {
				ri := RiskItem{HostID: h.ID, ServiceID: s.ID, IP: h.IP, Port: s.Port, Owner: h.Owner, Score: s.Interestingness}
				if len(issues) > 0 {
					ri.Kind, ri.Title = issues[0].Kind, issues[0].Title
					ri.Ticket = ticketFor[h.ID+"|"+s.ID+"|"+issues[0].Kind]
				} else {
					ri.Kind, ri.Title = remediation.KindOther, fmt.Sprintf("%s on %s:%d", strings.TrimSpace(nonEmpty(s.Product+" "+s.Version, s.ServiceName)), h.IP, s.Port)
				}
				top = append(top, ri)
			}
		}
	}
	sort.SliceStable(d.Risky, func(i, j int) bool { return d.Risky[i].Score > d.Risky[j].Score })
	sort.SliceStable(top, func(i, j int) bool {
		if top[i].Score != top[j].Score {
			return top[i].Score > top[j].Score
		}
		return top[i].IP+fmt.Sprint(top[i].Port) < top[j].IP+fmt.Sprint(top[j].Port)
	})
	if len(top) > 5 {
		top = top[:5]
	}
	d.TopRisks = top

	for i := range in.Tickets {
		t := &in.Tickets[i]
		ti := TicketItem{ID: t.ID, HostID: t.HostID, Where: t.Where(), Title: t.Title, Owner: t.Owner, DueAt: t.DueAt}
		if t.DueAt != nil {
			ti.DueDate = locale.DueDay(*t.DueAt, loc)
		}
		switch {
		case t.Status == remediation.StatusFixed && t.FixedAt != nil && !t.FixedAt.Before(in.Since):
			ti.Note = t.LastCheckNote
			ti.FixedReason, ti.Outcome = t.FixedReason, t.FixOutcome()
			d.Fixed = append(d.Fixed, ti)
		case t.Active():
			d.Counts.OpenTickets++
			if t.Overdue || t.PastDue(in.Now) {
				d.Overdue = append(d.Overdue, ti)
			}
		}
	}

	d.Counts.NewHosts, d.Counts.GoneHosts = len(d.NewHosts), len(d.GoneHosts)
	d.Counts.NewServices, d.Counts.ClosedServices = len(d.NewServices), len(d.ClosedServices)
	d.Counts.Risky, d.Counts.Fixed, d.Counts.Overdue = len(d.Risky), len(d.Fixed), len(d.Overdue)
	d.Owners = groupByOwner(d)
	d.Headline = headline(d.Counts)
	d.ensureSlices()
	return d
}

func (d *Digest) ensureSlices() {
	if d.NewHosts == nil {
		d.NewHosts = []HostItem{}
	}
	if d.GoneHosts == nil {
		d.GoneHosts = []HostItem{}
	}
	if d.NewServices == nil {
		d.NewServices = []ServiceItem{}
	}
	if d.ClosedServices == nil {
		d.ClosedServices = []ServiceItem{}
	}
	if d.Risky == nil {
		d.Risky = []RiskItem{}
	}
	if d.TopRisks == nil {
		d.TopRisks = []RiskItem{}
	}
	if d.Owners == nil {
		d.Owners = []OwnerGroup{}
	}
	if d.Fixed == nil {
		d.Fixed = []TicketItem{}
	}
	if d.Overdue == nil {
		d.Overdue = []TicketItem{}
	}
}

func hostItem(h *domain.Host, ev *domain.ChangeEvent, owner string) HostItem {
	it := HostItem{HostID: ev.HostID, IP: ev.HostIP, Owner: owner, Summary: ev.Summary}
	if h != nil {
		it.Hostname = h.Hostname
		if it.IP == "" {
			it.IP = h.IP
		}
	}
	return it
}

func serviceItem(ev *domain.ChangeEvent, owner string) ServiceItem {
	name := ""
	if ev.After != nil {
		parts := []string{}
		for _, k := range []string{"service", "product", "version"} {
			if v, _ := ev.After[k].(string); v != "" {
				parts = append(parts, v)
			}
		}
		name = strings.Join(parts, " ")
	}
	if name == "" && ev.Before != nil {
		name, _ = ev.Before["service"].(string)
	}
	return ServiceItem{HostID: ev.HostID, ServiceID: ev.ServiceID, IP: ev.HostIP, Port: ev.Port, Service: name, Owner: owner, Severity: ev.Severity}
}

func groupByOwner(d *Digest) []OwnerGroup {
	groups := map[string]*OwnerGroup{}
	get := func(owner string) *OwnerGroup {
		if strings.TrimSpace(owner) == "" {
			owner = Unassigned
		}
		g := groups[owner]
		if g == nil {
			g = &OwnerGroup{Owner: owner}
			groups[owner] = g
		}
		return g
	}
	for _, h := range d.NewHosts {
		g := get(h.Owner)
		g.NewHosts = append(g.NewHosts, h)
	}
	for _, h := range d.GoneHosts {
		g := get(h.Owner)
		g.GoneHosts = append(g.GoneHosts, h)
	}
	for _, s := range d.NewServices {
		g := get(s.Owner)
		g.NewServices = append(g.NewServices, s)
	}
	for _, r := range d.Risky {
		g := get(r.Owner)
		g.Risky = append(g.Risky, r)
	}
	for _, t := range d.Fixed {
		g := get(t.Owner)
		g.Fixed = append(g.Fixed, t)
	}
	for _, t := range d.Overdue {
		g := get(t.Owner)
		g.Overdue = append(g.Overdue, t)
	}
	out := make([]OwnerGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	weight := func(g OwnerGroup) int {
		return len(g.Risky)*10 + len(g.Overdue)*5 + len(g.NewServices) + len(g.NewHosts) + len(g.GoneHosts)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Owner == Unassigned) != (out[j].Owner == Unassigned) {
			return out[j].Owner == Unassigned
		}
		if weight(out[i]) != weight(out[j]) {
			return weight(out[i]) > weight(out[j])
		}
		return out[i].Owner < out[j].Owner
	})
	return out
}

func headline(c Counts) string {
	var parts []string
	add := func(n int, one, many string) {
		if n == 1 {
			parts = append(parts, "1 "+one)
		} else if n > 1 {
			parts = append(parts, fmt.Sprintf("%d %s", n, many))
		}
	}
	add(c.Risky, "new risky exposure", "new risky exposures")
	add(c.NewServices, "new service", "new services")
	add(c.NewHosts, "new host", "new hosts")
	add(c.GoneHosts, "host gone", "hosts gone")
	add(c.ClosedServices, "service closed", "services closed")
	add(c.Fixed, "ticket closed as fixed", "tickets closed as fixed")
	add(c.Overdue, "ticket overdue", "tickets overdue")
	if len(parts) == 0 {
		return "Quiet night: nothing new on the network."
	}
	return strings.Join(parts, ", ") + "."
}

// loc is the timezone the digest is written in (digests of older versions: the default).
func (d *Digest) loc() *time.Location { return locale.Location(d.Timezone) }

// Day is the digest's local date ("2026-11-22").
func (d *Digest) Day() string { return locale.Date(d.CreatedAt, d.loc()) }

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return b
}
