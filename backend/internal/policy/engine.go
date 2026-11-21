package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Retention of resolved violations (history shown in the UI).
const (
	resolvedKeep    = 30 * 24 * time.Hour
	maxResolvedKept = 1000
)

// State is the persisted violation ledger.
type State struct {
	Violations  []domain.PolicyViolation `json:"violations"`
	EvaluatedAt time.Time                `json:"evaluated_at"`
}

// Engine evaluates zone policies against the inventory, keeps the violation ledger
// (first/last seen, resolution) and serves the read-time index used by the asset query
// language (violation:true, policy:<name>) and the service badges.
type Engine struct {
	store db.Store
	mu    sync.Mutex // serialises evaluations
	idx   atomic.Pointer[index]
}

type hit struct {
	zoneID   string
	zoneName string // lower case, for matching
	display  domain.PolicyHit
}

type index struct {
	byHost    map[string][]hit
	byService map[string][]hit
}

// NewEngine returns an engine over store and loads the current ledger into the index.
func NewEngine(store db.Store) *Engine {
	e := &Engine{store: store}
	st := e.loadState(context.Background())
	e.rebuild(st.Violations)
	return e
}

func (e *Engine) loadState(ctx context.Context) State {
	var st State
	if ss, ok := e.store.(db.SettingsStore); ok {
		_, _ = ss.GetSetting(ctx, SettingViolations, &st)
	}
	return st
}

// State returns the ledger (open and recently resolved violations).
func (e *Engine) State(ctx context.Context) State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadState(ctx)
}

// Evaluate checks the whole inventory against the current zones, updates the ledger and
// returns the change events for violations that appeared, reappeared or resolved. The
// events are not stored: the ingest pipeline records them with its scan run, other callers
// use RecordEvents.
func (e *Engine) Evaluate(ctx context.Context) ([]domain.ChangeEvent, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ss, ok := e.store.(db.SettingsStore)
	if !ok {
		return nil, nil
	}
	zones, _ := LoadZones(ctx, e.store)
	prev := e.loadState(ctx)
	if len(zones) == 0 && len(prev.Violations) == 0 {
		return nil, nil
	}
	hosts, _, err := e.store.ListHosts(ctx, db.HostFilter{})
	if err != nil {
		return nil, fmt.Errorf("policy: list hosts: %w", err)
	}
	now := time.Now().UTC()
	current := Evaluate(zones, hosts, now)
	next, events := Merge(prev.Violations, current, now)
	if err := ss.SaveSetting(ctx, SettingViolations, State{Violations: next, EvaluatedAt: now}); err != nil {
		return nil, fmt.Errorf("policy: save violations: %w", err)
	}
	e.rebuild(next)
	return events, nil
}

// Merge folds the current evaluation into the previous ledger: new and reappearing
// violations open (keeping the original first seen), still present ones refresh last seen
// and details, missing open ones resolve. Returns the new ledger and the change events.
func Merge(prev, current []domain.PolicyViolation, now time.Time) ([]domain.PolicyViolation, []domain.ChangeEvent) {
	prevByID := make(map[string]domain.PolicyViolation, len(prev))
	for _, p := range prev {
		prevByID[p.ID] = p
	}
	curIDs := make(map[string]bool, len(current))
	var next []domain.PolicyViolation
	var events []domain.ChangeEvent
	for _, c := range current {
		curIDs[c.ID] = true
		p, existed := prevByID[c.ID]
		if existed && !p.FirstSeen.IsZero() {
			c.FirstSeen = p.FirstSeen
		} else {
			c.FirstSeen = now
		}
		c.Status, c.LastSeen, c.ResolvedAt = domain.PolicyStatusOpen, now, nil
		if !existed || p.Status != domain.PolicyStatusOpen {
			events = append(events, violationEvent(c, existed))
		}
		next = append(next, c)
	}
	var resolved []domain.PolicyViolation
	for _, p := range prev {
		if curIDs[p.ID] {
			continue
		}
		if p.Status == domain.PolicyStatusOpen {
			t := now
			p.Status, p.ResolvedAt = domain.PolicyStatusResolved, &t
			events = append(events, resolvedEvent(p))
		}
		if p.ResolvedAt != nil && now.Sub(*p.ResolvedAt) <= resolvedKeep {
			resolved = append(resolved, p)
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].ResolvedAt.After(*resolved[j].ResolvedAt) })
	if len(resolved) > maxResolvedKept {
		resolved = resolved[:maxResolvedKept]
	}
	next = append(next, resolved...)
	if next == nil {
		next = []domain.PolicyViolation{}
	}
	return next, events
}

func eventAfter(v domain.PolicyViolation) map[string]any {
	after := map[string]any{
		"violation_id": v.ID,
		"zone":         v.ZoneName,
		"zone_id":      v.ZoneID,
		"rule":         v.Rule,
		"rules":        v.Rules,
		"evidence":     v.Evidence,
		"status":       v.Status,
	}
	if v.Owner != "" {
		after["owner"] = v.Owner
	}
	return after
}

func violationEvent(v domain.PolicyViolation, reopened bool) domain.ChangeEvent {
	summary := "Policy violation: " + v.Summary
	if reopened {
		summary = "Policy violation again: " + v.Summary
	}
	return domain.ChangeEvent{
		HostID:    v.HostID,
		HostIP:    v.HostIP,
		ServiceID: v.ServiceID,
		Port:      v.Port,
		EventType: domain.EventPolicyViolation,
		Severity:  v.Severity,
		Summary:   summary,
		After:     eventAfter(v),
	}
}

func resolvedEvent(v domain.PolicyViolation) domain.ChangeEvent {
	return domain.ChangeEvent{
		HostID:    v.HostID,
		HostIP:    v.HostIP,
		ServiceID: v.ServiceID,
		Port:      v.Port,
		EventType: domain.EventPolicyResolved,
		Severity:  "info",
		Summary:   fmt.Sprintf("Policy violation resolved: %s on %s:%d in zone %q (%s)", nonEmpty(v.ServiceName, "service"), v.HostIP, v.Port, v.ZoneName, RuleLabel(v.Rule)),
		Before:    map[string]any{"rules": v.Rules, "severity": v.Severity},
		After:     eventAfter(v),
	}
}

// RecordEvents stores events produced outside an ingest (policy edits) and returns them
// with ids and timestamps. emit (optional) publishes each one live.
func (e *Engine) RecordEvents(ctx context.Context, events []domain.ChangeEvent, emit func(domain.LiveEvent)) []domain.ChangeEvent {
	now := time.Now().UTC()
	out := make([]domain.ChangeEvent, 0, len(events))
	for _, ev := range events {
		ev.ID = db.NewID()
		ev.CreatedAt = now
		if ev.TimeSlot == "" {
			ev.TimeSlot = domain.TimeSlotFor(now)
		}
		if err := e.store.AddChangeEvent(ctx, &ev); err != nil {
			continue
		}
		out = append(out, ev)
		if emit != nil {
			emit(domain.LiveEvent{Type: "change.detected", Timestamp: now, Payload: map[string]any{
				"change_id": ev.ID, "event_type": ev.EventType, "severity": ev.Severity, "host_ip": ev.HostIP, "summary": ev.Summary,
			}})
		}
	}
	return out
}

func (e *Engine) rebuild(vs []domain.PolicyViolation) {
	idx := &index{byHost: map[string][]hit{}, byService: map[string][]hit{}}
	for _, v := range vs {
		if v.Status != domain.PolicyStatusOpen {
			continue
		}
		h := hit{zoneID: v.ZoneID, zoneName: strings.ToLower(v.ZoneName), display: domain.PolicyHit{
			ZoneID: v.ZoneID, ZoneName: v.ZoneName, Rules: v.Rules, Severity: v.Severity, Summary: v.Summary,
		}}
		idx.byHost[v.HostID] = append(idx.byHost[v.HostID], h)
		if v.ServiceID != "" {
			idx.byService[v.ServiceID] = append(idx.byService[v.ServiceID], h)
		}
	}
	e.idx.Store(idx)
}

// HostHasViolation implements db.PolicyMatcher: values empty means any open violation;
// otherwise a value matches a zone name (substring), zone id, rule id, category or severity.
func (e *Engine) HostHasViolation(hostID string, values []string) bool {
	idx := e.idx.Load()
	if idx == nil {
		return false
	}
	return matchHits(idx.byHost[hostID], values)
}

// ServiceHasViolation implements db.PolicyMatcher for one service.
func (e *Engine) ServiceHasViolation(serviceID string, values []string) bool {
	idx := e.idx.Load()
	if idx == nil {
		return false
	}
	return matchHits(idx.byService[serviceID], values)
}

func matchHits(hits []hit, values []string) bool {
	if len(hits) == 0 {
		return false
	}
	if len(values) == 0 {
		return true
	}
	for _, h := range hits {
		for _, v := range values {
			if v == "" {
				continue
			}
			if strings.Contains(h.zoneName, v) || h.zoneID == v || h.display.Severity == v {
				return true
			}
			for _, r := range h.display.Rules {
				if r == v || strings.TrimPrefix(r, domain.PolicyRuleForbidden) == v {
					return true
				}
			}
		}
	}
	return false
}

// AnnotateServices fills PolicyViolations on each service from the index (read-time view).
func (e *Engine) AnnotateServices(services []domain.Service) {
	idx := e.idx.Load()
	if idx == nil {
		return
	}
	for i := range services {
		hits := idx.byService[services[i].ID]
		if len(hits) == 0 {
			continue
		}
		out := make([]domain.PolicyHit, 0, len(hits))
		for _, h := range hits {
			out = append(out, h.display)
		}
		services[i].PolicyViolations = out
	}
}

// AnnotateHosts annotates every service of every host.
func (e *Engine) AnnotateHosts(hosts []domain.Host) {
	for i := range hosts {
		e.AnnotateServices(hosts[i].Services)
	}
}

// OpenCount returns the number of open violations in the index.
func (e *Engine) OpenCount() int {
	idx := e.idx.Load()
	if idx == nil {
		return 0
	}
	n := 0
	for _, hs := range idx.byHost {
		n += len(hs)
	}
	return n
}
