package ingest

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// LoadTagRules returns the configured CIDR tag rules (empty when the store has no settings
// support or nothing was configured).
func LoadTagRules(ctx context.Context, store db.Store) []domain.TagRule {
	ss, ok := store.(db.SettingsStore)
	if !ok {
		return nil
	}
	var rules []domain.TagRule
	if found, err := ss.GetSetting(ctx, db.SettingTagRules, &rules); err != nil || !found {
		return nil
	}
	return rules
}

// NormalizeTagRule validates and canonicalises a rule (CIDR or single IP, trimmed tags).
func NormalizeTagRule(r *domain.TagRule) error {
	c := strings.TrimSpace(r.CIDR)
	if c == "" {
		return fmt.Errorf("cidr is required")
	}
	if !strings.Contains(c, "/") {
		ip := net.ParseIP(c)
		if ip == nil {
			return fmt.Errorf("invalid CIDR %q", r.CIDR)
		}
		if ip.To4() != nil {
			c += "/32"
		} else {
			c += "/128"
		}
	}
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q", r.CIDR)
	}
	r.CIDR = n.String()
	tags := make([]string, 0, len(r.Tags))
	for _, t := range r.Tags {
		if t = strings.TrimSpace(t); t != "" {
			tags = appendUnique(tags, t)
		}
	}
	r.Tags = tags
	r.Owner = strings.TrimSpace(r.Owner)
	r.Environment = strings.ToLower(strings.TrimSpace(r.Environment))
	r.Description = strings.TrimSpace(r.Description)
	if len(r.Tags) == 0 && r.Owner == "" && r.Environment == "" {
		return fmt.Errorf("rule %s must set at least one of tags, owner, environment", r.CIDR)
	}
	return nil
}

// RuleValues is what the tag rules derive for one IP: the union of tags of every matching
// enabled rule, plus owner / environment from the most specific rule that defines them.
type RuleValues struct {
	Tags        []string
	Owner       string
	Environment string
}

// DeriveRuleValues evaluates the rules for one IP.
func DeriveRuleValues(ipStr string, rules []domain.TagRule) RuleValues {
	var out RuleValues
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || len(rules) == 0 {
		return out
	}
	type hit struct {
		rule domain.TagRule
		ones int
	}
	var hits []hit
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		_, n, err := net.ParseCIDR(r.CIDR)
		if err != nil || !n.Contains(ip) {
			continue
		}
		ones, _ := n.Mask.Size()
		hits = append(hits, hit{rule: r, ones: ones})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].ones > hits[j].ones })
	for _, ht := range hits {
		for _, t := range ht.rule.Tags {
			if !containsFold(out.Tags, t) {
				out.Tags = append(out.Tags, t)
			}
		}
		if out.Owner == "" {
			out.Owner = ht.rule.Owner
		}
		if out.Environment == "" {
			out.Environment = ht.rule.Environment
		}
	}
	return out
}

// ApplyTagRules applies the current rules to an observed host record (used on ingest and by
// "apply now"). Owner is rule-derived only (scanners and importers never set it), so it is
// replaced by the most specific matching rule's owner; environment from a rule beats an
// unknown/empty value; rule tags are added. Analyst overrides still win on read because they
// are merged on top of the observed record. Returns true when the host changed.
func ApplyTagRules(h *domain.Host, rules []domain.TagRule) bool {
	return RecomputeTagRules(h, nil, rules)
}

// RecomputeTagRules moves a host from the values derived by oldRules to those derived by
// newRules: tags only the old rules gave are removed, new rule tags are added, and owner /
// environment that came from the old rules (or were empty) follow the new rules. Values the
// rules never produced (scanner tags, an inferred "staging" environment) are kept. With
// oldRules == nil it behaves like a plain apply. Returns true when the host changed.
func RecomputeTagRules(h *domain.Host, oldRules, newRules []domain.TagRule) bool {
	if h == nil || (len(oldRules) == 0 && len(newRules) == 0) {
		return false
	}
	oldV := DeriveRuleValues(h.IP, oldRules)
	newV := DeriveRuleValues(h.IP, newRules)
	changed := false

	// Tags: drop the ones only the previous rules produced, then add the current ones.
	if len(oldV.Tags) > 0 {
		kept := h.Tags[:0:0]
		for _, t := range h.Tags {
			if containsFold(oldV.Tags, t) && !containsFold(newV.Tags, t) {
				changed = true
				continue
			}
			kept = append(kept, t)
		}
		h.Tags = kept
	}
	for _, t := range newV.Tags {
		if !containsFold(h.Tags, t) {
			h.Tags = append(h.Tags, t)
			changed = true
		}
	}

	// Owner: scanners and importers never set it, so in the observed record it is purely
	// rule-derived (an analyst's owner is an override and wins on read).
	if strings.TrimSpace(h.Owner) != newV.Owner {
		h.Owner, changed = newV.Owner, true
	}

	// Environment: an explicit rule beats the scanner's guess; when the rule that set it goes
	// away, fall back to unknown (the pipeline may infer "staging" again on the next scan).
	env := strings.TrimSpace(h.Environment)
	switch {
	case newV.Environment != "":
		if env != newV.Environment {
			h.Environment, changed = newV.Environment, true
		}
	case oldV.Environment != "" && strings.EqualFold(env, oldV.Environment):
		h.Environment, changed = "unknown", true
	}
	return changed
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
