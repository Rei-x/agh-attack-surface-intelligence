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

// ApplyTagRules adds the tags of every enabled rule whose CIDR contains the host IP, and
// fills owner / environment from the most specific matching rule that defines them (only
// when the scanner did not provide a value). Analyst overrides still win on read because
// they are merged on top of the observed record. Returns true when the host changed.
func ApplyTagRules(h *domain.Host, rules []domain.TagRule) bool {
	if h == nil || len(rules) == 0 {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(h.IP))
	if ip == nil {
		return false
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
	if len(hits) == 0 {
		return false
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].ones > hits[j].ones })

	changed := false
	for _, ht := range hits {
		for _, t := range ht.rule.Tags {
			if !containsFold(h.Tags, t) {
				h.Tags = append(h.Tags, t)
				changed = true
			}
		}
	}
	if strings.TrimSpace(h.Owner) == "" {
		for _, ht := range hits {
			if ht.rule.Owner != "" {
				h.Owner = ht.rule.Owner
				changed = true
				break
			}
		}
	}
	if h.Environment == "" || h.Environment == "unknown" {
		for _, ht := range hits {
			if ht.rule.Environment != "" {
				h.Environment = ht.rule.Environment
				changed = true
				break
			}
		}
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
