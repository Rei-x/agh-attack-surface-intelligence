package defectdojo

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/policy"
)

// KindPolicy tags zone policy violations in the "Dzięcioł changes" test.
const KindPolicy = "policy-violation"

// BuildPolicyFindings turns the open zone policy violations into change findings, so they
// are reimported (and mitigated when resolved) together with the other change findings.
// Like the rest of the change test, titles and descriptions hold only stable facts (zone,
// rules, endpoint, owner) and no evidence text or timestamps, which keeps the DefectDojo
// hash_code stable between runs. inScope (optional) limits the findings to these host ids.
func BuildPolicyFindings(violations []domain.PolicyViolation, inScope map[string]bool, now time.Time) []ChangeFinding {
	var out []ChangeFinding
	for _, v := range violations {
		if v.Status != domain.PolicyStatusOpen {
			continue
		}
		if inScope != nil && !inScope[v.HostID] {
			continue
		}
		proto := v.Protocol
		if proto == "" {
			proto = "tcp"
		}
		where := fmt.Sprintf("%s:%d/%s", v.HostIP, v.Port, proto)
		title := fmt.Sprintf("Zone policy violation: %s on %s (zone %s)", policy.RuleLabel(v.Rule), where, v.ZoneName)
		if v.Owner != "" {
			title += " [owner: " + v.Owner + "]"
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Service `%s` (%s) breaks the policy of zone **%s**.\n\n", where, nonEmptyStr(v.ServiceName, "unknown"), v.ZoneName)
		b.WriteString("Broken rules:\n")
		for _, r := range v.Rules {
			fmt.Fprintf(&b, "- %s\n", policy.RuleLabel(r))
		}
		if v.Owner != "" {
			fmt.Fprintf(&b, "\nOwner: %s\n", v.Owner)
		}
		tags := []string{"dzieciol", KindPolicy, "zone:" + slug(v.ZoneName)}
		if v.Owner != "" {
			tags = append(tags, "owner:"+slug(v.Owner))
		}
		f := ChangeFinding{Kind: KindPolicy, Owner: v.Owner, genericFinding: genericFinding{
			Title:            title,
			Description:      b.String(),
			Severity:         dojoSeverity(v.Severity),
			Active:           true,
			Tags:             tags,
			UniqueIDFromTool: UniqueID(v.HostIP, v.Port, proto, "dz-policy:"+v.ZoneID),
			VulnIDFromTool:   KindPolicy,
			Date:             firstSeenDate(v.FirstSeen, now),
			Mitigation:       "Move the service to the zone meant for it, close the port, or change the zone policy if this is intended.",
			Endpoints:        []genericEndpoint{{Host: v.HostIP, Port: v.Port}},
			ComponentName:    v.HostIP,
			ComponentVersion: fmt.Sprintf("%d/%s", v.Port, proto),
		}}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UniqueIDFromTool < out[j].UniqueIDFromTool })
	return out
}

func dojoSeverity(s string) string {
	switch s {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	}
	return "Info"
}

func firstSeenDate(t, now time.Time) string {
	if t.IsZero() {
		t = now
	}
	return t.UTC().Format("2006-01-02")
}

func nonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '@', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '/' || r == ':':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// PolicyFindingsFor loads the violation ledger and returns the open violations of hosts
// (the synced scope) as change findings.
func PolicyFindingsFor(ctx context.Context, store db.Store, hosts []domain.Host) []ChangeFinding {
	ss, ok := store.(db.SettingsStore)
	if !ok {
		return nil
	}
	var st policy.State
	if found, err := ss.GetSetting(ctx, policy.SettingViolations, &st); err != nil || !found {
		return nil
	}
	in := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		in[h.ID] = true
	}
	return BuildPolicyFindings(st.Violations, in, time.Now().UTC())
}
