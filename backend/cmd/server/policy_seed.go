package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/policy"
)

// seedDemoPolicies stores the lab zone set (10.66.0.0/18, see policy.DemoZones) on the demo
// path only, and only when zones were never configured, so an operator's own zones (or an
// emptied list) are never touched. DZIECIOL_SEED_DEMO_POLICIES=false skips it while keeping
// the demo accounts.
func seedDemoPolicies(ctx context.Context, store db.Store) {
	if strings.EqualFold(envOrDefault("DZIECIOL_SEED_DEMO_POLICIES", "true"), "false") {
		return
	}
	seeded, err := policy.SeedDemo(ctx, store)
	if err != nil {
		log.Printf("[WARN] demo zone policies: %v", err)
		return
	}
	if seeded {
		log.Printf("[INFO] seeded demo zone policies for the lab network 10.66.0.0/18")
	}
}

// policyChangeFindings returns the open zone policy violations of hosts (the profile scope)
// as findings for the "Dzięcioł changes" test.
func policyChangeFindings(ctx context.Context, store db.Store, hosts []domain.Host) []defectdojo.ChangeFinding {
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
	return defectdojo.BuildPolicyFindings(st.Violations, in, time.Now().UTC())
}
