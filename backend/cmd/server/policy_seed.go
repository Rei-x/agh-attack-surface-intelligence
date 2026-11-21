package main

import (
	"context"
	"log"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
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
