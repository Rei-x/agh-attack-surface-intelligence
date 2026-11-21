package policy

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Setting keys (encrypted settings documents, see db.SettingsStore).
const (
	SettingZones      = "policy_zones"
	SettingViolations = "policy_violations"
)

// MaxZones bounds the zone list.
const MaxZones = 200

// LoadZones returns the configured zones (found=false when never saved).
func LoadZones(ctx context.Context, store db.Store) ([]domain.PolicyZone, bool) {
	ss, ok := store.(db.SettingsStore)
	if !ok {
		return nil, false
	}
	var zones []domain.PolicyZone
	found, err := ss.GetSetting(ctx, SettingZones, &zones)
	if err != nil || !found {
		return nil, false
	}
	return zones, true
}

// SaveZones normalises and stores the full zone list, keeping ids and creation metadata of
// zones that already existed.
func SaveZones(ctx context.Context, store db.Store, zones []domain.PolicyZone, user string) ([]domain.PolicyZone, error) {
	ss, ok := store.(db.SettingsStore)
	if !ok {
		return nil, fmt.Errorf("store backend does not support settings")
	}
	if len(zones) > MaxZones {
		return nil, fmt.Errorf("too many zones (max %d)", MaxZones)
	}
	prev := map[string]domain.PolicyZone{}
	if old, found := LoadZones(ctx, store); found {
		for _, z := range old {
			prev[z.ID] = z
		}
	}
	now := time.Now().UTC()
	for i := range zones {
		z := &zones[i]
		if err := NormalizeZone(z); err != nil {
			return nil, err
		}
		if old, ok := prev[z.ID]; ok && z.ID != "" {
			z.CreatedBy, z.CreatedAt = old.CreatedBy, old.CreatedAt
		} else {
			z.ID = db.NewID()
			z.CreatedBy, z.CreatedAt = user, now
		}
		z.UpdatedAt = now
	}
	if zones == nil {
		zones = []domain.PolicyZone{}
	}
	if err := ss.SaveSetting(ctx, SettingZones, zones); err != nil {
		return nil, err
	}
	return zones, nil
}

// NormalizeZone validates and canonicalises a zone in place.
func NormalizeZone(z *domain.PolicyZone) error {
	z.Name = strings.TrimSpace(z.Name)
	if z.Name == "" {
		return fmt.Errorf("zone name is required")
	}
	if len(z.Name) > 120 {
		return fmt.Errorf("zone name too long")
	}
	z.Description = strings.TrimSpace(z.Description)
	z.Owner = strings.TrimSpace(z.Owner)
	z.Preset = strings.TrimSpace(z.Preset)
	cidrs := make([]string, 0, len(z.CIDRs))
	seen := map[string]bool{}
	for _, c := range z.CIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		n, err := parseCIDR(c)
		if err != nil {
			return fmt.Errorf("zone %q: %w", z.Name, err)
		}
		if !seen[n] {
			seen[n] = true
			cidrs = append(cidrs, n)
		}
	}
	if len(cidrs) == 0 {
		return fmt.Errorf("zone %q needs at least one CIDR", z.Name)
	}
	z.CIDRs = cidrs

	ports := make([]int, 0, len(z.Rules.AllowedPorts))
	for _, p := range z.Rules.AllowedPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("zone %q: invalid port %d", z.Name, p)
		}
		if !containsInt(ports, p) {
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	z.Rules.AllowedPorts = ports

	cats := make([]string, 0, len(z.Rules.Forbidden))
	for _, c := range z.Rules.Forbidden {
		c = strings.ToLower(strings.TrimSpace(c))
		if _, ok := CategoryByID(c); !ok {
			return fmt.Errorf("zone %q: unknown category %q", z.Name, c)
		}
		if !containsStr(cats, c) {
			cats = append(cats, c)
		}
	}
	z.Rules.Forbidden = cats
	if z.Rules.MaxRisk < 0 || z.Rules.MaxRisk > 100 {
		return fmt.Errorf("zone %q: max risk must be 0..100", z.Name)
	}
	return nil
}

func parseCIDR(c string) (string, error) {
	if !strings.Contains(c, "/") {
		ip := net.ParseIP(c)
		if ip == nil {
			return "", fmt.Errorf("invalid CIDR %q", c)
		}
		if ip.To4() != nil {
			c += "/32"
		} else {
			c += "/128"
		}
	}
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR %q", c)
	}
	return n.String(), nil
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// DemoZones is the zone set matching the CBI AGH lab network 10.66.0.0/18 used for the
// jury demo. Seeded only on the demo path (DZIECIOL_SEED_DEMO) and only when no zones were
// ever saved.
func DemoZones() []domain.PolicyZone {
	mk := func(name, desc, preset string, cidrs []string) domain.PolicyZone {
		p, _ := PresetByID(preset)
		return domain.PolicyZone{Name: name, Description: desc, Preset: preset, CIDRs: cidrs, Enabled: true, Rules: p.Rules}
	}
	return []domain.PolicyZone{
		mk("Lab baseline", "Everything in the lab network that has no more specific zone.", PresetDefault, []string{"10.66.0.0/18"}),
		mk("Server zone", "The designated place for services. Web and SSH only.", PresetServerWeb, []string{"10.66.0.0/24"}),
		mk("Management VLAN", "Out-of-band management. The only place for BMCs.", PresetManagement, []string{"10.66.4.0/24"}),
		mk("Student network", "Student labs and staff desktops. No servers.", PresetUserNetwork, []string{"10.66.16.0/20", "10.66.3.128/25"}),
	}
}

// SeedDemo stores DemoZones when zones were never configured. Returns true when seeded.
func SeedDemo(ctx context.Context, store db.Store) (bool, error) {
	if _, ok := store.(db.SettingsStore); !ok {
		return false, nil
	}
	if _, found := LoadZones(ctx, store); found {
		return false, nil
	}
	if _, err := SaveZones(ctx, store, DemoZones(), "demo-seed"); err != nil {
		return false, err
	}
	return true, nil
}
