// Package policy implements zone policies (exposure policy as code): each network zone
// (one or more CIDRs) declares what may run there, for example "user network: no servers"
// or "server zone: web only". After every ingest and on every policy change the whole
// inventory is evaluated and every service breaking the rules of its zone becomes a
// violation with severity, evidence, owner and first/last seen. Violations resolve on their
// own when the service is gone, and both transitions are emitted as change events so they
// reach the Diff view, the alert webhook and DefectDojo.
package policy

import "github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"

// Preset is a named starting point for a zone's rules.
type Preset struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Rules       domain.PolicyRules `json:"rules"`
}

// Category describes one forbiddable category (for the UI and evidence text).
type Category struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// Categories lists every category a zone can forbid, most severe first.
var Categories = []Category{
	{domain.PolicyCatCleartext, "Cleartext admin", "Telnet, FTP and r-services send credentials unencrypted", "high"},
	{domain.PolicyCatDatabase, "Exposed database", "Database listener reachable over the network", "high"},
	{domain.PolicyCatAdminPanel, "Admin panel", "Management or login interface reachable", "high"},
	{domain.PolicyCatIoTBMC, "IoT or BMC", "Embedded devices and server BMCs (iDRAC, iLO, IPMI)", "high"},
	{domain.PolicyCatEOL, "End-of-life software", "Version branch no longer gets security fixes", "medium"},
	{domain.PolicyCatStaging, "Staging or dev", "Non-production environment exposed", "medium"},
}

// CategoryByID returns the category metadata (ok=false for unknown ids).
func CategoryByID(id string) (Category, bool) {
	for _, c := range Categories {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// Preset identifiers.
const (
	PresetUserNetwork = "user_network"
	PresetServerWeb   = "server_web_only"
	PresetManagement  = "management_vlan"
	PresetDefault     = "default"
	PresetCustom      = "custom"
)

// Presets are the built-in rule sets offered in the zone editor.
var Presets = []Preset{
	{
		ID:          PresetUserNetwork,
		Name:        "User network: no servers",
		Description: "Student and staff networks. Any listening service is out of place here.",
		Rules: domain.PolicyRules{
			NoServices: true,
			Forbidden:  []string{domain.PolicyCatCleartext, domain.PolicyCatDatabase, domain.PolicyCatAdminPanel, domain.PolicyCatIoTBMC, domain.PolicyCatStaging},
		},
	},
	{
		ID:          PresetServerWeb,
		Name:        "Server zone: web only",
		Description: "The designated place for public services: SSH and web only, no databases or devices.",
		Rules: domain.PolicyRules{
			AllowedPorts: []int{22, 80, 443},
			Forbidden:    []string{domain.PolicyCatCleartext, domain.PolicyCatDatabase, domain.PolicyCatIoTBMC, domain.PolicyCatStaging, domain.PolicyCatEOL},
		},
	},
	{
		ID:          PresetManagement,
		Name:        "Management VLAN: BMC allowed here only",
		Description: "Out-of-band management. BMCs and admin panels belong here, cleartext protocols still do not.",
		Rules: domain.PolicyRules{
			Forbidden: []string{domain.PolicyCatCleartext, domain.PolicyCatEOL},
		},
	},
	{
		ID:          PresetDefault,
		Name:        "Default: no cleartext admin, no exposed DB",
		Description: "Baseline for everything else: no telnet or FTP, no reachable databases, no BMCs outside the management VLAN.",
		Rules: domain.PolicyRules{
			Forbidden: []string{domain.PolicyCatCleartext, domain.PolicyCatDatabase, domain.PolicyCatIoTBMC},
		},
	},
}

// PresetByID returns a copy of the preset (ok=false for unknown ids).
func PresetByID(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			p.Rules.AllowedPorts = append([]int(nil), p.Rules.AllowedPorts...)
			p.Rules.Forbidden = append([]string(nil), p.Rules.Forbidden...)
			return p, true
		}
	}
	return Preset{}, false
}
