package vulndb

import "github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"

// Every eol.Annotate / eol.ApplyScore call (ingest, API reads, DefectDojo findings,
// policies) also fills Service.Vulns and adds the KEV / EPSS / CVSS score factors.
func init() {
	eol.RegisterAnnotator(Annotate, FactorPrefixes...)
}
