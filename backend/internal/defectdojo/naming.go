package defectdojo

import (
	"os"
	"strconv"
	"strings"
)

// DefectDojo naming, aligned with the OWASP secureCodeBox persistence-defectdojo hook.
// SCB sets these per scan with annotations; Dzięcioł uses the same four levels and lets the
// operator override the defaults with environment variables of the same names:
//
//	SCB annotation (defectdojo.securecodebox.io/...)  Dzięcioł
//	product-type-name                                 DZIECIOL_DEFECTDOJO_PRODUCT_TYPE_NAME   (default "Dzięcioł")
//	product-name                                      DZIECIOL_DEFECTDOJO_PRODUCT_NAME        (default "AGH Attack Surface")
//	engagement-name                                   DZIECIOL_DEFECTDOJO_ENGAGEMENT_NAME     (default "Dzięcioł continuous discovery")
//	engagement-deduplicate-on-engagement              DZIECIOL_DEFECTDOJO_DEDUPLICATE_ON_ENGAGEMENT (default false)
//	test-title                                        per scan profile: "Dzięcioł Nmap: <profile>" (SCB: scan name)
//	minimum_severity                                  DZIECIOL_DEFECTDOJO_MINIMUM_SEVERITY    (default "Info")
//
// A product/engagement pinned by ID in the DefectDojo settings still wins over these names.

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// defaultContext returns the product type / product / engagement names used when nothing
// is pinned by ID.
func defaultContext() importContext {
	return importContext{
		ProductType: envOr("DZIECIOL_DEFECTDOJO_PRODUCT_TYPE_NAME", DefaultProductType),
		Product:     envOr("DZIECIOL_DEFECTDOJO_PRODUCT_NAME", DefaultProduct),
		Engagement:  envOr("DZIECIOL_DEFECTDOJO_ENGAGEMENT_NAME", DefaultEngagement),
	}
}

// extraReimportFields are the optional SCB-equivalent knobs for /api/v2/reimport-scan/.
// deduplication_on_engagement only applies when DefectDojo creates the engagement.
func extraReimportFields() [][2]string {
	var out [][2]string
	if v, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("DZIECIOL_DEFECTDOJO_DEDUPLICATE_ON_ENGAGEMENT"))); err == nil && v {
		out = append(out, [2]string{"deduplication_on_engagement", "true"})
	}
	return out
}

// minimumSeverity maps DZIECIOL_DEFECTDOJO_MINIMUM_SEVERITY onto DefectDojo's scale.
func minimumSeverity() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DZIECIOL_DEFECTDOJO_MINIMUM_SEVERITY"))) {
	case "low":
		return "Low"
	case "medium":
		return "Medium"
	case "high":
		return "High"
	case "critical":
		return "Critical"
	default:
		return "Info"
	}
}
