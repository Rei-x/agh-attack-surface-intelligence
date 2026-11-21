package defectdojo

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Names follow the secureCodeBox DefectDojo hook levels and can be overridden like its annotations.
func TestDefectDojoNamingOverridesLikeSCBAnnotations(t *testing.T) {
	t.Setenv("ASI_DEFECTDOJO_PRODUCT_TYPE_NAME", "CBI AGH")
	t.Setenv("ASI_DEFECTDOJO_PRODUCT_NAME", "Sieć kampusowa")
	t.Setenv("ASI_DEFECTDOJO_ENGAGEMENT_NAME", "Discovery 2026")
	t.Setenv("ASI_DEFECTDOJO_DEDUPLICATE_ON_ENGAGEMENT", "true")
	t.Setenv("ASI_DEFECTDOJO_MINIMUM_SEVERITY", "low")

	fd := newFakeDojo(t)
	srv := httptest.NewServer(fd)
	defer srv.Close()
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "secret-dojo-token"}
	xml := `<?xml version="1.0"?><nmaprun scanner="nmap"><host><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>`
	if _, err := NewClient().ImportNmapXML(context.Background(), cfg, 0, NmapTestTitle("Noc"), "Run #1", xml); err != nil {
		t.Fatal(err)
	}
	f := fd.forms[0]
	if f["product_type_name"] != "CBI AGH" || f["product_name"] != "Sieć kampusowa" || f["engagement_name"] != "Discovery 2026" {
		t.Fatalf("names not overridden: %+v", f)
	}
	if f["deduplication_on_engagement"] != "true" || f["minimum_severity"] != "Low" || f["test_title"] != "Dzięcioł Nmap: Noc" {
		t.Fatalf("SCB-equivalent knobs missing: %+v", f)
	}
}

func TestDefectDojoNamingDefaults(t *testing.T) {
	ic := defaultContext()
	if ic.ProductType != DefaultProductType || ic.Product != DefaultProduct || ic.Engagement != DefaultEngagement {
		t.Fatalf("defaults changed: %+v", ic)
	}
	if len(extraReimportFields()) != 0 || minimumSeverity() != "Info" {
		t.Fatal("optional fields must be off by default")
	}
}
