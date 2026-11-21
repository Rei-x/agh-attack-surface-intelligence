package defectdojo

import (
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestBuildPolicyFindingsStableAndScoped(t *testing.T) {
	now := time.Now().UTC()
	vs := []domain.PolicyViolation{
		{ID: "a", ZoneID: "z1", ZoneName: "Student network", Rule: "forbidden:database", Rules: []string{"forbidden:database", "no_services"},
			Severity: "high", HostID: "h1", HostIP: "10.66.17.9", Port: 3306, Protocol: "tcp", ServiceName: "mysql",
			Owner: "lab@agh.edu.pl", Status: domain.PolicyStatusOpen, FirstSeen: now.Add(-48 * time.Hour), Evidence: []string{"changes every run"}},
		{ID: "b", ZoneID: "z1", ZoneName: "Student network", Rule: "no_services", Severity: "medium", HostID: "h2", HostIP: "10.66.17.10", Port: 22, Status: domain.PolicyStatusOpen},
		{ID: "c", ZoneID: "z1", ZoneName: "Student network", Rule: "no_services", Severity: "medium", HostID: "h1", HostIP: "10.66.17.9", Port: 80, Status: domain.PolicyStatusResolved},
	}
	got := BuildPolicyFindings(vs, map[string]bool{"h1": true}, now)
	if len(got) != 1 {
		t.Fatalf("only the open violation in scope: %+v", got)
	}
	f := got[0]
	if f.Severity != "High" || f.Kind != KindPolicy || !strings.Contains(f.Title, "exposed database not allowed") ||
		!strings.Contains(f.Title, "[owner: lab@agh.edu.pl]") || strings.Contains(f.Description, "changes every run") {
		t.Fatalf("finding: %+v", f)
	}
	again := BuildPolicyFindings(vs, map[string]bool{"h1": true}, now.Add(time.Hour))
	if again[0].Title != f.Title || again[0].Description != f.Description || again[0].UniqueIDFromTool != f.UniqueIDFromTool {
		t.Fatal("finding must be stable between runs (DefectDojo hash_code)")
	}
}
