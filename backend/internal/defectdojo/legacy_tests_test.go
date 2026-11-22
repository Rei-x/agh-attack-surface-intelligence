package defectdojo

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// legacyLayout is what an older version leaves in DefectDojo: one change test per profile
// (and per profile name, after a rename), a plain "Dzięcioł changes" for hosts outside the
// profiles, integration leftovers in an older engagement of the same name, plus tests the
// migration must not touch.
type legacyLayout struct {
	product                            *simProduct
	t18old, t18, t22, rest, integ      *simTest
	nmap, obs, peer, otherProduct      *simTest
	eolUID, jenkinsUID                 string
	eolNoteOn, jenkinsFP               *simFinding
	canonEOLBefore, canonJenkinsBefore int
}

func seedLegacyLayout(t *testing.T, sim *dojoSim, hosts []domain.Host, profiles []domain.ScanProfile) *legacyLayout {
	t.Helper()
	now := time.Now().UTC()
	all := InventoryChangeFindings(context.Background(), hosts, profiles, now)
	pick := func(keep func(ChangeFinding) bool) []ChangeFinding {
		var out []ChangeFinding
		for _, f := range all {
			if keep(f) {
				out = append(out, f)
			}
		}
		return out
	}
	in22 := func(f ChangeFinding) bool {
		return strings.HasPrefix(f.ComponentName, "10.66.0.") || strings.Contains(f.Title, "10.66.0.")
	}
	in18 := func(f ChangeFinding) bool { return in22(f) || strings.Contains(f.Title, "10.66.9.20") }
	outside := func(f ChangeFinding) bool { return strings.Contains(f.Title, "192.168.7.7") }

	l := &legacyLayout{}
	l.product = sim.addProduct(DefaultProduct)
	oldEng := sim.addEngagement(l.product, DefaultEngagement)
	eng := sim.addEngagement(l.product, DefaultEngagement) // DefectDojo resolves the name to the last one
	otherEng := sim.addEngagement(sim.addProduct("Another product"), DefaultEngagement)

	// /18 under its old name: stale since the rename, misses the host found later.
	l.t18old = sim.addTest(eng, "Dzięcioł changes: Lab AGH — cała sieć /18", genericScanType)
	sim.seed(l.t18old, pick(in22))
	sim.seed(l.t18old, []ChangeFinding{{genericFinding: genericFinding{Title: "Gone long ago", Description: "x", UniqueIDFromTool: "aegis-stale"}}})
	// /18 under its current name: holds the most of today's findings.
	l.t18 = sim.addTest(eng, "Dzięcioł changes: Lab AGH · cała sieć /18", genericScanType)
	for _, sf := range sim.seed(l.t18, pick(in18)) {
		switch {
		case strings.HasPrefix(sf.Title, "nginx"):
			l.eolUID, l.canonEOLBefore = sf.UID, sf.ID
		case strings.Contains(sf.Title, "Jenkins"):
			l.jenkinsUID, l.canonJenkinsBefore = sf.UID, sf.ID
		}
	}
	// /22: an analyst note on one finding, a false positive set in DefectDojo on another.
	l.t22 = sim.addTest(eng, "Dzięcioł changes: Lab AGH · szybki test /22", genericScanType)
	for _, sf := range sim.seed(l.t22, pick(in22)) {
		switch sf.UID {
		case l.eolUID:
			sim.addNote(sf, "Mitigated by Generic Findings Import re-upload.")
			sim.addNote(sf, "INC-42: owner upgrades nginx in December")
			l.eolNoteOn = sf
		case l.jenkinsUID:
			sf.FalseP, sf.Active = true, false
			sim.addNote(sf, "VPN only, the scanner reaches it through the jump host")
			l.jenkinsFP = sf
		}
	}
	l.rest = sim.addTest(eng, ChangesTest, genericScanType)
	sim.seed(l.rest, pick(outside))
	l.integ = sim.addTest(oldEng, "Dzięcioł changes: integration-20261121-185056", genericScanType)
	sim.seed(l.integ, pick(in22)[:2])

	// Not ours to close.
	l.nmap = sim.addTest(eng, "Dzięcioł Nmap: Lab AGH · cała sieć /18", "Nmap Scan")
	sim.seed(l.nmap, []ChangeFinding{{genericFinding: genericFinding{Title: "Open port: 22/TCP", Description: "nmap"}}})
	l.obs = sim.addTest(eng, ObservationsTest, genericScanType)
	sim.seed(l.obs, []ChangeFinding{{genericFinding: genericFinding{Title: "Exposed admin panel", Description: "manual", UniqueIDFromTool: "aegis-obs"}}})
	l.peer = sim.addTest(oldEng, ChangesTest, genericScanType) // another engagement's change test
	sim.seed(l.peer, []ChangeFinding{{genericFinding: genericFinding{Title: "Peer", Description: "peer", UniqueIDFromTool: "aegis-peer"}}})
	l.otherProduct = sim.addTest(otherEng, "Dzięcioł changes: other", genericScanType)
	sim.seed(l.otherProduct, pick(in22)[:1])
	if l.eolNoteOn == nil || l.jenkinsFP == nil {
		t.Fatalf("fixture lacks the EOL or Jenkins finding:\n%s", sim.summary())
	}
	return l
}

func activeIn(sim *dojoSim, tt *simTest) int {
	n := 0
	for _, f := range sim.findingsOf(tt.ID) {
		if f.Active {
			n++
		}
	}
	return n
}

func findingByUID(sim *dojoSim, tt *simTest, uid string) *simFinding {
	for _, f := range sim.findingsOf(tt.ID) {
		if f.UID == uid && !f.IsMitigated {
			return f
		}
	}
	return nil
}

func notesWith(f *simFinding, s string) int {
	n := 0
	for _, note := range f.Notes {
		if e, _ := note["entry"].(string); strings.Contains(e, s) {
			n++
		}
	}
	return n
}

// First sync after the upgrade: the /18 test becomes the change test (renamed, findings
// kept), every other change test of the product is closed, notes and DefectDojo-side triage
// move over, and nothing is active twice. A second sync changes nothing.
func TestSyncChangesRetiresPerProfileTests(t *testing.T) {
	sim, srv := newDojoSim(t)
	sim.pageCap = 3 // page through everything
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}
	hosts, profiles := inventoryHosts(), overlappingProfiles()
	store := newFixtureStore(t, hosts, profiles)
	ctx := context.Background()
	l := seedLegacyLayout(t, sim, hosts, profiles)
	// State of the old version: last push went to the /22 test, no context recorded.
	_ = db.SaveDefectDojoSync(ctx, store, domain.DefectDojoSyncState{TestID: l.t22.ID, FindingsByKey: map[string][]domain.DefectDojoFindingRef{
		"service:x": {{ServiceID: "x", TestID: l.t22.ID, FindingID: 1}}}})

	res := syncOnce(t, store, cfg, "upgrade")
	if res.Import.TestID != l.t18.ID || l.t18.Title != ChangesTest || l.rest.Title != outsideProfilesTitle {
		t.Fatalf("want the /18 test adopted and renamed, the old plain test renamed away; got test %d:\n%s", res.Import.TestID, sim.summary())
	}
	if first := sim.reimports[0]; first["test"] != strconv.Itoa(l.t18.ID) {
		t.Fatalf("first reimport must target the adopted test by id: %+v", first)
	}
	if !strings.Contains(l.t18.Description, "whole inventory") {
		t.Errorf("change test description: %q", l.t18.Description)
	}
	// Findings already in the adopted test keep their DefectDojo identity.
	if f := findingByUID(sim, l.t18, l.eolUID); f == nil || f.ID != l.canonEOLBefore || !f.Active {
		t.Fatalf("adopted EOL finding lost its id: %+v", f)
	}

	for _, old := range []*simTest{l.t18old, l.t22, l.rest, l.integ} {
		if n := activeIn(sim, old); n != 0 {
			t.Errorf("superseded test #%d %q still has %d active findings", old.ID, old.Title, n)
		}
		for _, f := range sim.findingsOf(old.ID) {
			if !f.IsMitigated {
				t.Errorf("finding #%d of superseded test #%d not closed", f.ID, old.ID)
			}
		}
		if !strings.Contains(old.Version, "superseded by test #"+strconv.Itoa(l.t18.ID)) || !strings.Contains(old.Description, "Superseded on") {
			t.Errorf("superseded test #%d not labelled: version %q description %q", old.ID, old.Version, old.Description)
		}
	}
	for _, keep := range []*simTest{l.nmap, l.obs, l.peer, l.otherProduct} {
		if activeIn(sim, keep) == 0 {
			t.Errorf("test #%d %q must not be touched", keep.ID, keep.Title)
		}
	}
	for uid, ids := range sim.activeByUID(l.product.ID) {
		if uid != "" && len(ids) > 1 {
			t.Errorf("unique id %s active in %d findings %v", uid, len(ids), ids)
		}
	}

	// Carried over: the analyst note (not DefectDojo's own) and the DefectDojo-side FP.
	eol := findingByUID(sim, l.t18, l.eolUID)
	if notesWith(eol, "INC-42") != 1 || notesWith(eol, "Carried over from DefectDojo finding #"+strconv.Itoa(l.eolNoteOn.ID)) != 1 || notesWith(eol, "Mitigated by") != 0 {
		t.Errorf("EOL notes not carried once: %+v", eol.Notes)
	}
	jenkins := findingByUID(sim, l.t18, l.jenkinsUID)
	if jenkins == nil || !jenkins.FalseP || jenkins.Active || notesWith(jenkins, "VPN only") != 1 {
		t.Errorf("DefectDojo-side false positive not carried: %+v", jenkins)
	}
	// Decisions made in Dzięcioł are applied by the triage sync as always.
	for _, f := range sim.findingsOf(l.t18.ID) {
		switch {
		case strings.Contains(f.Title, "10.66.0.90") && !f.RiskAccepted:
			t.Errorf("accepted risk from Dzięcioł not applied: %+v", f)
		case strings.Contains(f.Title, "10.66.0.91") && !f.FalseP:
			t.Errorf("false positive from Dzięcioł not applied: %+v", f)
		}
	}

	st := db.LoadDefectDojoSync(ctx, store)
	if st.TestID != l.t18.ID || st.ChangesContext == "" || len(st.LegacyTests) != 4 || len(res.Retired) != 4 {
		t.Fatalf("state after migration: test %d context %q legacy %+v", st.TestID, st.ChangesContext, st.LegacyTests)
	}
	carriedNotes, carriedTriage := 0, 0
	for _, lt := range st.LegacyTests {
		carriedNotes += lt.NotesCarried
		carriedTriage += lt.TriageCarried
		if lt.URL != srv.URL+"/test/"+strconv.Itoa(lt.TestID) {
			t.Errorf("legacy test link %q", lt.URL)
		}
	}
	if carriedNotes != 2 || carriedTriage != 1 {
		t.Errorf("carried notes=%d triage=%d, want 2 and 1", carriedNotes, carriedTriage)
	}
	if _, stale := st.FindingsByKey["service:x"]; stale {
		t.Error("links into the superseded tests survived")
	}
	for key, refs := range st.FindingsByKey {
		for _, r := range refs {
			if r.TestID != l.t18.ID {
				t.Errorf("%s links test %d", key, r.TestID)
			}
		}
	}

	// Second sync: by id, nothing reimported into the old tests, nothing carried twice, and
	// the DefectDojo-side false positive is not reverted.
	n := len(sim.reimports)
	res2 := syncOnce(t, store, cfg, "next")
	for _, f := range sim.reimports[n:] {
		if f["test"] != strconv.Itoa(l.t18.ID) {
			t.Errorf("second sync reimported elsewhere: %+v", f)
		}
	}
	if len(res2.Retired) != 0 || len(db.LoadDefectDojoSync(ctx, store).LegacyTests) != 4 {
		t.Errorf("second sync retired again: %+v", res2.Retired)
	}
	if notesWith(findingByUID(sim, l.t18, l.eolUID), "INC-42") != 1 {
		t.Error("note carried twice")
	}
	if j := findingByUID(sim, l.t18, l.jenkinsUID); !j.FalseP {
		t.Error("triage sync reverted a false positive set in DefectDojo")
	}
}

// A per-profile test written again by an older binary after the upgrade (or an integration
// run) is closed by the next sync too: retirement does not depend on the one-off adoption.
func TestSyncChangesRetiresLateLegacyTest(t *testing.T) {
	sim, srv := newDojoSim(t)
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}
	hosts, profiles := inventoryHosts(), overlappingProfiles()
	store := newFixtureStore(t, hosts, profiles)
	syncOnce(t, store, cfg, "1")
	ct := sim.testByTitle(ChangesTest)[0]
	var eng *simEngagement
	for _, e := range sim.engagements {
		if e.ID == ct.Engagement {
			eng = e
		}
	}
	late := sim.addTest(eng, "Dzięcioł changes: Lab AGH · szybki test /22", genericScanType)
	sim.seed(late, BuildChangeFindings(fixtureHosts(), time.Now().UTC()))

	res := syncOnce(t, store, cfg, "2")
	if activeIn(sim, late) != 0 || len(res.Retired) != 1 || res.Retired[0].TestID != late.ID {
		t.Fatalf("late per-profile test not retired: %+v\n%s", res.Retired, sim.summary())
	}
	for uid, ids := range sim.activeByUID(sim.productOf(ct)) {
		if len(ids) > 1 {
			t.Errorf("unique id %s active %d times", uid, len(ids))
		}
	}
}
