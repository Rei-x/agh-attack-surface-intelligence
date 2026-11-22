package defectdojo

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// The demo layout: a quick /22 inside the nightly /18.
func overlappingProfiles() []domain.ScanProfile {
	return []domain.ScanProfile{
		{ID: "p18", Name: "Lab AGH · cała sieć /18", Targets: []string{"10.66.0.0/18"}},
		{ID: "p22", Name: "Lab AGH · szybki test /22", Targets: []string{"10.66.0.0/22"}},
	}
}

// inventoryHosts: the fixture hosts (all inside the /22), a host only the /18 covers and an
// imported host no profile covers.
func inventoryHosts() []domain.Host {
	base := changesNow.Add(-10 * 24 * time.Hour)
	hosts := fixtureHosts()
	for i := range hosts {
		hosts[i].ID = "h-" + hosts[i].IP
		for j := range hosts[i].Services {
			hosts[i].Services[j].ID = hosts[i].ID + ":" + strconv.Itoa(hosts[i].Services[j].Port)
		}
	}
	return append(hosts,
		domain.Host{ID: "h-10.66.9.20", IP: "10.66.9.20", Owner: "ki@agh.edu.pl", LifecycleState: domain.HostStateActive, FirstSeen: base, LastSeen: changesNow,
			Services: []domain.Service{{ID: "s-9.20-8080", Port: 8080, Protocol: "tcp", State: "open", ServiceName: "http", IsAdminPanel: true, FirstSeen: base,
				Technologies: []domain.DetectedTechnology{{Name: "Grafana", Category: "admin_panel"}}}}},
		domain.Host{ID: "h-192.168.7.7", IP: "192.168.7.7", LifecycleState: domain.HostStateActive, FirstSeen: base, LastSeen: changesNow,
			Services: []domain.Service{{ID: "s-7.7-23", Port: 23, Protocol: "tcp", State: "open", ServiceName: "telnet", FirstSeen: base}}},
	)
}

func uidsOf(fs []ChangeFinding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.UniqueIDFromTool]++
	}
	return out
}

// Overlapping profiles: every condition once, the same findings as the inventory treated as
// one scope (all fixture hosts are inside both profiles, so the baseline is the same).
func TestInventoryChangeFindingsOverlappingProfiles(t *testing.T) {
	ctx := context.Background()
	fs := InventoryChangeFindings(ctx, fixtureHosts(), overlappingProfiles(), changesNow)
	for uid, n := range uidsOf(fs) {
		if n != 1 {
			t.Fatalf("unique id %s appears %d times", uid, n)
		}
	}
	a, _ := json.Marshal(fs)
	b, _ := json.Marshal(BuildChangeFindings(fixtureHosts(), changesNow))
	if string(a) != string(b) {
		t.Fatalf("inventory payload differs from the single-scope payload:\n%s\n%s", a, b)
	}
	// Renaming a profile changes nothing in the payload.
	renamed := overlappingProfiles()
	renamed[1].Name = "Lab AGH: quick /22"
	c, _ := json.Marshal(InventoryChangeFindings(ctx, fixtureHosts(), renamed, changesNow))
	if string(a) != string(c) {
		t.Fatal("profile rename changed the change findings")
	}
	// Two records of one IP (and so identical findings) are sent once.
	dup := append(fixtureHosts(), fixtureHosts()[0])
	if got := InventoryChangeFindings(ctx, dup, overlappingProfiles(), changesNow); len(got) != len(fs) {
		t.Fatalf("duplicate host record: %d findings, want %d", len(got), len(fs))
	}
}

// "New service" keeps a per-profile baseline in the inventory-wide test: the first scan of a
// freshly added profile is its baseline, a host appearing later inside a watched profile is
// news, and hosts no profile covers share their own baseline.
func TestInventoryChangeFindingsNewServiceBaselines(t *testing.T) {
	day0 := changesNow.Add(-10 * 24 * time.Hour)
	fresh := changesNow.Add(-24 * time.Hour)
	svc := func(id string, port int, seen time.Time) domain.Service {
		return domain.Service{ID: id, Port: port, Protocol: "tcp", State: "open", ServiceName: "http", FirstSeen: seen}
	}
	host := func(ip string, seen time.Time, s domain.Service) domain.Host {
		return domain.Host{ID: "h-" + ip, IP: ip, LifecycleState: domain.HostStateActive, FirstSeen: seen, LastSeen: changesNow, Services: []domain.Service{s}}
	}
	hosts := []domain.Host{
		host("10.66.0.10", day0, svc("old", 8081, day0)),                                          // baseline of the /22 and the /18
		host("10.66.9.20", day0.Add(5*24*time.Hour), svc("in18", 9000, day0.Add(5*24*time.Hour))), // appeared later inside the /18
		host("10.77.0.5", fresh, svc("p3first", 9000, fresh)),                                     // first scan of a new profile
		host("10.77.0.6", fresh.Add(3*time.Hour), svc("p3later", 9000, fresh.Add(3*time.Hour))),   // after that first scan
		host("192.168.5.5", changesNow.Add(-48*time.Hour), svc("import", 9000, changesNow.Add(-48*time.Hour))),
	}
	profiles := append(overlappingProfiles(), domain.ScanProfile{ID: "p3", Name: "Nowa sieć", Targets: []string{"10.77.0.0/24"}})
	newOn := map[string]bool{}
	for _, f := range InventoryChangeFindings(context.Background(), hosts, profiles, changesNow) {
		if f.Kind == KindNew {
			newOn[f.ServiceID] = true
		}
	}
	if len(newOn) != 2 || !newOn["in18"] || !newOn["p3later"] {
		t.Fatalf("new services %v, want in18 and p3later only", newOn)
	}
	// One baseline for everything would flag the first scan of the new profile and the
	// import as new: what the per-profile baselines avoid.
	flat := map[string]bool{}
	for _, f := range BuildChangeFindings(hosts, changesNow) {
		if f.Kind == KindNew {
			flat[f.ServiceID] = true
		}
	}
	if !flat["p3first"] || !flat["import"] {
		t.Fatalf("expected the flat baseline to over-report, got %v", flat)
	}
}

func syncOnce(t *testing.T, store *fixtureStore, cfg *domain.DefectDojoConfig, label string) *ChangeSyncResult {
	t.Helper()
	res, err := SyncChanges(context.Background(), store, NewClient(), cfg, label, "run-"+label, "auto-push")
	if err != nil {
		t.Fatalf("sync %s: %v", label, err)
	}
	return res
}

// Two overlapping profiles, then a rename: one change test, every finding once and active
// once, the test addressed by id from the second sync on, and a fixed item mitigated.
func TestSyncChangesOneTestForOverlappingProfiles(t *testing.T) {
	sim, srv := newDojoSim(t)
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}
	store := newFixtureStore(t, inventoryHosts(), overlappingProfiles())

	res := syncOnce(t, store, cfg, "1")
	tests := sim.testByTitle(ChangesTest)
	if len(tests) != 1 || len(sim.tests) != 1 {
		t.Fatalf("want exactly one change test:\n%s", sim.summary())
	}
	ct := tests[0]
	product := sim.productOf(ct)
	if n := len(sim.findingsOf(ct.ID)); n != res.Findings || n == 0 {
		t.Fatalf("change test holds %d findings, payload %d", n, res.Findings)
	}
	for uid, ids := range sim.activeByUID(product) {
		if len(ids) != 1 {
			t.Fatalf("unique id %s active %d times", uid, len(ids))
		}
	}
	st := db.LoadDefectDojoSync(context.Background(), store)
	if st.TestID != ct.ID || !strings.HasSuffix(st.TestURL, "/test/"+strconv.Itoa(ct.ID)) || st.ChangesContext == "" || st.Findings != res.Findings {
		t.Fatalf("sync state: %+v", st)
	}
	for key, refs := range st.FindingsByKey {
		for _, r := range refs {
			if r.TestID != ct.ID || r.FindingID == 0 {
				t.Fatalf("%s links %+v, want a finding of test %d", key, r, ct.ID)
			}
		}
	}
	if refs := st.FindingsByKey["service:s-7.7-23"]; len(refs) != 1 {
		t.Fatalf("host outside every profile must be in the change test once: %+v", refs)
	}

	// Rename the /22: same test, by id, nothing created or closed.
	before := len(sim.findings)
	store.profiles[1].Name = "Lab AGH: quick /22"
	syncOnce(t, store, cfg, "2")
	last := sim.reimports[len(sim.reimports)-1]
	if last["test"] != strconv.Itoa(ct.ID) || last["test_title"] != "" {
		t.Fatalf("second sync must reimport by test id: %+v", last)
	}
	if len(sim.tests) != 1 || len(sim.findings) != before {
		t.Fatalf("rename created tests or findings:\n%s", sim.summary())
	}

	// RDP closed on 10.66.0.12: its finding is mitigated, the rest stays.
	for i := range store.hosts {
		if store.hosts[i].IP == "10.66.0.12" {
			store.hosts[i].Services[1].State = "closed"
		}
	}
	syncOnce(t, store, cfg, "3")
	mitigated := 0
	for _, f := range sim.findingsOf(ct.ID) {
		if f.IsMitigated && !f.FalseP { // a false positive is mitigated too
			mitigated++
			if !strings.Contains(f.Title, "RDP") {
				t.Errorf("unexpected mitigation: %s", f.Title)
			}
		}
	}
	if mitigated != 1 {
		t.Fatalf("want the RDP finding mitigated, got %d mitigated:\n%s", mitigated, sim.summary())
	}
}

// A change test deleted in DefectDojo: the sync falls back to the title (DefectDojo creates
// the test again) and says so.
func TestSyncChangesRecreatesDeletedTest(t *testing.T) {
	sim, srv := newDojoSim(t)
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}
	store := newFixtureStore(t, inventoryHosts(), overlappingProfiles())
	syncOnce(t, store, cfg, "1")
	gone := sim.tests[0].ID
	sim.tests, sim.findings = nil, nil

	res := syncOnce(t, store, cfg, "2")
	if len(res.Warnings) == 0 || !strings.Contains(res.Warnings[0], "#"+strconv.Itoa(gone)) {
		t.Fatalf("warnings %v", res.Warnings)
	}
	if tests := sim.testByTitle(ChangesTest); len(tests) != 1 || tests[0].ID == gone || res.Import.TestID != tests[0].ID {
		t.Fatalf("change test not recreated:\n%s", sim.summary())
	}
	if st := db.LoadDefectDojoSync(context.Background(), store); st.TestID != res.Import.TestID {
		t.Fatalf("state still points at the deleted test: %+v", st)
	}
}

// A false positive is mitigated in DefectDojo: the sync must still find it, link it, and
// reactivate it when the analyst withdraws the decision in Dzięcioł.
func TestSyncChangesWithdrawsFalsePositive(t *testing.T) {
	sim, srv := newDojoSim(t)
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}
	store := newFixtureStore(t, inventoryHosts(), overlappingProfiles())
	syncOnce(t, store, cfg, "1")
	ct := sim.testByTitle(ChangesTest)[0]
	smb := func() *simFinding {
		for _, f := range sim.findingsOf(ct.ID) {
			if strings.Contains(f.Title, "10.66.0.91") {
				return f
			}
		}
		t.Fatalf("no SMB finding:\n%s", sim.summary())
		return nil
	}
	if f := smb(); !f.FalseP || !f.IsMitigated {
		t.Fatalf("false positive not applied: %+v", f)
	}
	syncOnce(t, store, cfg, "2") // the mitigated false positive is listed: still linked, nothing changes
	st := db.LoadDefectDojoSync(context.Background(), store)
	refs := st.FindingsByKey["service:h-10.66.0.91:445"]
	if len(refs) != 1 || refs[0].FindingID != smb().ID || refs[0].State != DojoStateFalsePos {
		t.Fatalf("false positive link: %+v", refs)
	}

	for i := range store.hosts {
		if store.hosts[i].IP == "10.66.0.91" {
			store.hosts[i].Services[0].Triage = nil
		}
	}
	syncOnce(t, store, cfg, "3")
	if f := smb(); f.FalseP || f.IsMitigated || !f.Active || notesWith(f, "withdrawn") != 1 {
		t.Fatalf("withdrawn false positive not reactivated: %+v", f)
	}
}
