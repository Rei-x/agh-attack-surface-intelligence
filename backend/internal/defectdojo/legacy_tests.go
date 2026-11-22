package defectdojo

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Retiring the per-profile change tests of older versions.
//
// Before the single change test (changes.go) every scan profile had its own
// "Dzięcioł changes: <profile>" test. Overlapping profiles put the same finding into two
// tests, both active, and renaming a profile started a new test while the old one kept its
// findings open forever. The sync cleans that up in DefectDojo itself:
//
//   - adoption, on the first sync after the upgrade (or after the DefectDojo context
//     changed): of the old change tests in the engagement DefectDojo resolves the context to,
//     the one already holding most of today's findings becomes the change test and is
//     renamed "Dzięcioł changes". Its findings keep their DefectDojo id, history, notes,
//     JIRA links and risk acceptance, and only the difference churns;
//   - retirement, on every sync (a few cheap requests once nothing is left): every other
//     change test of the product with open findings is closed by an empty reimport with
//     close_old_findings, after the analyst notes and the false positive / risk accepted
//     state set in DefectDojo on its findings that are still current were copied onto the
//     matching finding of the change test (same unique_id_from_tool). Its version and
//     description name the test that superseded it. Decisions made in Dzięcioł need no copy:
//     SyncTriage applies them to the change test anyway.
//
// Outside the change test's engagement only "Dzięcioł changes: ..." tests are retired, never
// a plain "Dzięcioł changes": that is the change test of another engagement (a second
// Dzięcioł instance sharing the product), not a leftover.

const (
	genericScanType = "Generic Findings Import"
	// outsideProfilesTitle renames a plain "Dzięcioł changes" test that loses the adoption:
	// in older versions that title held the hosts no profile covered.
	outsideProfilesTitle = ChangesTest + ": hosts outside profiles (superseded)"
	// changesTestDescription describes the change test in DefectDojo.
	changesTestDescription = "Actionable changes found by Dzięcioł for the whole inventory: one finding per " +
		"condition (risky exposure, admin panel, end of life, known vulnerability, new service, gone host, zone " +
		"policy), with the owner from the CIDR rules. Reimported after every completed scan, triage change and " +
		"verified fix with close_old_findings: fixed items are mitigated, returning ones reactivated."
)

type dojoTest struct {
	ID           int    `json:"id"`
	Title        string `json:"title"`
	Engagement   int    `json:"engagement"`
	ScanType     string `json:"scan_type"`
	TestTypeName string `json:"test_type_name"`
	Version      string `json:"version"`
}

type dojoEngagement struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Product int    `json:"product"`
}

// isChangesTest: a Generic Findings test titled "Dzięcioł changes" or "Dzięcioł changes: ...".
func isChangesTest(t dojoTest) bool {
	typ := t.ScanType
	if typ == "" {
		typ = t.TestTypeName
	}
	if typ != "" && typ != genericScanType {
		return false
	}
	return t.Title == ChangesTest || strings.HasPrefix(t.Title, ChangesTest+":")
}

// listPaged reads every page of a DefectDojo list endpoint (path carries its own query).
// The offset is computed here rather than taken from "next", which carries DefectDojo's own
// host name.
func listPaged[T any](ctx context.Context, c *Client, cfg *domain.DefectDojoConfig, path string, pageSize int) ([]T, error) {
	var out []T
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	for offset, pages := 0, 0; pages < 500; pages++ {
		var page struct {
			Count   int     `json:"count"`
			Next    *string `json:"next"`
			Results []T     `json:"results"`
		}
		if err := c.getJSON(ctx, cfg, fmt.Sprintf("%s%slimit=%d&offset=%d", path, sep, pageSize, offset), &page); err != nil {
			return out, err
		}
		out = append(out, page.Results...)
		offset += len(page.Results)
		if page.Next == nil || *page.Next == "" || len(page.Results) == 0 || (page.Count > 0 && offset >= page.Count) {
			break
		}
	}
	return out, nil
}

// countFindings returns how many findings of a test match the query, from one tiny page.
func (c *Client) countFindings(ctx context.Context, cfg *domain.DefectDojoConfig, testID int, query string) (int, error) {
	var page struct {
		Count   int           `json:"count"`
		Results []dojoFinding `json:"results"`
	}
	if err := c.getJSON(ctx, cfg, fmt.Sprintf("/api/v2/findings/?test=%d%s&limit=1", testID, query), &page); err != nil {
		return 0, err
	}
	if page.Count == 0 && len(page.Results) > 0 {
		return len(page.Results), nil
	}
	return page.Count, nil
}

// changesEngagement finds the engagement the context names resolve to, the way DefectDojo's
// auto_create_context does (product by exact name, then the last engagement with the name),
// or the pinned one. 0 when it does not exist yet.
func (c *Client) changesEngagement(ctx context.Context, cfg *domain.DefectDojoConfig, ic importContext) (int, error) {
	if cfg.EngagementID > 0 {
		return cfg.EngagementID, nil
	}
	productID := cfg.ProductID
	if productID <= 0 {
		var page struct {
			Results []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"results"`
		}
		if err := c.getJSON(ctx, cfg, "/api/v2/products/?limit=100&name_exact="+url.QueryEscape(ic.Product), &page); err != nil {
			return 0, fmt.Errorf("find product %q: %w", ic.Product, err)
		}
		for _, p := range page.Results {
			if p.Name == ic.Product {
				productID = p.ID
			}
		}
		if productID <= 0 {
			return 0, nil
		}
	}
	engs, err := listPaged[dojoEngagement](ctx, c, cfg, fmt.Sprintf("/api/v2/engagements/?product=%d&name=%s", productID, url.QueryEscape(ic.Engagement)), 100)
	if err != nil {
		return 0, fmt.Errorf("find engagement %q: %w", ic.Engagement, err)
	}
	best := 0
	for _, e := range engs {
		if e.Name == ic.Engagement && e.ID > best {
			best = e.ID
		}
	}
	return best, nil
}

// changesTestsOf lists the change tests ("Dzięcioł changes", "Dzięcioł changes: ...") of an
// engagement.
func (c *Client) changesTestsOf(ctx context.Context, cfg *domain.DefectDojoConfig, engagementID int) ([]dojoTest, error) {
	tests, err := listPaged[dojoTest](ctx, c, cfg, fmt.Sprintf("/api/v2/tests/?engagement=%d", engagementID), 200)
	if err != nil {
		return nil, fmt.Errorf("list tests of engagement %d: %w", engagementID, err)
	}
	var out []dojoTest
	for _, t := range tests {
		if isChangesTest(t) {
			if t.Engagement == 0 {
				t.Engagement = engagementID
			}
			out = append(out, t)
		}
	}
	return out, nil
}

// adoptChangesTest picks the change test among the old change tests of the engagement the
// context resolves to: the one whose open findings cover most of today's findings (by
// unique id; a tie goes to a test already titled "Dzięcioł changes", then to the newest).
// It renames it "Dzięcioł changes" (a plain "Dzięcioł changes" that loses is renamed out of
// the way) and returns its id, or 0 when there is no old change test (a fresh install: the
// title creates the test). listed holds every finding listed per test, for the retirement.
func (c *Client) adoptChangesTest(ctx context.Context, cfg *domain.DefectDojoConfig, ic importContext, findings []ChangeFinding) (id int, listed map[int][]dojoFinding, warnings []string, err error) {
	engID, err := c.changesEngagement(ctx, cfg, ic)
	if err != nil || engID == 0 {
		return 0, nil, nil, err
	}
	cands, err := c.changesTestsOf(ctx, cfg, engID)
	if err != nil || len(cands) == 0 {
		return 0, nil, nil, err
	}
	want := make(map[string]bool, len(findings))
	for _, f := range findings {
		want[f.UniqueIDFromTool] = true
	}
	listed = make(map[int][]dojoFinding, len(cands))
	best, bestScore := dojoTest{}, -1
	for _, t := range cands {
		fs, lerr := c.listCurrentFindings(ctx, cfg, t.ID)
		if lerr != nil {
			return 0, nil, nil, fmt.Errorf("list findings of test %d: %w", t.ID, lerr)
		}
		listed[t.ID] = fs
		seen := map[string]bool{}
		for _, f := range fs {
			if want[f.UniqueIDFromTool] && (!f.IsMitigated || f.FalseP || f.RiskAccepted) {
				seen[f.UniqueIDFromTool] = true
			}
		}
		score := len(seen)
		better := score > bestScore ||
			(score == bestScore && t.Title == ChangesTest && best.Title != ChangesTest) ||
			(score == bestScore && (t.Title == ChangesTest) == (best.Title == ChangesTest) && t.ID > best.ID)
		if better {
			best, bestScore = t, score
		}
	}
	if best.Title != ChangesTest {
		for _, t := range cands {
			if t.Title == ChangesTest {
				if perr := c.patchJSON(ctx, cfg, fmt.Sprintf("/api/v2/tests/%d/", t.ID), map[string]any{"title": outsideProfilesTitle}); perr != nil {
					warnings = append(warnings, fmt.Sprintf("rename test #%d: %v", t.ID, perr))
				}
			}
		}
		if perr := c.patchJSON(ctx, cfg, fmt.Sprintf("/api/v2/tests/%d/", best.ID), map[string]any{"title": ChangesTest}); perr != nil {
			// Cosmetic: the change test is addressed by id from now on.
			warnings = append(warnings, fmt.Sprintf("rename test #%d to %q: %v", best.ID, ChangesTest, perr))
		}
	}
	return best.ID, listed, warnings, nil
}

// retireLegacyTests closes the change tests of the product other than the change test (see
// the file comment) and returns what it retired. findings and refs are the payload just
// pushed and its links (refs[i] for findings[i]; carried triage updates refs in place),
// existing the findings of the change test, listed the findings the adoption listed.
func (c *Client) retireLegacyTests(ctx context.Context, cfg *domain.DefectDojoConfig, imp *ImportResult, findings []ChangeFinding, refs []FindingRef, existing []dojoFinding, listed map[int][]dojoFinding) ([]domain.DefectDojoLegacyTest, []string) {
	var warnings []string
	engs, err := listPaged[dojoEngagement](ctx, c, cfg, fmt.Sprintf("/api/v2/engagements/?product=%d", imp.ProductID), 100)
	if err != nil {
		return nil, []string{fmt.Sprintf("list engagements of product %d: %v", imp.ProductID, err)}
	}
	var legacy []dojoTest
	for _, e := range engs {
		tests, terr := c.changesTestsOf(ctx, cfg, e.ID)
		if terr != nil {
			warnings = append(warnings, terr.Error())
			continue
		}
		for _, t := range tests {
			if t.ID == imp.TestID || (t.Title == ChangesTest && e.ID != imp.EngagementID && imp.EngagementID > 0) {
				continue
			}
			legacy = append(legacy, t)
		}
	}
	if len(legacy) == 0 {
		return nil, warnings
	}

	co := newCarryOver(c, cfg, imp, findings, refs, existing)
	base := baseURL(cfg.URL)
	var out []domain.DefectDojoLegacyTest
	version := supersededVersion(imp.TestID)
	for _, t := range legacy {
		// Only tests with open findings are closed: once closed (every finding mitigated) a
		// test costs one small request per sync. Carrying also looks at false positives, which
		// DefectDojo marks mitigated.
		fs, cached := listed[t.ID]
		open := 0
		if cached {
			for _, f := range fs {
				if !f.IsMitigated {
					open++
				}
			}
		} else {
			n, cerr := c.countFindings(ctx, cfg, t.ID, "&is_mitigated=false")
			if cerr != nil {
				warnings = append(warnings, fmt.Sprintf("count findings of test #%d: %v", t.ID, cerr))
				continue
			}
			open = n
		}
		rec := domain.DefectDojoLegacyTest{TestID: t.ID, Title: t.Title, URL: fmt.Sprintf("%s/test/%d", base, t.ID), RetiredAt: time.Now().UTC()}
		if open == 0 {
			// Nothing open (an empty per-profile test, or one closed earlier): only say that
			// it is superseded, once.
			if !strings.HasPrefix(t.Version, supersededVersionPrefix) {
				if perr := c.patchJSON(ctx, cfg, fmt.Sprintf("/api/v2/tests/%d/", t.ID), map[string]any{
					"version": version, "description": supersededDescription(rec.RetiredAt, imp.TestID, false)}); perr != nil {
					warnings = append(warnings, fmt.Sprintf("label superseded test #%d: %v", t.ID, perr))
				} else {
					out = append(out, rec)
				}
			}
			continue
		}
		if !cached {
			var lerr error
			if fs, lerr = c.listCurrentFindings(ctx, cfg, t.ID); lerr != nil {
				warnings = append(warnings, fmt.Sprintf("list findings of test #%d: %v", t.ID, lerr))
				continue
			}
		}
		for _, f := range fs {
			if f.Active {
				rec.Closed++
			}
		}
		rec.NotesCarried, rec.TriageCarried = co.carry(ctx, t, fs)
		if _, err := c.importChanges(ctx, cfg, reimportTarget{TestID: t.ID}, version, nil); err != nil {
			warnings = append(warnings, fmt.Sprintf("close superseded test #%d: %v", t.ID, err))
			continue
		}
		if perr := c.patchJSON(ctx, cfg, fmt.Sprintf("/api/v2/tests/%d/", t.ID), map[string]any{"description": supersededDescription(rec.RetiredAt, imp.TestID, true)}); perr != nil {
			warnings = append(warnings, fmt.Sprintf("describe superseded test #%d: %v", t.ID, perr))
		}
		out = append(out, rec)
	}
	return out, append(warnings, co.warnings...)
}

const supersededVersionPrefix = "superseded by test #"

// supersededVersion is the version a superseded test gets (shown in DefectDojo's test lists).
func supersededVersion(changesTestID int) string {
	return fmt.Sprintf("%s%d (%s)", supersededVersionPrefix, changesTestID, ChangesTest)
}

// supersededDescription explains on a superseded test what happened to it.
func supersededDescription(at time.Time, changesTestID int, closed bool) string {
	d := fmt.Sprintf("Superseded on %s by test #%d %q. Dzięcioł now keeps one change test for the whole inventory, "+
		"so a host covered by several scan profiles gives one finding.", at.Format("2006-01-02"), changesTestID, ChangesTest)
	if closed {
		d += fmt.Sprintf(" The open findings of this test were closed by an empty reimport; analyst notes and false "+
			"positive / risk accepted states set in DefectDojo on findings that are still current were copied to the "+
			"matching findings of test #%d.", changesTestID)
	}
	return d
}

// carryOver copies what an analyst left on a superseded test's findings onto the matching
// finding of the change test.
type carryOver struct {
	c         *Client
	cfg       *domain.DefectDojoConfig
	productID int
	testID    int
	findings  []ChangeFinding
	refs      []FindingRef
	byUID     map[string]int          // unique id -> index into findings/refs
	marks     map[int]map[string]bool // change test finding id -> carried note markers
	raEnabled bool
	warnings  []string
}

func newCarryOver(c *Client, cfg *domain.DefectDojoConfig, imp *ImportResult, findings []ChangeFinding, refs []FindingRef, existing []dojoFinding) *carryOver {
	co := &carryOver{c: c, cfg: cfg, productID: imp.ProductID, testID: imp.TestID, findings: findings, refs: refs,
		byUID: map[string]int{}, marks: map[int]map[string]bool{}}
	for i := range findings {
		if i < len(refs) && refs[i].FindingID > 0 {
			co.byUID[findings[i].UniqueIDFromTool] = i
		}
	}
	for _, f := range existing {
		for _, n := range f.Notes {
			if strings.HasPrefix(n.Entry, carriedNotePrefix) {
				co.mark(f.ID, carriedMarker(n.Entry))
			}
		}
	}
	return co
}

const carriedNotePrefix = "Carried over from DefectDojo finding #"

// carriedMarker is the "Carried over from DefectDojo finding #N, note #M" head of a carried
// note: what makes carrying idempotent.
func carriedMarker(entry string) string {
	if i := strings.Index(entry, " in test #"); i > 0 {
		return entry[:i]
	}
	return entry
}

func (co *carryOver) mark(findingID int, marker string) bool {
	if co.marks[findingID] == nil {
		co.marks[findingID] = map[string]bool{}
	}
	if co.marks[findingID][marker] {
		return false
	}
	co.marks[findingID][marker] = true
	return true
}

// carry copies the notes and DefectDojo-side triage of one superseded test's open findings.
func (co *carryOver) carry(ctx context.Context, t dojoTest, fs []dojoFinding) (notes, triage int) {
	for _, lf := range fs {
		i, ok := co.byUID[lf.UniqueIDFromTool]
		if !ok {
			continue // the condition is gone: closing the old finding is right
		}
		ref := &co.refs[i]
		for _, n := range lf.Notes {
			if !isAnalystNote(n.Entry) {
				continue
			}
			marker := fmt.Sprintf("%s%d, note #%d", carriedNotePrefix, lf.ID, n.ID)
			if !co.mark(ref.FindingID, marker) {
				continue
			}
			entry := fmt.Sprintf("%s in test #%d %q (by %s on %s):\n\n%s", marker, t.ID, t.Title, nonEmpty(n.Author.Username, "unknown"), dateOnly(n.Date), n.Entry)
			if err := co.c.postJSON(ctx, co.cfg, fmt.Sprintf("/api/v2/findings/%d/notes/", ref.FindingID), map[string]any{"entry": entry}); err != nil {
				co.warnings = append(co.warnings, fmt.Sprintf("carry note of finding #%d: %v", lf.ID, err))
				continue
			}
			notes++
		}
		// A decision made in Dzięcioł wins (SyncTriage applied it); one made in DefectDojo on
		// the old finding moves to the new one unless that one has its own already.
		state := lf.state()
		if (state != DojoStateFalsePos && state != DojoStateRiskAccepted) || co.findings[i].Triage != nil || ref.State != DojoStateActive {
			continue
		}
		if err := co.c.setFindingState(ctx, co.cfg, ref.FindingID, co.productID, state, &co.raEnabled); err != nil {
			co.warnings = append(co.warnings, fmt.Sprintf("carry %s of finding #%d: %v", state, lf.ID, err))
			continue
		}
		ref.State = state
		triage++
		label := "false positive"
		if state == DojoStateRiskAccepted {
			label = "risk accepted"
		}
		entry := fmt.Sprintf("%s%d, state in test #%d %q: %s in DefectDojo, kept on this finding.", carriedNotePrefix, lf.ID, t.ID, t.Title, label)
		_ = co.c.postJSON(ctx, co.cfg, fmt.Sprintf("/api/v2/findings/%d/notes/", ref.FindingID), map[string]any{"entry": entry})
	}
	return notes, triage
}

// isAnalystNote: a note a person wrote, not one DefectDojo or Dzięcioł adds on its own
// (reimport mitigation/reactivation, Dzięcioł triage mirroring, which SyncTriage redoes).
func isAnalystNote(entry string) bool {
	e := strings.TrimSpace(entry)
	if e == "" {
		return false
	}
	for _, p := range []string{"Mitigated by ", "Re-activated by ", triageNotePrefix, withdrawnNotePrefix} {
		if strings.HasPrefix(e, p) {
			return false
		}
	}
	return true
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return nonEmpty(s, "unknown date")
}
