package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// dojoSim is a stateful stand-in for the parts of DefectDojo API v2 the change sync relies
// on, following DefectDojo 2.x/3.x behaviour:
//
//   - reimport-scan by names with auto_create_context (product by exact name, the last
//     engagement with the name, the last test with the title and scan type), or by test id
//     alone (an unknown id is 400 {"test": ["Invalid pk ..."]});
//   - Generic Findings reimport matching by hash_code (title + description) inside the test:
//     a match is left untouched (reactivated when mitigated, unless false positive or risk
//     accepted, which DefectDojo skips), the rest is created, and with
//     close_old_findings every open finding the report lacks is mitigated, false positives
//     and risk accepted ones included; a brand new test never closes anything;
//   - finding lists with test / is_mitigated / active filters and limit/offset pages capped
//     at pageCap, PATCH of findings and tests (a false positive is also mitigated, setting
//     active clears both), notes on findings and tests.
type dojoSim struct {
	t       *testing.T
	mu      sync.Mutex
	nextID  int
	pageCap int

	products    []*simProduct
	engagements []*simEngagement
	tests       []*simTest
	findings    []*simFinding

	reimports []map[string]string // multipart fields of every reimport, in order
}

type simProduct struct {
	ID   int
	Name string
}

type simEngagement struct {
	ID, Product int
	Name        string
}

type simTest struct {
	ID, Engagement           int
	Title, ScanType, Version string
	Description              string
	Notes                    []string
}

type simFinding struct {
	ID, Test                                         int
	Title, Description, UID                          string
	Active, FalseP, RiskAccepted, IsMitigated, Verif bool
	Notes                                            []map[string]any
}

func newDojoSim(t *testing.T) (*dojoSim, *httptest.Server) {
	s := &dojoSim{t: t, nextID: 1, pageCap: 50}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return s, srv
}

func (s *dojoSim) id() int {
	s.nextID++
	return s.nextID
}

func (s *dojoSim) addProduct(name string) *simProduct {
	p := &simProduct{ID: s.id(), Name: name}
	s.products = append(s.products, p)
	return p
}

func (s *dojoSim) addEngagement(p *simProduct, name string) *simEngagement {
	e := &simEngagement{ID: s.id(), Product: p.ID, Name: name}
	s.engagements = append(s.engagements, e)
	return e
}

func (s *dojoSim) addTest(e *simEngagement, title, scanType string) *simTest {
	t := &simTest{ID: s.id(), Engagement: e.ID, Title: title, ScanType: scanType}
	s.tests = append(s.tests, t)
	return t
}

// seed puts change findings into a test as an earlier reimport would have.
func (s *dojoSim) seed(t *simTest, fs []ChangeFinding) []*simFinding {
	var out []*simFinding
	for _, f := range fs {
		sf := &simFinding{ID: s.id(), Test: t.ID, Title: f.Title, Description: f.Description, UID: f.UniqueIDFromTool, Active: true}
		s.findings = append(s.findings, sf)
		out = append(out, sf)
	}
	return out
}

func (s *dojoSim) test(id int) *simTest {
	for _, t := range s.tests {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (s *dojoSim) testByTitle(title string) []*simTest {
	var out []*simTest
	for _, t := range s.tests {
		if t.Title == title {
			out = append(out, t)
		}
	}
	return out
}

func (s *dojoSim) finding(id int) *simFinding {
	for _, f := range s.findings {
		if f.ID == id {
			return f
		}
	}
	return nil
}

func (s *dojoSim) findingsOf(testID int) []*simFinding {
	var out []*simFinding
	for _, f := range s.findings {
		if f.Test == testID {
			out = append(out, f)
		}
	}
	return out
}

func (s *dojoSim) productOf(t *simTest) int {
	for _, e := range s.engagements {
		if e.ID == t.Engagement {
			return e.Product
		}
	}
	return 0
}

// activeByUID counts the active findings per unique id across a product: the duplicates a
// DefectDojo user sees.
func (s *dojoSim) activeByUID(productID int) map[string][]int {
	out := map[string][]int{}
	for _, f := range s.findings {
		if t := s.test(f.Test); f.Active && t != nil && s.productOf(t) == productID {
			out[f.UID] = append(out[f.UID], f.ID)
		}
	}
	return out
}

func (s *dojoSim) addNote(f *simFinding, entry string) {
	f.Notes = append(f.Notes, map[string]any{"id": s.id(), "entry": entry, "date": "2026-11-21T10:00:00Z", "author": map[string]any{"username": "analyst"}})
}

func (s *dojoSim) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	q := r.URL.Query()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // api v2 <kind> [id] [sub]
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "v2" {
		http.NotFound(w, r)
		return
	}
	kind, id, sub := parts[2], 0, ""
	if len(parts) > 3 {
		id, _ = strconv.Atoi(parts[3])
	}
	if len(parts) > 4 {
		sub = parts[4]
	}
	switch {
	case kind == "reimport-scan" && r.Method == http.MethodPost:
		s.reimport(w, r)
	case kind == "products" && r.Method == http.MethodGet && id == 0:
		var res []any
		for _, p := range s.products {
			if n := q.Get("name_exact"); n == "" || n == p.Name {
				res = append(res, map[string]any{"id": p.ID, "name": p.Name})
			}
		}
		s.page(w, r, res)
	case kind == "products" && r.Method == http.MethodPatch:
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	case kind == "engagements" && r.Method == http.MethodGet:
		var res []any
		for _, e := range s.engagements {
			if (q.Get("product") == "" || q.Get("product") == strconv.Itoa(e.Product)) && (q.Get("name") == "" || q.Get("name") == e.Name) {
				res = append(res, map[string]any{"id": e.ID, "name": e.Name, "product": e.Product})
			}
		}
		s.page(w, r, res)
	case kind == "tests" && r.Method == http.MethodGet && id == 0:
		var res []any
		for _, t := range s.tests {
			if q.Get("engagement") == "" || q.Get("engagement") == strconv.Itoa(t.Engagement) {
				res = append(res, map[string]any{"id": t.ID, "title": t.Title, "engagement": t.Engagement, "scan_type": t.ScanType, "test_type_name": t.ScanType, "version": t.Version})
			}
		}
		s.page(w, r, res)
	case kind == "tests" && r.Method == http.MethodPatch && sub == "":
		t := s.test(id)
		if t == nil {
			http.NotFound(w, r)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if v, ok := body["title"]; ok {
			t.Title = v
		}
		if v, ok := body["description"]; ok {
			t.Description = v
		}
		if v, ok := body["version"]; ok {
			t.Version = v
		}
		_, _ = io.WriteString(w, `{}`)
	case kind == "tests" && r.Method == http.MethodPost && sub == "notes":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.test(id).Notes = append(s.test(id).Notes, body["entry"])
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{}`)
	case kind == "findings" && r.Method == http.MethodGet && id == 0:
		var res []any
		for _, f := range s.findings {
			if q.Get("test") != "" && q.Get("test") != strconv.Itoa(f.Test) {
				continue
			}
			if v := q.Get("is_mitigated"); v != "" && v != strconv.FormatBool(f.IsMitigated) {
				continue
			}
			if v := q.Get("active"); v != "" && v != strconv.FormatBool(f.Active) {
				continue
			}
			res = append(res, map[string]any{"id": f.ID, "test": f.Test, "unique_id_from_tool": f.UID, "title": f.Title,
				"active": f.Active, "false_p": f.FalseP, "risk_accepted": f.RiskAccepted, "is_mitigated": f.IsMitigated,
				"verified": f.Verif, "notes": f.Notes})
		}
		s.page(w, r, res)
	case kind == "findings" && r.Method == http.MethodPatch && sub == "":
		f := s.finding(id)
		if f == nil {
			http.NotFound(w, r)
			return
		}
		var body map[string]bool
		_ = json.NewDecoder(r.Body).Decode(&body)
		for k, v := range body {
			switch k {
			case "false_p":
				f.FalseP = v
			case "risk_accepted":
				f.RiskAccepted = v
			case "active":
				f.Active = v
			case "verified":
				f.Verif = v
			}
		}
		// DefectDojo's update_finding_status: active clears false_p and the mitigation,
		// false_p implies mitigated and inactive.
		if body["active"] {
			f.FalseP, f.IsMitigated = false, false
		}
		if f.FalseP {
			f.IsMitigated, f.Active = true, false
		}
		_, _ = io.WriteString(w, `{}`)
	case kind == "findings" && r.Method == http.MethodPost && sub == "notes":
		f := s.finding(id)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.addNote(f, body["entry"])
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{}`)
	default:
		s.t.Errorf("dojoSim: unexpected %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	}
}

func (s *dojoSim) page(w http.ResponseWriter, r *http.Request, res []any) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > s.pageCap {
		limit = s.pageCap
	}
	end := offset + limit
	if end > len(res) {
		end = len(res)
	}
	var next any
	if end < len(res) {
		next = "http://dojo.internal/next"
	}
	page := []any{}
	if offset < len(res) {
		page = res[offset:end]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"count": len(res), "next": next, "results": page})
}

func (s *dojoSim) reimport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		s.t.Fatalf("dojoSim: multipart: %v", err)
	}
	form := map[string]string{}
	for k, v := range r.MultipartForm.Value {
		form[k] = v[0]
	}
	file, _, _ := r.FormFile("file")
	raw, _ := io.ReadAll(file)
	s.reimports = append(s.reimports, form)
	bad := func(body string) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, body)
	}

	var test *simTest
	created := false
	if form["test"] != "" {
		if form["product_name"] != "" || form["engagement_name"] != "" {
			bad(`{"detail":"test id together with context names"}`)
			return
		}
		tid, _ := strconv.Atoi(form["test"])
		if test = s.test(tid); test == nil {
			bad(`{"test":["Invalid pk \"` + form["test"] + `\" - object does not exist."]}`)
			return
		}
	} else {
		if form["auto_create_context"] != "true" {
			bad(`{"detail":"A test could not be found!"}`)
			return
		}
		var prod *simProduct
		for _, p := range s.products {
			if p.Name == form["product_name"] {
				prod = p
			}
		}
		if prod == nil {
			prod = s.addProduct(form["product_name"])
		}
		var eng *simEngagement
		for _, e := range s.engagements {
			if e.Product == prod.ID && e.Name == form["engagement_name"] && (eng == nil || e.ID > eng.ID) {
				eng = e
			}
		}
		if eng == nil {
			eng = s.addEngagement(prod, form["engagement_name"])
		}
		for _, t := range s.tests {
			if t.Engagement == eng.ID && t.Title == form["test_title"] && t.ScanType == form["scan_type"] && (test == nil || t.ID > test.ID) {
				test = t
			}
		}
		if test == nil {
			test, created = s.addTest(eng, form["test_title"], form["scan_type"]), true
		}
	}
	if v := form["version"]; v != "" {
		test.Version = v
	}
	if test.ScanType == "Generic Findings Import" {
		var doc struct {
			Findings []struct {
				Title       string `json:"title"`
				Description string `json:"description"`
				UID         string `json:"unique_id_from_tool"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			bad(`{"detail":"bad generic findings json"}`)
			return
		}
		matched := map[int]bool{}
		for _, item := range doc.Findings {
			var hit *simFinding
			for _, f := range s.findingsOf(test.ID) {
				if f.Title == item.Title && f.Description == item.Description && !matched[f.ID] {
					hit = f
					break
				}
			}
			if hit == nil {
				hit = &simFinding{ID: s.id(), Test: test.ID, Title: item.Title, Description: item.Description, UID: item.UID, Active: true}
				s.findings = append(s.findings, hit)
			} else if hit.FalseP || hit.RiskAccepted {
				// special status: left as it is
			} else if hit.IsMitigated {
				hit.IsMitigated, hit.Active = false, true
				s.addNote(hit, "Re-activated by Generic Findings Import re-upload.")
			}
			matched[hit.ID] = true
		}
		if form["close_old_findings"] == "true" && !created {
			for _, f := range s.findingsOf(test.ID) {
				if !matched[f.ID] && !f.IsMitigated {
					f.IsMitigated, f.Active = true, false
					s.addNote(f, "Mitigated by Generic Findings Import re-upload.")
				}
			}
		}
	}
	eng := 0
	for _, e := range s.engagements {
		if e.ID == test.Engagement {
			eng = e.ID
		}
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"test": test.ID, "test_id": test.ID, "engagement_id": eng, "product_id": s.productOf(test),
		"statistics": map[string]any{"after": map[string]any{"total": map[string]any{"total": len(s.findingsOf(test.ID))}}}})
}

// fixtureStore is a memory store whose inventory and profiles are fixed by the test.
type fixtureStore struct {
	*db.MemoryStore
	hosts    []domain.Host
	profiles []domain.ScanProfile
}

func newFixtureStore(t *testing.T, hosts []domain.Host, profiles []domain.ScanProfile) *fixtureStore {
	vault, err := crypto.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureStore{MemoryStore: db.NewMemoryStore(vault), hosts: hosts, profiles: profiles}
}

func (s *fixtureStore) ListHosts(context.Context, db.HostFilter) ([]domain.Host, int, error) {
	out := make([]domain.Host, len(s.hosts))
	copy(out, s.hosts)
	return out, len(out), nil
}

func (s *fixtureStore) ListProfiles(context.Context) ([]domain.ScanProfile, error) {
	return append([]domain.ScanProfile(nil), s.profiles...), nil
}

// summary renders the sim's tests for failure messages.
func (s *dojoSim) summary() string {
	var b strings.Builder
	ts := append([]*simTest(nil), s.tests...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].ID < ts[j].ID })
	for _, t := range ts {
		active := 0
		for _, f := range s.findingsOf(t.ID) {
			if f.Active {
				active++
			}
		}
		fmt.Fprintf(&b, "  test #%d eng %d %q (%s) findings=%d active=%d version=%q\n", t.ID, t.Engagement, t.Title, t.ScanType, len(s.findingsOf(t.ID)), active, t.Version)
	}
	return b.String()
}
