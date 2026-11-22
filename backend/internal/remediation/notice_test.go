package remediation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/outbound"
)

// nginx 1.20.1 on a faculty host, first seen at 00:39 Warsaw time on 22 November (23:39 UTC
// on the 21st), drafted the same morning.
var (
	nginxSeen = time.Date(2026, 11, 21, 23, 39, 0, 0, time.UTC)
	nginxNow  = time.Date(2026, 11, 22, 7, 15, 0, 0, time.UTC)
)

func nginxService(t *testing.T) (*Service, *domain.Host, *domain.Service) {
	t.Helper()
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	host, err := store.UpsertObservedHost(ctx, &domain.Host{IP: "10.66.2.246", LifecycleState: domain.HostStateActive, Owner: "eaiib.agh.edu.pl", FirstSeen: nginxSeen})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := store.UpsertObservedService(ctx, &domain.Service{
		HostID: host.ID, Port: 80, Protocol: "tcp", State: "open", ServiceName: "http", Product: "nginx", Version: "1.20.1",
		FirstSeen: nginxSeen,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := NewService(store, outbound.NewDeliverer(store, nil))
	s.Now = func() time.Time { return nginxNow }
	return s, host, svc
}

func TestPolishNoticeForEndOfLifeNginx(t *testing.T) {
	ctx := context.Background()
	s, host, svc := nginxService(t)
	d, err := s.Draft(ctx, host.ID, svc.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Language != locale.PL || d.DefaultLanguage != locale.PL || d.Timezone != "Europe/Warsaw" {
		t.Fatalf("a new install drafts Polish in Warsaw time: %s %s %s", d.Language, d.DefaultLanguage, d.Timezone)
	}
	wantSubject := "[CBI AGH] Wymagane działanie: nginx 1.20.1 bez wsparcia (EOL) od 2022-05-24"
	if d.Subject != wantSubject {
		t.Errorf("subject:\n got %q\nwant %q", d.Subject, wantSubject)
	}
	wantBody := `Szanowni Państwo,

Nasz system monitorowania sieci wykrył problem na hoście, którym Państwo administrują (w naszej ewidencji: eaiib.agh.edu.pl).

Problem: nginx 1.20.1 bez wsparcia (EOL) od 2022-05-24
Adres: 10.66.2.246:80/tcp
Usługa: http nginx 1.20.1
Szczegóły: Wersję nginx 1.20.1 rozpoznano na podstawie wyniku nmap -sV. Gałąź 1.20 nie otrzymuje poprawek bezpieczeństwa od 2022-05-24. Źródło: https://endoflife.date/nginx
Pierwsze wykrycie: 2026-11-22

Zalecenie: Zaktualizować nginx do wersji 1.30 (stable) lub nowszej albo wyłączyć usługę, jeśli nie jest potrzebna.
Prosimy o aktualizację w terminie do 2027-02-20 i o odpowiedź na tę wiadomość po zakończeniu prac. Sprawdzamy ten adres po każdym skanowaniu i zamkniemy zgłoszenie, gdy problem przestanie występować.

Jeśli ten host nie należy do Państwa, prosimy o informację, kto nim administruje.

Z poważaniem
Zespół bezpieczeństwa CBI AGH`
	if d.Body != wantBody {
		t.Errorf("body:\n%s\n\nwant:\n%s", d.Body, wantBody)
	}
	if strings.ContainsAny(d.Subject+d.Body, "\u2013\u2014") {
		t.Error("notices must not contain en or em dashes")
	}
	// The issue list of the dialog stays English (analyst UI), the notice does not.
	if d.Issues[0].Title != "nginx 1.20.1 is end of life since 2022-05-24" {
		t.Errorf("issue title: %q", d.Issues[0].Title)
	}

	// Per message the analyst can switch to English.
	en, err := s.Draft(ctx, host.ID, svc.ID, d.IssueKey, "en")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Hello eaiib.agh.edu.pl,", "First seen: 2026-11-22", "Please patch it by 2027-02-20 and reply when done.", "CBI AGH security team"} {
		if !strings.Contains(en.Body, want) {
			t.Errorf("English body misses %q:\n%s", want, en.Body)
		}
	}
	if en.Language != locale.EN || en.DefaultLanguage != locale.PL {
		t.Errorf("languages: %s / %s", en.Language, en.DefaultLanguage)
	}

	// Sending stores the language; the chat card facts follow it.
	res, err := s.Create(ctx, CreateRequest{HostID: host.ID, ServiceID: svc.ID, IssueKey: d.IssueKey, Subject: d.Subject, Body: d.Body, Language: d.Language, DueDate: d.DueDate, Channel: "none"}, "ana")
	if err != nil {
		t.Fatal(err)
	}
	if res.Ticket.Language != locale.PL || locale.DueDay(*res.Ticket.DueAt, warsaw) != "2027-02-20" {
		t.Fatalf("ticket: %s %v", res.Ticket.Language, res.Ticket.DueAt)
	}
	// The ticket itself stays English for the board.
	if res.Ticket.Title != "nginx 1.20.1 is end of life since 2022-05-24" {
		t.Fatalf("ticket title: %q", res.Ticket.Title)
	}
}

func TestPolishIssueTexts(t *testing.T) {
	svc := &domain.Service{HostIP: "10.0.0.9", Port: 23, Protocol: "tcp", ServiceName: "telnet"}
	is := ServiceIssuesIn(svc, t0, locale.PL)
	if is[0].Title != "Logowanie bez szyfrowania (Telnet) na 10.0.0.9:23/tcp" || is[0].Advice != "Wyłączyć Telnet i korzystać z szyfrowanej alternatywy (SSH, SFTP)." {
		t.Fatalf("telnet: %+v", is[0])
	}
	// A passive hint outside the embedded vulnerability database, built by hand.
	hint := domain.VulnHint{ID: "CVE-2024-6387", Name: "regreSSHion (unauthenticated RCE in the sshd SIGALRM handler)", Product: "OpenSSH",
		Version: "8.9p1 Ubuntu-3ubuntu0.6", Affected: ">= 8.5p1, < 9.8p1", DistroPackaged: true}
	vi := vulnIssue(textPL, hint)
	if vi.Title != "Możliwa podatność CVE-2024-6387 (regreSSHion, zdalne wykonanie kodu bez uwierzytelnienia w obsłudze sygnału SIGALRM w sshd) w OpenSSH 8.9p1" {
		t.Fatalf("regreSSHion title: %q", vi.Title)
	}
	if vi.Evidence != "Ocena wyłącznie na podstawie numeru wersji: OpenSSH 8.9p1 Ubuntu-3ubuntu0.6 mieści się w zakresie wersji podatnych na CVE-2024-6387 (>= 8.5p1, < 9.8p1). Usługi nie testowano, aby to potwierdzić. To wersja z dystrybucji systemu: poprawka mogła zostać przeniesiona (backport), prosimy sprawdzić wersję pakietu." {
		t.Fatalf("regreSSHion evidence: %q", vi.Evidence)
	}
	if vi.Severity != "medium" || vi.DueDays != 90 {
		t.Fatalf("passive hint severity: %+v", vi)
	}
	svc = &domain.Service{HostIP: "10.0.0.9", Port: 8080, Protocol: "tcp", ServiceName: "http", IsAdminPanel: true, IsStagingEnv: true,
		Technologies: []domain.DetectedTechnology{{Name: "Jenkins", Category: "admin_panel", Confidence: 90}},
		HTTP:         &domain.HTTPFingerprint{URL: "http://10.0.0.9:8080/login", Title: "Sign in [Jenkins]"}}
	is = ServiceIssuesIn(svc, t0, locale.PL)
	titles := []string{}
	for _, i := range is {
		titles = append(titles, i.Title)
	}
	want := "Panel administracyjny Jenkins dostępny na 10.0.0.9:8080/tcp|Środowisko testowe dostępne na 10.0.0.9:8080/tcp"
	if strings.Join(titles, "|") != want {
		t.Fatalf("titles: %v", titles)
	}
	if is[0].Evidence != "Wykryto stronę logowania administratora lub konsolę zarządzania pod adresem http://10.0.0.9:8080/login (tytuł strony: „Sign in [Jenkins]”)." {
		t.Fatalf("admin evidence: %q", is[0].Evidence)
	}
	g := GenericIssueIn(nil, &domain.Host{IP: "10.0.0.9"}, locale.PL)
	if g.Title != "Host 10.0.0.9 wymaga weryfikacji" {
		t.Fatalf("generic: %+v", g)
	}
	for _, i := range append(is, g) {
		if strings.ContainsAny(i.Title+i.Evidence+i.Advice, "\u2013\u2014") {
			t.Errorf("dash in %+v", i)
		}
	}
	// Polish subjects are cut on a letter boundary.
	long := truncateRunes(strings.Repeat("ż", 100), 160)
	if !strings.HasSuffix(long, "...") || !strings.HasPrefix(long, "ż") || len(long) > 160 {
		t.Fatalf("truncate: %q", long)
	}
	for _, r := range strings.TrimSuffix(long, "...") {
		if r != 'ż' {
			t.Fatalf("broken rune in %q", long)
		}
	}
}

func TestNoticeDatesUseTheInstanceTimezone(t *testing.T) {
	// 23:39 UTC on the 21st is the 22nd in Warsaw: notices never print the UTC day.
	due := time.Date(2027, 2, 19, 22, 59, 0, 0, time.UTC) // 23:59 Warsaw
	tk := &Ticket{HostIP: "10.66.2.246", Port: 80, Protocol: "tcp", Title: "x", Action: ActionPatch, DueAt: &due}
	pl := BuildDraft(tk, Notice{Lang: locale.PL, Loc: warsaw, FirstSeen: nginxSeen})
	if !strings.Contains(pl.Body, "Pierwsze wykrycie: 2026-11-22") || !strings.Contains(pl.Body, "w terminie do 2027-02-19") {
		t.Fatalf("Warsaw dates:\n%s", pl.Body)
	}
	ny := locale.Location("America/New_York")
	en := BuildDraft(tk, Notice{Lang: locale.EN, Loc: ny, FirstSeen: nginxSeen})
	if !strings.Contains(en.Body, "First seen: 2026-11-21") || !strings.Contains(en.Body, "by 2027-02-19") {
		t.Fatalf("New York dates:\n%s", en.Body)
	}
	// A due date of an older version (23:59 UTC) keeps its day in Warsaw.
	legacy := time.Date(2026, 12, 22, 23, 59, 0, 0, time.UTC)
	tk.DueAt = &legacy
	if d := BuildDraft(tk, Notice{Lang: locale.EN, Loc: warsaw}); !strings.Contains(d.Body, "by 2026-12-22") {
		t.Fatalf("legacy due:\n%s", d.Body)
	}

	// A typed due day ends at 23:59 Warsaw time and the history note shows the same day.
	ctx := context.Background()
	s, host, svc := nginxService(t)
	res, err := s.Create(ctx, CreateRequest{HostID: host.ID, ServiceID: svc.ID, DueDate: "2026-12-22", Channel: "none"}, "ana")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 12, 22, 22, 59, 0, 0, time.UTC); !res.Ticket.DueAt.Equal(want) {
		t.Fatalf("due at %s, want %s", res.Ticket.DueAt.UTC(), want)
	}
	tk2, err := s.UpdateStatus(ctx, res.Ticket.ID, StatusRequest{DueDate: "2027-01-15"}, "ana")
	if err != nil {
		t.Fatal(err)
	}
	if h := tk2.History[len(tk2.History)-1]; h.Note != "due 2027-01-15" {
		t.Fatalf("history note: %q", h.Note)
	}
	if _, err := s.UpdateStatus(ctx, res.Ticket.ID, StatusRequest{DueDate: "01/15/2027"}, "ana"); err == nil {
		t.Fatal("a US date must be refused")
	}
}

func TestSLATableMatchesDefectDojo(t *testing.T) {
	for sev, want := range map[string]int{"critical": 7, "high": 30, "medium": 90, "low": 120, "info": 120, "": 120, "High": 30} {
		if got := DefaultSLA.Days(sev); got != want {
			t.Errorf("%q: %d, want %d", sev, got, want)
		}
	}
	custom := EffectiveSLA(map[string]int{"medium": 60, "bogus": 1})
	if custom.Days("medium") != 60 || custom.Days("high") != 30 || len(custom) != 4 {
		t.Fatalf("overrides: %v", custom)
	}

	// Severities are the ones DefectDojo gets, so the SLA days agree.
	cases := []struct {
		svc  domain.Service
		kind string
		sev  string
		days int
	}{
		{domain.Service{Port: 80, ServiceName: "http", Product: "nginx", Version: "1.20.1"}, KindEOL, "medium", 90},
		{domain.Service{Port: 80, ServiceName: "http", Product: "nginx", Version: "1.18.0 (Ubuntu)"}, KindEOL, "low", 120},
		{domain.Service{Port: 23, ServiceName: "telnet"}, KindCleartextAdmin, "high", 30},
		{domain.Service{Port: 513, ServiceName: "login"}, KindCleartextAdmin, "high", 30},
		{domain.Service{Port: 6379, ServiceName: "redis"}, KindExposure, "high", 30},
		{domain.Service{Port: 3306, ServiceName: "mysql"}, KindExposure, "medium", 90},
		{domain.Service{Port: 8080, ServiceName: "http", IsAdminPanel: true}, KindAdminPanel, "medium", 90},
		{domain.Service{Port: 8080, ServiceName: "http", IsStagingEnv: true}, KindStaging, "low", 120},
	}
	for _, c := range cases {
		svc := c.svc
		svc.HostIP, svc.Protocol = "10.0.0.1", "tcp"
		var got *Issue
		for _, is := range ServiceIssues(&svc, t0) {
			if is.Kind == c.kind {
				is := is
				got = &is
				break
			}
		}
		if got == nil || got.Severity != c.sev || got.DueDays != c.days {
			t.Errorf("%s %s: %+v, want %s / %d days", c.kind, svc.ServiceName, got, c.sev, c.days)
		}
	}
	if defectdojo.EOLSeverity(domain.OutdatedComponent{}) != "Medium" || defectdojo.SeverityPassiveHint != "Medium" {
		t.Fatal("DefectDojo severity mapping changed: update the SLA test")
	}

	// Due day is DefectDojo's SLA expiry (UTC first-seen day plus SLA days), else today plus SLA days.
	due, info := DueFor(DefaultSLA, "medium", "2026-11-21", nginxNow, warsaw)
	if info.Expires != "2027-02-19" || info.Due != "2027-02-19" || !info.FromDefectDojo || info.Expired || locale.Date(due, warsaw) != "2027-02-19" {
		t.Fatalf("medium: %+v", info)
	}
	_, info = DueFor(DefaultSLA, "high", "", nginxNow, warsaw)
	if info.Start != "2026-11-22" || info.Due != "2026-12-22" || info.FromDefectDojo {
		t.Fatalf("no finding: %+v", info)
	}
	// A finding already past its DefectDojo SLA: the owner gets the full SLA from today.
	_, info = DueFor(DefaultSLA, "critical", "2026-10-01", nginxNow, warsaw)
	if !info.Expired || info.Expires != "2026-10-08" || info.Due != "2026-11-29" {
		t.Fatalf("expired: %+v", info)
	}

	// The draft: Medium EOL, 90 days from DefectDojo's date, same as DefectDojo's SLA.
	ctx := context.Background()
	s, host, svc := nginxService(t)
	d, err := s.Draft(ctx, host.ID, svc.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ddExpiry, _ := locale.AddDays(defectdojo.FindingDate(svc.FirstSeen, nginxNow), 90)
	if d.SLA.Days != 90 || d.SLA.Severity != "medium" || d.DueDate != ddExpiry || d.SLA.Start != "2026-11-22" {
		t.Fatalf("draft SLA: %+v due %s, DefectDojo %s", d.SLA, d.DueDate, ddExpiry)
	}
	// A configured table (another DefectDojo SLA configuration) is used instead.
	if err := outbound.Save(ctx, s.store, &outbound.Settings{SLADays: map[string]int{"medium": 45}}, false, false); err != nil {
		t.Fatal(err)
	}
	if d, _ = s.Draft(ctx, host.ID, svc.ID, "", ""); d.SLA.Days != 45 || d.DueDate != "2027-01-06" {
		t.Fatalf("configured SLA: %+v %s", d.SLA, d.DueDate)
	}

	// An existing ticket due 23:59 UTC on 2026-12-20 is drafted and re-sent with that day.
	legacyDue := time.Date(2026, 12, 20, 23, 59, 0, 0, time.UTC)
	if err := s.Repo.Update(ctx, func(ts []Ticket) ([]Ticket, error) {
		return append(ts, Ticket{ID: "old", HostID: host.ID, ServiceID: svc.ID, IssueKey: d.IssueKey, Kind: KindEOL, Status: StatusNotified, DueAt: &legacyDue, CreatedAt: nginxNow.Add(-time.Hour)}), nil
	}); err != nil {
		t.Fatal(err)
	}
	d, _ = s.Draft(ctx, host.ID, svc.ID, "", "")
	if d.Existing == nil || d.DueDate != "2026-12-20" || !strings.Contains(d.Body, "w terminie do 2026-12-20") {
		t.Fatalf("existing ticket due: %s\n%s", d.DueDate, d.Body)
	}
	res, err := s.Create(ctx, CreateRequest{HostID: host.ID, ServiceID: svc.ID, IssueKey: d.IssueKey, Subject: d.Subject, Body: d.Body, DueDate: d.DueDate, Channel: "none"}, "ana")
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || locale.DueDay(*res.Ticket.DueAt, warsaw) != "2026-12-20" {
		t.Fatalf("re-send moved the due date: %v", res.Ticket.DueAt)
	}
}

func TestVerificationOutcomeTypes(t *testing.T) {
	tk := eolTicket()
	cases := []struct {
		name   string
		host   *domain.Host
		fixed  string
		detail string
		reason string
	}{
		{"port closed", eolHost("1.14.0", "closed"), FixedServiceRemoved, "", "no longer reachable from the scanner: port 80/tcp is closed (it may be firewalled rather than removed)"},
		{"port filtered", eolHost("1.14.0", "filtered"), FixedServiceRemoved, "", "port 80/tcp is filtered"},
		{"host deleted", nil, FixedServiceRemoved, "", "no longer in the inventory"},
		{"upgraded", eolHost("1.30.1", "open"), FixedUpgraded, "nginx 1.30.1", "upgraded to nginx 1.30.1, which is no longer end of life"},
		{"version hidden", eolHost("", "open"), FixedIssueGone, "", "no longer visible to the scanner"},
	}
	inactive := eolHost("1.14.0", "open")
	inactive.LifecycleState = domain.HostStateInactive
	cases = append(cases, struct {
		name   string
		host   *domain.Host
		fixed  string
		detail string
		reason string
	}{"host inactive", inactive, FixedServiceRemoved, "", "host no longer answers"})
	gone := eolHost("1.14.0", "open")
	gone.Services = nil
	cases = append(cases, struct {
		name   string
		host   *domain.Host
		fixed  string
		detail string
		reason string
	}{"port gone", gone, FixedServiceRemoved, "", "port 80/tcp is gone from the inventory"})
	for _, c := range cases {
		r := Check(&tk, c.host, t0)
		if !r.Known || r.Present || r.Fixed != c.fixed || r.Detail != c.detail || !strings.Contains(r.Reason, c.reason) {
			t.Errorf("%s: %+v", c.name, r)
		}
	}

	// The labels the UI and the digest show.
	labels := map[string]string{}
	for _, c := range []struct{ reason, detail string }{{FixedServiceRemoved, ""}, {FixedUpgraded, "nginx 1.30.1"}, {FixedIssueGone, ""}, {FixedManual, ""}} {
		labels[c.reason] = FixOutcomeLabel(c.reason, c.detail)
	}
	if labels[FixedServiceRemoved] != "Closed: not reachable" || labels[FixedUpgraded] != "Fixed: upgraded to nginx 1.30.1" ||
		labels[FixedIssueGone] != "Fixed: issue no longer detected" || labels[FixedManual] != "Fixed (marked by an analyst)" {
		t.Fatalf("labels: %v", labels)
	}

	// Verify records the outcome on the ticket and in history; a manual fix says so; reopen clears it.
	ts := []Ticket{eolTicket()}
	hosts := map[string]*domain.Host{"h1": eolHost("1.14.0", "closed")}
	out := Verify(ts, func(id string) (*domain.Host, bool) { return hosts[id], true }, "scan-9", t0, warsaw)
	if len(out) != 1 || out[0].FixedReason != FixedServiceRemoved || ts[0].FixOutcome() != "Closed: not reachable" {
		t.Fatalf("verify: %+v / %+v", out, ts[0])
	}
	h := ts[0].History[len(ts[0].History)-1]
	if h.Action != "verified_fixed" || h.FixedReason != FixedServiceRemoved || !strings.Contains(h.Note, "it may be firewalled") {
		t.Fatalf("history: %+v", h)
	}
	if err := ts[0].SetStatus(StatusReopened, "ana", "back", "", t0); err != nil || ts[0].FixedReason != "" {
		t.Fatalf("reopen must clear the outcome: %v %+v", err, ts[0])
	}
	if err := ts[0].SetStatus(StatusFixed, "ana", "owner says done", "", t0); err != nil || ts[0].FixedReason != FixedManual || ts[0].Verified {
		t.Fatalf("manual fix: %v %+v", err, ts[0])
	}

	// Fixes verified by an older version get their outcome from the note they wrote.
	old := []Ticket{
		{ID: "a", Status: StatusFixed, Verified: true, LastCheckNote: "port 23/tcp is closed"},
		{ID: "b", Status: StatusFixed, Verified: true, LastCheckNote: "version is no longer end of life (now nginx 1.30.1)"},
		{ID: "c", Status: StatusFixed, Verified: true, LastCheckNote: "admin panel is no longer detected"},
		{ID: "d", Status: StatusFixed, Verified: false},
		{ID: "e", Status: StatusFixed, Verified: true, LastCheckNote: "host no longer answers on the network"},
		{ID: "f", Status: StatusFixed, Verified: true, LastCheckNote: "version is no longer end of life (now nginx)"},
	}
	migrate(old)
	want := []string{FixedServiceRemoved, FixedUpgraded, FixedIssueGone, FixedManual, FixedServiceRemoved, FixedIssueGone}
	for i, w := range want {
		if old[i].FixedReason != w {
			t.Errorf("migrate %s: %q, want %q", old[i].ID, old[i].FixedReason, w)
		}
	}
	if old[1].FixedDetail != "nginx 1.30.1" {
		t.Errorf("migrated detail: %q", old[1].FixedDetail)
	}
}
