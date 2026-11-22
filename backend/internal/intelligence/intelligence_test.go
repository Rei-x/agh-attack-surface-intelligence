package intelligence

import (
	"math"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

func TestNoisyORConfidenceAndConflictDetection(t *testing.T) {
	// Exact Noisy-OR formula: 1 - (1 - 0.6)*(1 - 0.5) = 1 - 0.2 = 0.8
	got := NoisyOR([]float64{0.6, 0.5})
	if math.Abs(got-0.8) > 1e-9 {
		t.Fatalf("NoisyOR([0.6, 0.5]) = %f, want 0.8", got)
	}

	ev := []domain.TechEvidence{
		{SignalType: "header", Detail: "Server: nginx/1.24.0", Weight: 0.6},
		{SignalType: "banner", Detail: "product=nginx", Weight: 0.5},
	}
	baseConf := FuseConfidence(ev, 1, false)
	if baseConf != 80 {
		t.Fatalf("baseConf = %d, want 80", baseConf)
	}
	boostedConf := FuseConfidence(ev, 5, false)
	if boostedConf <= baseConf {
		t.Fatalf("expected temporal stability boost (%d > %d)", boostedConf, baseConf)
	}
	conflictConf := FuseConfidence(ev, 1, true)
	if conflictConf >= baseConf {
		t.Fatalf("expected conflict dampening (%d < %d)", conflictConf, baseConf)
	}

	// A banner version that disagrees with the Server header yields conflict evidence.
	eng := signatures.NewEngine(nil)
	obs := domain.ObservedService{
		Port:        80,
		Protocol:    "tcp",
		ServiceName: "http",
		Product:     "nginx",
		Version:     "1.22.0",
		HTTP: &domain.HTTPFingerprint{
			StatusCode:   200,
			ServerHeader: "nginx/1.24.0",
			Headers:      map[string]string{"Server": "nginx/1.24.0"},
		},
	}
	matches := eng.Evaluate(obs)
	techs := DetectTechnologies(obs, matches, 3)

	var foundNginx *domain.DetectedTechnology
	for i := range techs {
		if techs[i].Name == "Nginx" {
			foundNginx = &techs[i]
		}
	}
	if foundNginx == nil {
		t.Fatalf("expected Nginx in detected technologies: %+v", techs)
	}
	hasConflictEv := false
	for _, e := range foundNginx.Evidence {
		if e.SignalType == "conflict" {
			hasConflictEv = true
		}
	}
	if !hasConflictEv {
		t.Fatalf("expected conflict evidence for mismatched versions 1.22.0 vs 1.24.0, got %+v", foundNginx.Evidence)
	}
}

func TestInterestingnessScoring(t *testing.T) {
	svc := &domain.Service{
		Port:         8443,
		Protocol:     "tcp",
		ServiceName:  "https",
		IsAdminPanel: true,
		IsStagingEnv: true,
		HTTP: &domain.HTTPFingerprint{
			MissingSecHeaders:  []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"},
			InterestingHeaders: []string{"X-Debug-Mode: 1", "WWW-Authenticate: Basic"},
			Cookies: []domain.CookieInfo{
				{Name: "PHPSESSID", Flags: []string{"missing_httponly", "missing_secure"}},
			},
			TLS: &domain.TLSInfo{
				IsExpired:    true,
				IsSelfSigned: true,
				DaysToExpiry: -5,
			},
		},
	}

	// Admin panel + staging + debug headers are strong-ish signals and land in the medium
	// band; five hygiene findings on top add at most domain.HygieneCap, never a band jump to
	// critical.
	score, factors := ScoreService(svc, nil)
	if score < 55 || score >= 75 {
		t.Fatalf("expected a medium score [55..75), got %d (factors=%+v)", score, factors)
	}
	if len(factors) < 5 {
		t.Fatalf("expected transparent breakdown >= 5 factors, got %+v", factors)
	}
	sum, hygiene := 0, 0
	for _, f := range factors {
		sum += f.Points
		if f.Kind == domain.FactorKindHygiene {
			hygiene += f.Points
		}
	}
	if sum != score || hygiene > domain.HygieneCap {
		t.Fatalf("points add up to %d (score %d), hygiene %d (cap %d)", sum, score, hygiene, domain.HygieneCap)
	}
}

func TestHostLifecycleTransitionsAndGracePeriod(t *testing.T) {
	cfg := LifecycleConfig{MissingThreshold: 3, GracePeriodHours: 72}
	t0 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)

	host := &domain.Host{ID: "h-1", IP: "10.0.0.5"}

	// 1. First seen -> NEW
	r1 := EvaluateHostLifecycle(host, true, t0, cfg)
	if r1.NewState != domain.HostStateNew {
		t.Fatalf("step 1 state = %s, want NEW", r1.NewState)
	}

	// 2. Second seen -> ACTIVE
	r2 := EvaluateHostLifecycle(host, true, t0.Add(2*time.Hour), cfg)
	if r2.NewState != domain.HostStateActive {
		t.Fatalf("step 2 state = %s, want ACTIVE", r2.NewState)
	}

	// 3. Three misses inside the 72h grace period stay MISSING, not INACTIVE.
	for i := 1; i <= 3; i++ {
		r := EvaluateHostLifecycle(host, false, t0.Add(time.Duration(2+i*4)*time.Hour), cfg)
		if r.NewState != domain.HostStateMissing {
			t.Fatalf("miss #%d within grace period: state = %s, want MISSING", i, r.NewState)
		}
	}

	// 4. A fourth miss past the grace period, with >= 3 misses, is INACTIVE.
	rInactive := EvaluateHostLifecycle(host, false, t0.Add(76*time.Hour), cfg)
	if rInactive.NewState != domain.HostStateInactive {
		t.Fatalf("after grace period: state = %s, want INACTIVE", rInactive.NewState)
	}

	// 5. Back online -> REACTIVATED
	rReact := EvaluateHostLifecycle(host, true, t0.Add(80*time.Hour), cfg)
	if rReact.NewState != domain.HostStateReactivated {
		t.Fatalf("after recovery from INACTIVE: state = %s, want REACTIVATED", rReact.NewState)
	}

	// 6. A flapping host becomes INTERMITTENT.
	flapper := &domain.Host{ID: "h-2", IP: "10.0.0.6"}
	EvaluateHostLifecycle(flapper, true, t0, cfg)                   // NEW
	EvaluateHostLifecycle(flapper, true, t0.Add(time.Hour), cfg)    // ACTIVE
	EvaluateHostLifecycle(flapper, false, t0.Add(2*time.Hour), cfg) // MISSING (transitions=1)
	rFlap := EvaluateHostLifecycle(flapper, true, t0.Add(3*time.Hour), cfg)
	if rFlap.NewState != domain.HostStateIntermittent {
		t.Fatalf("flapping host state = %s, want INTERMITTENT", rFlap.NewState)
	}
	if flapper.StabilityScore >= 90 {
		t.Fatalf("expected reduced stability score for intermittent host, got %d", flapper.StabilityScore)
	}
}

func TestTimeOfDayExpectedOffHoursVsTimeAnomaly(t *testing.T) {
	cfg := DefaultLifecycleConfig()
	host := &domain.Host{ID: "h-lab", IP: "10.10.5.20"}

	// Four days ON in the morning slot (06-12) and OFF at night (00-06).
	baseDay := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	for d := 0; d < 4; d++ {
		day := baseDay.AddDate(0, 0, d)
		EvaluateHostLifecycle(host, true, day.Add(9*time.Hour), cfg)  // 09:00 -> ON
		EvaluateHostLifecycle(host, false, day.Add(2*time.Hour), cfg) // 02:00 -> OFF
	}

	// Day 5, 02:00 OFF: expected off-hours, not an anomaly.
	day5 := baseDay.AddDate(0, 0, 5)
	rExpected := EvaluateHostLifecycle(host, false, day5.Add(2*time.Hour), cfg)
	if !rExpected.IsExpectedSchedule || rExpected.IsTimeAnomaly {
		t.Fatalf("expected off-hours schedule at 02:00 OFF, got expected=%v anomaly=%v", rExpected.IsExpectedSchedule, rExpected.IsTimeAnomaly)
	}

	// Day 6, 02:00 ON: time anomaly.
	day6 := baseDay.AddDate(0, 0, 6)
	rAnomaly := EvaluateHostLifecycle(host, true, day6.Add(2*time.Hour), cfg)
	if !rAnomaly.IsTimeAnomaly {
		t.Fatalf("expected TIME_ANOMALY when night-offline host turns ON at 02:00, got %+v", rAnomaly)
	}

	// Day 6, 09:00 OFF: time anomaly.
	rDayAnomaly := EvaluateHostLifecycle(host, false, day6.Add(9*time.Hour), cfg)
	if !rDayAnomaly.IsTimeAnomaly {
		t.Fatalf("expected TIME_ANOMALY when daytime-online host goes OFF at 09:00, got %+v", rDayAnomaly)
	}
}

func TestScanDiffAndServiceClustering(t *testing.T) {
	prev := []domain.Host{
		{
			ID: "h1", IP: "10.0.0.1", LifecycleState: domain.HostStateActive,
			Services: []domain.Service{
				{
					ID: "s1", HostID: "h1", HostIP: "10.0.0.1", Port: 80, Protocol: "tcp",
					ServiceName: "http", Product: "nginx", Version: "1.22.0",
					HTTP: &domain.HTTPFingerprint{Title: "Old Portal", StatusCode: 200, TLS: &domain.TLSInfo{SHA256: "aaa"}},
				},
				{
					ID: "s2", HostID: "h1", HostIP: "10.0.0.1", Port: 22, Protocol: "tcp",
					ServiceName: "ssh", Product: "OpenSSH", Version: "8.9",
				},
			},
		},
		{
			ID: "h2", IP: "10.0.0.2", LifecycleState: domain.HostStateActive,
		},
	}

	curr := []domain.Host{
		{
			ID: "h1", IP: "10.0.0.1", LifecycleState: domain.HostStateActive,
			Services: []domain.Service{
				{
					ID: "s1", HostID: "h1", HostIP: "10.0.0.1", Port: 80, Protocol: "tcp",
					ServiceName: "http", Product: "nginx", Version: "1.24.0", // changed
					HTTP: &domain.HTTPFingerprint{Title: "New Portal", StatusCode: 200, TLS: &domain.TLSInfo{SHA256: "bbb"}}, // title and TLS changed
				},
				{
					ID: "s3", HostID: "h1", HostIP: "10.0.0.1", Port: 8443, Protocol: "tcp",
					ServiceName: "https", IsAdminPanel: true, // new service
				},
			},
		},
		{
			ID: "h3", IP: "10.0.0.3", LifecycleState: domain.HostStateNew, // new host
		},
	}

	events, report := ComputeDiff("scan-2", "scan-1", prev, curr, time.Date(2026, 5, 2, 14, 0, 0, 0, time.UTC))
	if len(events) == 0 {
		t.Fatalf("expected non-empty change events")
	}
	if report.Summary.NewHosts != 1 || report.Summary.MissingHosts != 1 {
		t.Fatalf("unexpected host diff summary: %+v", report.Summary)
	}
	if report.Summary.NewServices != 1 || report.Summary.ClosedServices != 1 {
		t.Fatalf("unexpected service open/close summary: %+v", report.Summary)
	}
	if report.Summary.ChangedServices < 3 {
		t.Fatalf("expected >= 3 changed service events (version, title, tls), got %d", report.Summary.ChangedServices)
	}

	// Clustering by favicon, tech_stack, http_title and tls_issuer.
	clusterServices := []domain.Service{
		{
			ID: "c1", HostIP: "10.0.1.1", Port: 443, Interestingness: 60,
			HTTP: &domain.HTTPFingerprint{
				FaviconMMH3: "1943789861",
				Title:       "Grafana",
				TLS:         &domain.TLSInfo{Issuer: "AGH Internal CA"},
			},
			Technologies: []domain.DetectedTechnology{{Name: "Grafana"}, {Name: "Nginx"}},
		},
		{
			ID: "c2", HostIP: "10.0.1.2", Port: 443, Interestingness: 75,
			HTTP: &domain.HTTPFingerprint{
				FaviconMMH3: "1943789861",
				Title:       "Grafana",
				TLS:         &domain.TLSInfo{Issuer: "AGH Internal CA"},
			},
			Technologies: []domain.DetectedTechnology{{Name: "Nginx"}, {Name: "Grafana"}},
		},
		{
			ID: "c3", HostIP: "10.0.1.3", Port: 80, Interestingness: 20,
			HTTP: &domain.HTTPFingerprint{
				FaviconMMH3: "999999",
				Title:       "Unique App",
			},
		},
	}

	clusters := ComputeClusters(clusterServices)
	seenGroups := make(map[string]bool)
	for _, cl := range clusters {
		seenGroups[cl.GroupBy] = true
		if cl.Count != 2 {
			t.Fatalf("expected cluster count 2 for %s, got %d", cl.ClusterKey, cl.Count)
		}
		if cl.MaxScore != 75 {
			t.Fatalf("expected cluster max score 75, got %d", cl.MaxScore)
		}
	}
	for _, want := range []string{"favicon", "tech_stack", "http_title", "tls_issuer"} {
		if !seenGroups[want] {
			t.Fatalf("expected cluster grouped by %q, got clusters=%+v", want, clusters)
		}
	}
}
