package signatures

import (
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestAllBuiltinsValidAndSufficientCount(t *testing.T) {
	builtins := BuiltinSignatures()
	if len(builtins) < 45 {
		t.Fatalf("expected at least 45 built-in signatures, got %d", len(builtins))
	}

	seenIDs := make(map[string]bool)
	for _, sig := range builtins {
		if sig.ID == "" {
			t.Fatalf("builtin signature %q missing ID", sig.Name)
		}
		if seenIDs[sig.ID] {
			t.Fatalf("duplicate builtin signature ID %q", sig.ID)
		}
		seenIDs[sig.ID] = true

		vr := ValidateSignature(sig)
		if !vr.Valid {
			t.Fatalf("builtin signature %q (%s) failed validation: %v", sig.Name, sig.ID, vr.Errors)
		}
	}
}

func TestSafetyValidatorRejectsUnsafeSignatures(t *testing.T) {
	cases := []struct {
		name string
		sig  domain.Signature
	}{
		{
			name: "mutating HTTP POST",
			sig: domain.Signature{
				Name:             "Bad POST rule",
				Category:         "custom",
				MatchMode:        "any",
				ConfidenceWeight: 0.7,
				Matchers:         []domain.SignatureMatcher{{Type: "safe_path", Key: "POST /login", Pattern: "POST /login"}},
			},
		},
		{
			name: "credential brute force payload",
			sig: domain.Signature{
				Name:             "Login attempt",
				Category:         "custom",
				MatchMode:        "any",
				ConfidenceWeight: 0.7,
				Matchers:         []domain.SignatureMatcher{{Type: "html_body", Pattern: "password=admin123"}},
			},
		},
		{
			name: "Authorization Basic header",
			sig: domain.Signature{
				Name:             "Auth header",
				Category:         "custom",
				MatchMode:        "any",
				ConfidenceWeight: 0.7,
				Matchers:         []domain.SignatureMatcher{{Type: "header", Key: "Authorization", Pattern: "Authorization: Basic YWRtaW4="}},
			},
		},
		{
			name: "path traversal",
			sig: domain.Signature{
				Name:             "Traversal",
				Category:         "custom",
				MatchMode:        "any",
				ConfidenceWeight: 0.7,
				Matchers:         []domain.SignatureMatcher{{Type: "safe_path", Key: "/../../etc/passwd", Pattern: "/../../etc/passwd"}},
			},
		},
		{
			name: "external URL in safe_path",
			sig: domain.Signature{
				Name:             "SSRF path",
				Category:         "custom",
				MatchMode:        "any",
				ConfidenceWeight: 0.7,
				Matchers:         []domain.SignatureMatcher{{Type: "safe_path", Key: "http://169.254.169.254/latest", Pattern: "http://169.254.169.254/latest"}},
			},
		},
		{
			name: "invalid regex",
			sig: domain.Signature{
				Name:             "Broken Regex",
				Category:         "custom",
				MatchMode:        "any",
				ConfidenceWeight: 0.7,
				Matchers:         []domain.SignatureMatcher{{Type: "html_body", Pattern: "[unclosed", Regex: true}},
			},
		},
		{
			name: "nested quantifier ReDoS",
			sig: domain.Signature{
				Name:             "ReDoS",
				Category:         "custom",
				MatchMode:        "any",
				ConfidenceWeight: 0.7,
				Matchers:         []domain.SignatureMatcher{{Type: "html_body", Pattern: `(a+)+b`, Regex: true}},
			},
		},
		{
			name: "version group out of bounds",
			sig: domain.Signature{
				Name:             "Bad Group",
				Category:         "custom",
				MatchMode:        "any",
				ConfidenceWeight: 0.7,
				Matchers:         []domain.SignatureMatcher{{Type: "header", Key: "Server", Pattern: `nginx/(\d+)`, Regex: true, VersionGroup: 3}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vr := ValidateSignature(tc.sig)
			if vr.Valid {
				t.Fatalf("expected signature %q to be REJECTED by safety validator, but it passed", tc.name)
			}
		})
	}
}

func TestEngineEvaluateMatchModesAndVersionCapture(t *testing.T) {
	customAll := domain.Signature{
		ID:               "custom-agh-portal",
		Name:             "AGH Internal Portal",
		Category:         "custom",
		MatchMode:        "all",
		ConfidenceWeight: 0.90,
		InterestingPts:   15,
		Enabled:          true,
		Matchers: []domain.SignatureMatcher{
			{Type: "title", Pattern: `AGH.*Portal`, Regex: true},
			{Type: "header", Key: "X-AGH-App", Pattern: `portal-v([0-9]+\.[0-9]+)`, Regex: true, VersionGroup: 1},
		},
	}

	eng := NewEngine([]domain.Signature{customAll})

	svc := domain.ObservedService{
		Port:        443,
		Protocol:    "tcp",
		State:       "open",
		ServiceName: "https",
		HTTP: &domain.HTTPFingerprint{
			URL:           "https://staging.portal.agh.edu.pl/",
			Scheme:        "https",
			StatusCode:    200,
			Title:         "AGH Staging Portal",
			ServerHeader:  "nginx/1.24.0",
			MetaGenerator: "WordPress 6.4.2",
			Headers: map[string]string{
				"Server":       "nginx/1.24.0",
				"X-AGH-App":    "portal-v2.5",
				"X-Powered-By": "PHP/8.2.10",
			},
			SafePathHits: []domain.SafePathHit{
				{Path: "/wp-login.php", StatusCode: 200},
				{Path: "/admin", StatusCode: 401},
			},
		},
	}

	matches := eng.Evaluate(svc)
	byName := make(map[string]MatchResult)
	for _, m := range matches {
		byName[m.Signature.Name] = m
	}

	if wp, ok := byName["WordPress"]; !ok || wp.Version != "6.4.2" {
		t.Fatalf("expected WordPress 6.4.2 match, got %+v", wp)
	}
	if nx, ok := byName["Nginx"]; !ok || nx.Version != "1.24.0" {
		t.Fatalf("expected Nginx 1.24.0 match, got %+v", nx)
	}
	if _, ok := byName["Staging / Dev / Test Environment"]; !ok {
		t.Fatalf("expected Staging / Dev / Test Environment match")
	}
	if agh, ok := byName["AGH Internal Portal"]; !ok || agh.Version != "2.5" {
		t.Fatalf("expected custom all-mode signature match with version 2.5, got %+v", agh)
	}

	// If header is removed, match_mode="all" must NOT match.
	delete(svc.HTTP.Headers, "X-AGH-App")
	res := EvaluateOne(customAll, svc)
	if res.Matched {
		t.Fatalf("expected match_mode='all' to fail when one matcher misses")
	}
}

func TestRetroactivePlaygroundAndImportExport(t *testing.T) {
	sig := domain.Signature{
		ID:               "custom-grafana-fav",
		Name:             "Grafana Favicon Match",
		Category:         "server",
		MatchMode:        "any",
		ConfidenceWeight: 0.90,
		InterestingPts:   10,
		Enabled:          true,
		Matchers: []domain.SignatureMatcher{
			{Type: "favicon_mmh3", Pattern: "1943789861"},
		},
	}

	services := []domain.Service{
		{
			ID: "svc-1", HostID: "h-1", HostIP: "10.0.0.10", Port: 3000, ServiceName: "http",
			HTTP: &domain.HTTPFingerprint{FaviconMMH3: "1943789861", Title: "Grafana"},
		},
		{
			ID: "svc-2", HostID: "h-2", HostIP: "10.0.0.11", Port: 80, ServiceName: "http",
			HTTP: &domain.HTTPFingerprint{FaviconMMH3: "-12345", Title: "Other"},
		},
	}

	hits, vr := RetroactiveTest(sig, services)
	if !vr.Valid {
		t.Fatalf("expected valid signature, got errors: %v", vr.Errors)
	}
	if len(hits) != 1 || hits[0].ServiceID != "svc-1" {
		t.Fatalf("expected 1 retroactive hit on svc-1, got %+v", hits)
	}

	// JSON Export & Import roundtrip, including rejection of an unsafe entry.
	unsafeSig := domain.Signature{
		Name:             "Unsafe",
		Category:         "custom",
		MatchMode:        "any",
		ConfidenceWeight: 0.5,
		Matchers:         []domain.SignatureMatcher{{Type: "safe_path", Key: "/../secret", Pattern: "/../secret"}},
	}
	data, err := ExportJSON([]domain.Signature{sig, unsafeSig})
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}
	imported, rejected, err := ImportJSON(data)
	if err != nil {
		t.Fatalf("ImportJSON failed: %v", err)
	}
	if len(imported) != 1 || imported[0].Name != "Grafana Favicon Match" {
		t.Fatalf("expected 1 valid imported signature, got %+v", imported)
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0], "Unsafe") {
		t.Fatalf("expected 1 rejected unsafe signature, got %v", rejected)
	}
}
