package intelligence

import (
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestConfidenceWeakSignalsCannotExceed80(t *testing.T) {
	// A signature author may claim 0.9, but one safe-path hit is weak evidence.
	path := []domain.TechEvidence{{SignalType: "path", Detail: "safe_path /metrics -> 200", Weight: 0.9}}
	if c := FuseConfidence(path, 1, false); c > 25 {
		t.Fatalf("single safe-path hit = %d%%, want <= 25%%", c)
	}
	header := []domain.TechEvidence{{SignalType: "header", Detail: "Server: nginx", Weight: 0.97}}
	if c := FuseConfidence(header, 5, false); c > 80 {
		t.Fatalf("single header (even with temporal boost) = %d%%, want <= 80%%", c)
	}
	// Three correlated markers in the same HTML body are one witness, not three.
	html := []domain.TechEvidence{
		{SignalType: "html", Detail: "meta generator WordPress", Weight: 0.9},
		{SignalType: "html", Detail: "wp-content", Weight: 0.9},
		{SignalType: "html", Detail: "wp-json", Weight: 0.9},
	}
	if c := FuseConfidence(html, 1, false); c > 80 {
		t.Fatalf("same-channel evidence = %d%%, want <= 80%%", c)
	}
}

func TestConfidenceCorroborationRaisesScore(t *testing.T) {
	one := []domain.TechEvidence{{SignalType: "html", Detail: "meta generator WordPress 6.4", Weight: 0.9}}
	two := append(one, domain.TechEvidence{SignalType: "cookie", Detail: "wordpress_test_cookie", Weight: 0.9})
	three := append(two, domain.TechEvidence{SignalType: "path", Detail: "safe_path /wp-login.php -> 200", Weight: 0.9})
	c1, c2 := FuseConfidence(one, 1, false), FuseConfidence(two, 1, false)
	c3, expl := FuseConfidenceExplained(three, 1, false)
	if !(c1 < c2 && c2 < c3) || c2 < 90 {
		t.Fatalf("independent channels must corroborate: %d < %d < %d (two channels >= 90)", c1, c2, c3)
	}
	if !strings.Contains(expl, "⊕") || !strings.Contains(expl, "html 0.80") || !strings.Contains(expl, "cookie 0.75") {
		t.Fatalf("explanation should show per-channel weights: %q", expl)
	}
	if c3 > 99 {
		t.Fatal("confidence must never claim certainty")
	}
}

func TestEveryChannelHasDocumentedWeight(t *testing.T) {
	for _, ch := range []string{"banner", "favicon", "header", "html", "cookie", "tls", "path", "signature"} {
		w, ok := EvidenceChannels[ch]
		if !ok || w.Cap <= 0 || w.Cap > 0.9 || w.Rationale == "" {
			t.Fatalf("channel %q lacks a documented weight: %+v", ch, w)
		}
		if ch != "banner" && w.Cap > SingleChannelCeiling {
			t.Fatalf("channel %q cap %.2f exceeds single-channel ceiling", ch, w.Cap)
		}
	}
}

func TestDetectTechnologiesExposesExplanation(t *testing.T) {
	obs := domain.ObservedService{Port: 80, HTTP: &domain.HTTPFingerprint{ServerHeader: "nginx/1.24.0"}}
	techs := DetectTechnologies(obs, nil, 1)
	if len(techs) != 1 || techs[0].Explanation == "" || techs[0].Confidence > 80 {
		t.Fatalf("expected single-channel nginx with explanation and <=80%%, got %+v", techs)
	}
}
