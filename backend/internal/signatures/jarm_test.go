package signatures

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const testJARM = "21d19d00021d21d00042d43d00000091f9827a8676a9d9f27d421962a09b5d"

func jarmSig(pattern string, regex bool) domain.Signature {
	return domain.Signature{
		ID: "custom-jarm", Name: "Lab nginx TLS stack", Category: "server", MatchMode: "any",
		ConfidenceWeight: 0.5, Enabled: true,
		Matchers: []domain.SignatureMatcher{{Type: "jarm", Pattern: pattern, Regex: regex}},
	}
}

func TestJARMMatcherEqualityAndValidation(t *testing.T) {
	if vr := ValidateSignature(jarmSig(testJARM, false)); !vr.Valid {
		t.Fatalf("valid jarm signature rejected: %v", vr.Errors)
	}
	if vr := ValidateSignature(jarmSig("nginx", false)); vr.Valid {
		t.Fatal("non-hex jarm equality pattern must be rejected")
	}
	if vr := ValidateSignature(jarmSig("^21d19d", true)); !vr.Valid {
		t.Fatalf("jarm regex prefix rejected: %v", vr.Errors)
	}

	svc := domain.ObservedService{Port: 443, HTTP: &domain.HTTPFingerprint{TLS: &domain.TLSInfo{JARM: testJARM}}}
	other := domain.ObservedService{Port: 443, HTTP: &domain.HTTPFingerprint{TLS: &domain.TLSInfo{JARM: "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d"}}}
	noTLS := domain.ObservedService{Port: 80, HTTP: &domain.HTTPFingerprint{}}

	for _, sig := range []domain.Signature{jarmSig(testJARM, false), jarmSig("^21d19d", true)} {
		eng := NewEngineFromList([]domain.Signature{sig})
		hit := func(s domain.ObservedService) bool {
			for _, m := range eng.Evaluate(s) {
				if m.Matched && m.Signature.ID == "custom-jarm" {
					if len(m.Evidence) == 0 || m.Evidence[0].SignalType != "tls" {
						t.Fatalf("jarm evidence should be signal type tls, got %+v", m.Evidence)
					}
					return true
				}
			}
			return false
		}
		if !hit(svc) {
			t.Fatalf("signature %+v should match", sig.Matchers[0])
		}
		if hit(other) || hit(noTLS) {
			t.Fatalf("signature %+v must not match other JARM / non-TLS", sig.Matchers[0])
		}
	}
}
