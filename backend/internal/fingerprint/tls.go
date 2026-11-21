package fingerprint

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ExtractTLSInfo extracts certificate and TLS negotiation metadata from a ConnectionState.
func ExtractTLSInfo(state *tls.ConnectionState, now time.Time) *domain.TLSInfo {
	if state == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	info := &domain.TLSInfo{
		Version:     tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}

	if len(state.PeerCertificates) == 0 {
		return info
	}

	cert := state.PeerCertificates[0]
	info.SubjectCN = cert.Subject.CommonName
	if info.SubjectCN == "" {
		info.SubjectCN = cert.Subject.String()
	}
	info.Issuer = formatIssuer(cert)
	info.SANs = extractSANs(cert)
	info.NotBefore = cert.NotBefore.UTC()
	info.NotAfter = cert.NotAfter.UTC()

	days := math.Floor(cert.NotAfter.Sub(now).Hours() / 24.0)
	info.DaysToExpiry = int(days)
	info.IsExpired = now.After(cert.NotAfter) || now.Before(cert.NotBefore)
	info.IsSelfSigned = isSelfSignedCert(cert)

	sum := sha256.Sum256(cert.Raw)
	info.SHA256 = hex.EncodeToString(sum[:])

	return info
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func formatIssuer(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	parts := make([]string, 0, 2)
	if len(cert.Issuer.Organization) > 0 && strings.TrimSpace(cert.Issuer.Organization[0]) != "" {
		parts = append(parts, strings.TrimSpace(cert.Issuer.Organization[0]))
	}
	if strings.TrimSpace(cert.Issuer.CommonName) != "" {
		cn := strings.TrimSpace(cert.Issuer.CommonName)
		if len(parts) == 0 || parts[0] != cn {
			parts = append(parts, cn)
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, " - ")
	}
	return cert.Issuer.String()
}

func extractSANs(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var sans []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			sans = append(sans, s)
		}
	}
	for _, dns := range cert.DNSNames {
		add(dns)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	for _, email := range cert.EmailAddresses {
		add(email)
	}
	return sans
}

func isSelfSignedCert(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	if err := cert.CheckSignatureFrom(cert); err == nil {
		return true
	}
	return len(cert.AuthorityKeyId) == 0 || string(cert.AuthorityKeyId) == string(cert.SubjectKeyId)
}
