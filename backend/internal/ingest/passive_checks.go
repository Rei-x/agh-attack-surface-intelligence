package ingest

import (
	"regexp"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Passive follow-up checks: the "cascading scan" step that secureCodeBox delegates to
// sslyze / ssh-audit, done here only from data the scan already captured (the TLS
// handshake of the HTTP fingerprint and the SSH version banner). No extra packets, no
// authentication attempts. Names and categories follow the secureCodeBox sslyze and
// ssh-audit parsers so the findings read the same in SCB tooling or DefectDojo.

// PassiveFinding is one derived observation about a service.
type PassiveFinding struct {
	Name        string
	Category    string
	Severity    string // INFORMATIONAL, LOW, MEDIUM, HIGH (secureCodeBox scale)
	Description string
	Mitigation  string
	OSILayer    string
	Attributes  map[string]any
}

// deprecatedTLS mirrors DEPRECATED_VERSIONS in the secureCodeBox sslyze parser.
var deprecatedTLS = map[string]bool{"SSL 2.0": true, "SSL 3.0": true, "TLS 1.0": true, "TLS 1.1": true}

// TLSPassiveFindings summarises the TLS handshake captured during HTTP fingerprinting.
// The version is the one negotiated by a modern client, i.e. the highest the server
// offers: a deprecated value means the server cannot do TLS 1.2+ at all.
func TLSPassiveFindings(t *domain.TLSInfo) []PassiveFinding {
	if t == nil || (t.Version == "" && t.SHA256 == "") {
		return nil
	}
	info := map[string]any{
		"tls_versions":   nonEmptyList(t.Version),
		"cipher_suites":  nonEmptyList(t.CipherSuite),
		"subject_cn":     t.SubjectCN,
		"issuer":         t.Issuer,
		"days_to_expiry": t.DaysToExpiry,
		"cert_sha256":    t.SHA256,
	}
	if !t.NotAfter.IsZero() {
		info["not_after"] = t.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
	}
	if t.JARM != "" {
		info["jarm"] = t.JARM
	}
	out := []PassiveFinding{{
		Name:        "TLS Service",
		Category:    "TLS Service Info",
		Severity:    "INFORMATIONAL",
		Description: "TLS parameters observed passively during the HTTP fingerprint handshake.",
		OSILayer:    "PRESENTATION",
		Attributes:  info,
	}}
	if deprecatedTLS[t.Version] {
		out = append(out, PassiveFinding{
			Name:        "TLS Version " + t.Version + " is considered insecure",
			Category:    "Outdated TLS Version",
			Severity:    "MEDIUM",
			Description: "The server negotiated " + t.Version + " with a client offering TLS 1.3, so it does not support a current TLS version.",
			Mitigation:  "Upgrade to a higher tls version.",
			OSILayer:    "PRESENTATION",
			Attributes:  map[string]any{"outdated_version": t.Version},
		})
	}
	if t.IsSelfSigned {
		out = append(out, PassiveFinding{
			Name: "Self-Signed Certificate", Category: "Invalid Certificate", Severity: "MEDIUM",
			Description: "Certificate is self-signed", OSILayer: "PRESENTATION",
			Attributes: map[string]any{"subject_cn": t.SubjectCN, "issuer": t.Issuer},
		})
	}
	if t.IsExpired {
		out = append(out, PassiveFinding{
			Name: "Expired Certificate", Category: "Invalid Certificate", Severity: "MEDIUM",
			Description: "Certificate has expired", OSILayer: "PRESENTATION",
			Attributes: map[string]any{"subject_cn": t.SubjectCN, "not_after": info["not_after"]},
		})
	}
	return out
}

var sshProtoInExtra = regexp.MustCompile(`(?i)protocol\s+([0-9.]+)`)

// SSHBanner parses an SSH identification string ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3") or the
// nmap -sV fields of an ssh service into protocol version and software.
func SSHBanner(s domain.Service) (raw, protocol, software string, ok bool) {
	b := strings.TrimSpace(s.Banner)
	if strings.HasPrefix(b, "SSH-") {
		parts := strings.SplitN(strings.SplitN(b, "\n", 2)[0], "-", 3)
		if len(parts) == 3 {
			return strings.TrimSpace(strings.SplitN(b, "\n", 2)[0]), parts[1], strings.TrimSpace(parts[2]), true
		}
	}
	if !strings.EqualFold(s.ServiceName, "ssh") {
		return "", "", "", false
	}
	if m := sshProtoInExtra.FindStringSubmatch(b); m != nil {
		protocol = m[1]
	}
	software = strings.TrimSpace(s.Product + " " + s.Version)
	return b, protocol, software, true
}

// SSHPassiveFindings is the banner-only part of an ssh-audit run: the advertised protocol
// version and software. Algorithm lists would need a key exchange, which we do not do.
func SSHPassiveFindings(s domain.Service) []PassiveFinding {
	raw, proto, software, ok := SSHBanner(s)
	if !ok {
		return nil
	}
	out := []PassiveFinding{{
		Name:        "SSH Service",
		Category:    "SSH Service",
		Severity:    "INFORMATIONAL",
		Description: "SSH server identification observed passively (banner only, no authentication).",
		OSILayer:    "APPLICATION",
		Attributes: map[string]any{
			"server_banner": nilIfEmpty(raw),
			"ssh_version":   nilIfEmpty(proto),
			"ssh_software":  nilIfEmpty(software),
		},
	}}
	// "1.99" means SSH-1 is still accepted next to SSH-2; "1.5"/"1.3" are SSH-1 only.
	if strings.HasPrefix(proto, "1.") {
		out = append(out, PassiveFinding{
			Name:        "Insecure SSH Protocol Version " + proto,
			Category:    "SSH Policy Violation",
			Severity:    "HIGH",
			Description: "The server accepts SSH protocol version 1, which has known cryptographic weaknesses.",
			Mitigation:  "Disable SSH protocol 1 (Protocol 2 only).",
			OSILayer:    "APPLICATION",
			Attributes:  map[string]any{"ssh_version": proto},
		})
	}
	return out
}

func nonEmptyList(v string) []string {
	if v == "" {
		return []string{}
	}
	return []string{v}
}

func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
