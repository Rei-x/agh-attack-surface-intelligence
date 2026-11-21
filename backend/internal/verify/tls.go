package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Built-in TLS probes: plain handshakes, nothing else is sent.

func (e *Engine) runBuiltin(ctx context.Context, c *Check, t *Target) (bool, string, string, error) {
	_, hostPort := baseURL(t)
	switch c.Builtin {
	case "tls-protocols":
		return e.tlsProtocols(ctx, hostPort, t.HostIP)
	case "tls-certificate":
		return e.tlsCertificate(ctx, hostPort, t.HostIP)
	}
	return false, "", "", fmt.Errorf("unknown builtin %q", c.Builtin)
}

func (e *Engine) handshake(ctx context.Context, hostPort, host string, cfg *tls.Config) (*tls.ConnectionState, error) {
	if err := e.wait(ctx, host); err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: e.timeout()}
	raw, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(e.timeout()))
	cfg.InsecureSkipVerify = true //nolint:gosec // inspecting, not trusting
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	st := tc.ConnectionState()
	return &st, nil
}

// tlsProtocols confirms legacy protocol versions (TLS 1.0 / 1.1) or insecure cipher suites
// (RC4, 3DES, CBC with RSA key exchange as offered by Go's insecure list) are accepted.
func (e *Engine) tlsProtocols(ctx context.Context, hostPort, host string) (bool, string, string, error) {
	var issues, tried []string
	reachable := false
	for _, v := range []struct {
		ver  uint16
		name string
	}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}} {
		tried = append(tried, "ClientHello "+v.name+" only")
		st, err := e.handshake(ctx, hostPort, host, &tls.Config{MinVersion: v.ver, MaxVersion: v.ver})
		if err == nil {
			reachable = true
			issues = append(issues, fmt.Sprintf("%s accepted (negotiated %s)", v.name, tls.CipherSuiteName(st.CipherSuite)))
		}
	}
	var weak []uint16
	for _, cs := range tls.InsecureCipherSuites() {
		for _, v := range cs.SupportedVersions {
			if v == tls.VersionTLS12 {
				weak = append(weak, cs.ID)
				break
			}
		}
	}
	if len(weak) > 0 {
		tried = append(tried, "ClientHello TLS 1.2 offering only insecure cipher suites (RC4, 3DES, CBC-SHA256)")
		st, err := e.handshake(ctx, hostPort, host, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: weak})
		if err == nil {
			reachable = true
			issues = append(issues, "insecure cipher suite accepted: "+tls.CipherSuiteName(st.CipherSuite))
		}
	}
	_ = reachable
	if len(issues) == 0 {
		return false, "", "", nil
	}
	return true, "tls://" + hostPort + "\n" + strings.Join(tried, "\n"), strings.Join(issues, "\n"), nil
}

// tlsCertificate confirms certificate problems: expired / not yet valid, self-signed, weak
// key, SHA-1 or MD5 signature.
func (e *Engine) tlsCertificate(ctx context.Context, hostPort, host string) (bool, string, string, error) {
	st, err := e.handshake(ctx, hostPort, host, &tls.Config{MinVersion: tls.VersionTLS10})
	if err != nil {
		return false, "", "", err
	}
	if len(st.PeerCertificates) == 0 {
		return false, "", "", nil
	}
	leaf := st.PeerCertificates[0]
	now := e.now()
	var issues []string
	switch {
	case now.After(leaf.NotAfter):
		issues = append(issues, fmt.Sprintf("expired on %s (%d days ago)", leaf.NotAfter.UTC().Format("2006-01-02"), int(now.Sub(leaf.NotAfter).Hours()/24)))
	case now.Before(leaf.NotBefore):
		issues = append(issues, "not valid before "+leaf.NotBefore.UTC().Format("2006-01-02"))
	}
	if isSelfSigned(leaf) {
		issues = append(issues, "self-signed (issuer equals subject and the signature verifies with its own key)")
	}
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			issues = append(issues, fmt.Sprintf("weak RSA key: %d bits", k.N.BitLen()))
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			issues = append(issues, fmt.Sprintf("weak ECDSA key: %d bits", k.Curve.Params().BitSize))
		}
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.MD5WithRSA, x509.MD2WithRSA:
		issues = append(issues, "weak signature algorithm: "+leaf.SignatureAlgorithm.String())
	}
	if len(issues) == 0 {
		return false, "", "", nil
	}
	ev := fmt.Sprintf("Subject: %s\nIssuer: %s\nValid: %s to %s\nIssues:\n- %s",
		leaf.Subject.String(), leaf.Issuer.String(),
		leaf.NotBefore.UTC().Format("2006-01-02"), leaf.NotAfter.UTC().Format("2006-01-02"),
		strings.Join(issues, "\n- "))
	return true, "tls://" + hostPort + "\nTLS handshake, certificate inspected", ev, nil
}

func isSelfSigned(c *x509.Certificate) bool {
	if c.Subject.String() != c.Issuer.String() {
		return false
	}
	return c.CheckSignatureFrom(c) == nil || c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}
