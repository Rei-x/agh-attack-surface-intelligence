package emu

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

// CertStore lazily mints one certificate per (ip, kind) at handshake time.
// valid       — issued by an internal CA, currently valid, CN = host FQDN
// self_signed — issuer == subject, long validity (appliance default)
// expired     — issued by the internal CA, NotAfter in the past
type CertStore struct {
	mu     sync.Mutex
	key    *ecdsa.PrivateKey
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	cache  map[string]*tls.Certificate
}

func NewCertStore() (*CertStore, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AGH Lab Internal CA G2", Organization: []string{"Akademia Gorniczo-Hutnicza (lab)"}, Country: []string{"PL"}},
		NotBefore:             time.Now().AddDate(-3, 0, 0),
		NotAfter:              time.Now().AddDate(7, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, _ := x509.ParseCertificate(der)
	return &CertStore{key: key, caKey: caKey, caCert: ca, cache: map[string]*tls.Certificate{}}, nil
}

// Get returns the certificate for the given host.
func (cs *CertStore) Get(ip, cn, kind, org string) (*tls.Certificate, error) {
	k := ip + "|" + kind + "|" + cn
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if c, ok := cs.cache[k]; ok {
		return c, nil
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}, Country: []string{"PL"}},
		DNSNames:     []string{cn},
		IPAddresses:  []net.IP{net.ParseIP(ip)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signer := cs.caCert, cs.caKey
	switch kind {
	case "self_signed":
		tmpl.NotBefore = time.Now().AddDate(-2, 0, 0)
		tmpl.NotAfter = time.Now().AddDate(8, 0, 0)
		parent, signer = tmpl, cs.key
	case "expired":
		tmpl.NotBefore = time.Now().AddDate(-2, -3, 0)
		tmpl.NotAfter = time.Now().AddDate(0, -3, 0)
	default:
		tmpl.NotBefore = time.Now().AddDate(0, -2, 0)
		tmpl.NotAfter = time.Now().AddDate(0, 10, 0)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &cs.key.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	chain := [][]byte{der}
	if kind != "self_signed" {
		chain = append(chain, cs.caCert.Raw)
	}
	c := &tls.Certificate{Certificate: chain, PrivateKey: cs.key}
	cs.cache[k] = c
	return c, nil
}
