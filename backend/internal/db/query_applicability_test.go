package db

import (
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb"
)

// A Rapid Reset match on a port with HTTP/2 off must not answer kev:true, cve:<id>,
// cve:true, epss or cvss queries; with HTTP/2 not probed it still does.
func TestQueryTermsSkipSuppressedCVEs(t *testing.T) {
	snap, err := vulndb.Parse([]byte(`{"schema":1,"generated_at":"2026-11-21T00:00:00Z",
 "cves":[{"id":"CVE-2023-44487","s":7.5,"sev":"HIGH","k":"2023-10-10","e":0.94,"ep":0.999,"rq":"http2"}],
 "products":{"nginx":[{"c":"CVE-2023-44487","r":[{"ee":"1.25.3"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	vulndb.SetCurrent(vulndb.New(snap, "test"))
	defer vulndb.SetCurrent(nil)

	svc := func(http2 string) *domain.Service {
		s := &domain.Service{Port: 80, Product: "nginx", Version: "1.20.1", HTTP: &domain.HTTPFingerprint{Scheme: "http"}}
		if http2 != "" {
			s.HTTP.Protocols = &domain.ProtocolSupport{HTTP2: http2, CheckedAt: time.Now()}
		}
		return s
	}
	off, unknown := svc(domain.ProtoNo), svc("")
	for _, q := range []string{"kev:true", "cve:CVE-2023-44487", "cve:true", "epss>0.5", "cvss>=7"} {
		pq, err := ParseAssetQuery(q)
		if err != nil {
			t.Fatal(err)
		}
		if pq.MatchService(off) {
			t.Errorf("%s matched a service where the CVE is not applicable (HTTP/2 off)", q)
		}
		if !pq.MatchService(unknown) {
			t.Errorf("%s did not match the unverified version match", q)
		}
	}
	if pq, _ := ParseAssetQuery("-kev:true"); !pq.MatchService(off) {
		t.Error("-kev:true should match the HTTP/2-off service")
	}
}
