package main

import (
	"context"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

// The stored service carries the best evidence-backed product/version and its source,
// while the raw observation keeps what the scanner reported.
func TestIngestStoresIdentifiedProductWithSource(t *testing.T) {
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewMemoryStore(vault)
	p := ingest.NewPipeline(store, NewIntelligenceAnalyzer(), nil)
	_, err = p.ProcessObservations(context.Background(), ingest.IngestRequest{
		RunType: domain.ScanTypeImportJSON, ScanName: "t",
		Observations: []domain.ObservedHost{{
			IP: "10.9.9.9", IsAlive: true,
			Services: []domain.ObservedService{
				// nmap identified nginx without a version; the Server header has it.
				{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http", Product: "nginx",
					HTTP: &domain.HTTPFingerprint{StatusCode: 200, ServerHeader: "nginx/1.24.0", Title: "Welcome to nginx!"}},
				// nmap gave nothing; Tomcat's default page names it.
				{Port: 8080, Protocol: "tcp", State: "open", ServiceName: "http-proxy",
					HTTP: &domain.HTTPFingerprint{StatusCode: 200, Title: "Apache Tomcat/9.0.83",
						SafePathHits: []domain.SafePathHit{{Path: "/manager/html", StatusCode: 401, AuthChallenge: `Basic realm="Tomcat Manager Application"`}}}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := store.ListServices(context.Background(), db.ServiceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]domain.Service{}
	for _, s := range svcs {
		got[s.Port] = s
	}
	if s := got[80]; s.Product != "nginx" || s.Version != "1.24.0" || s.ProductSource != "nmap" || s.VersionSource != "http-server-header" {
		t.Errorf("port 80: %q %q (%s/%s)", s.Product, s.Version, s.ProductSource, s.VersionSource)
	}
	if s := got[8080]; s.Product != "Apache Tomcat" || s.Version != "9.0.83" || s.ProductSource != "http-page" || !s.IsAdminPanel {
		t.Errorf("port 8080: %q %q (%s) admin=%v", s.Product, s.Version, s.ProductSource, s.IsAdminPanel)
	}
}
