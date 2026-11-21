package api

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestScanDiffEmptyIsNotAChange(t *testing.T) {
	from := []domain.Host{{IP: "127.0.0.1", Services: []domain.Service{{Port: 15432, Protocol: "tcp", State: "open", Product: "PostgreSQL DB", Version: "9.6.0 or later"}}}}
	to := []domain.Host{{IP: "127.0.0.1", Services: []domain.Service{{Port: 15432, Protocol: "tcp", State: "open"}}}}
	if d := ComputeScanDiff("a", "b", from, to, nil); d.Summary.ChangedServicesCount != 0 {
		t.Fatalf("empty product/version must not count as a change: %+v", d.ChangedServices)
	}
	to[0].Services[0].Product, to[0].Services[0].Version = "PostgreSQL DB", "16.4"
	if d := ComputeScanDiff("a", "b", from, to, nil); d.Summary.ChangedServicesCount != 1 {
		t.Fatalf("a real version change must count, got %d", d.Summary.ChangedServicesCount)
	}
}

func TestScanDiffReopenedAndLatency(t *testing.T) {
	from := []domain.Host{{IP: "127.0.0.1", Services: []domain.Service{
		{Port: 8787, Protocol: "tcp", State: "closed"},
		{Port: 8085, Protocol: "tcp", State: "open", HTTP: &domain.HTTPFingerprint{MedianResponseMs: 15}},
	}}}
	to := []domain.Host{{IP: "127.0.0.1", Services: []domain.Service{
		{Port: 8787, Protocol: "tcp", State: "open"},
		{Port: 8085, Protocol: "tcp", State: "open", HTTP: &domain.HTTPFingerprint{MedianResponseMs: 530}},
	}}}
	d := ComputeScanDiff("a", "b", from, to, nil)
	if d.Summary.NewServicesCount != 1 || d.NewServices[0].Port != 8787 {
		t.Fatalf("reopened 8787 must be a new service: %+v", d.NewServices)
	}
	if d.Summary.ChangedServicesCount != 1 || d.ChangedServices[0].After["response_time_ms"] != int64(530) {
		t.Fatalf("latency jump must be a changed service: %+v", d.ChangedServices)
	}
}
