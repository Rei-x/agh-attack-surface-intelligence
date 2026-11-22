package ingest

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestCarryForwardKeepsKnownValues(t *testing.T) {
	prev := &domain.Service{ServiceName: "postgresql", Product: "PostgreSQL DB", Version: "9.6.0 or later", ProductSource: "nmap", VersionSource: "nmap"}

	// Second scan: nmap's light probe got nothing this time.
	p, v, _, _, n := carryForward(prev, "", "", "", "", "tcp")
	if p != "PostgreSQL DB" || v != "9.6.0 or later" || n != "postgresql" {
		t.Fatalf("empty observation must keep the previous identification, got %q %q %q", p, v, n)
	}
	// Same product, version not disclosed this time.
	_, v, _, _, _ = carryForward(prev, "PostgreSQL DB", "", "nmap", "", "postgresql")
	if v != "9.6.0 or later" {
		t.Fatalf("version must be carried for the same product, got %q", v)
	}
	// A real change wins.
	p, v, _, _, n = carryForward(prev, "MySQL", "8.0.36", "nmap", "nmap", "mysql")
	if p != "MySQL" || v != "8.0.36" || n != "mysql" {
		t.Fatalf("a new non-empty value must win, got %q %q %q", p, v, n)
	}
	// A different product without a version must not inherit the old product's version.
	_, v, _, _, _ = carryForward(prev, "MySQL", "", "nmap", "", "mysql")
	if v != "" {
		t.Fatalf("version of another product must not be carried, got %q", v)
	}
}

func TestDiffServiceIgnoresEmptyValues(t *testing.T) {
	prev := &domain.Service{Product: "PostgreSQL DB", Version: "9.6.0 or later", Banner: "x"}
	curr := &domain.Service{Product: "", Version: ""}
	if _, after, _, _ := diffService(prev, curr); len(after) != 0 {
		t.Fatalf("empty values must not be a change, got %v", after)
	}
}
