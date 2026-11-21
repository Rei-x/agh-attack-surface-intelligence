package main

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}

func portList(svcs []domain.Service, max int) string {
	sorted := append([]domain.Service(nil), svcs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Port < sorted[j].Port })
	parts := make([]string, 0, len(sorted))
	for i, s := range sorted {
		if i >= max {
			parts = append(parts, fmt.Sprintf("+%d", len(sorted)-max))
			break
		}
		name := s.ServiceName
		if name == "" {
			name = "?"
		}
		parts = append(parts, fmt.Sprintf("%d/%s", s.Port, name))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func ipLess(a, b string) bool {
	pa, ea := netip.ParseAddr(a)
	pb, eb := netip.ParseAddr(b)
	if ea == nil && eb == nil {
		return pa.Less(pb)
	}
	return a < b
}
