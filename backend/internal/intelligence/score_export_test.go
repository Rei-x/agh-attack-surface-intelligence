package intelligence_test

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/intelligence"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
	_ "github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb" // CVE annotator
)

// rescore runs the ingest scoring path (signatures, technology fusion, flags, service
// score, EOL / CVE annotators, host score) over hosts as the API exports them.
func rescore(hosts []domain.Host, now time.Time) {
	eng := signatures.NewEngine(nil)
	for hi := range hosts {
		h := &hosts[hi]
		for si := range h.Services {
			s := &h.Services[si]
			obs := domain.ObservedService{Port: s.Port, Protocol: s.Protocol, State: s.State, ServiceName: s.ServiceName,
				Product: s.Product, Version: s.Version, CPE: s.CPE, Banner: s.Banner, HTTP: s.HTTP, Tags: s.Tags}
			fresh := domain.Service{ID: s.ID, Port: s.Port, Protocol: s.Protocol, State: s.State, ServiceName: s.ServiceName,
				Product: s.Product, Version: s.Version, VersionSource: s.VersionSource, ProductSource: s.ProductSource,
				CPE: s.CPE, Banner: s.Banner, HTTP: s.HTTP, Tags: s.Tags}
			intelligence.EnrichService(&fresh, obs, eng, 1)
			eol.ApplyScore(&fresh, now)
			*s = fresh
		}
		h.Interestingness, h.InterestingFactors = intelligence.ScoreHost(h, h.Services, nil)
	}
}

type distribution struct {
	n, median, p75, p90, ge90, ge75, eq100 int
	hist                                   [11]int
}

func distOf(scores []int) distribution {
	s := append([]int(nil), scores...)
	sort.Ints(s)
	d := distribution{n: len(s)}
	if len(s) == 0 {
		return d
	}
	d.median, d.p75, d.p90 = s[len(s)/2], s[len(s)*3/4], s[len(s)*9/10]
	for _, x := range s {
		if x >= 90 {
			d.ge90++
		}
		if x >= 75 {
			d.ge75++
		}
		if x >= 100 {
			d.eq100++
		}
		d.hist[x/10]++
	}
	return d
}

func (d distribution) max() int {
	for i := len(d.hist) - 1; i >= 0; i-- {
		if d.hist[i] > 0 {
			return i * 10
		}
	}
	return 0
}

func (d distribution) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "n=%d median=%d p75=%d p90=%d >=75:%d (%.1f%%) >=90:%d (%.1f%%) =100:%d\n", d.n, d.median, d.p75, d.p90,
		d.ge75, pctOf(d.ge75, d.n), d.ge90, pctOf(d.ge90, d.n), d.eq100)
	for i, c := range d.hist {
		fmt.Fprintf(&b, "  %3d-%-3d %5d %s\n", i*10, i*10+9, c, strings.Repeat("#", (c*60+d.n-1)/max(d.n, 1)))
	}
	return b.String()
}

func pctOf(a, n int) float64 {
	if n == 0 {
		return 0
	}
	return float64(a) * 100 / float64(n)
}

// TestScoreDistributionLabExport re-scores a lab export (JSON array of hosts with services,
// as GET /api/v1/hosts returns them) when DZIECIOL_SCORE_EXPORT points at one. The export is
// not in the repository (it holds lab addresses); the synthetic population test below runs
// always.
func TestScoreDistributionLabExport(t *testing.T) {
	path := os.Getenv("DZIECIOL_SCORE_EXPORT")
	if path == "" {
		t.Skip("set DZIECIOL_SCORE_EXPORT to a hosts export to measure the lab distribution")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []domain.Host
	if err := json.Unmarshal(raw, &hosts); err != nil {
		var wrapped struct {
			Hosts []domain.Host `json:"hosts"`
		}
		if err2 := json.Unmarshal(raw, &wrapped); err2 != nil {
			t.Fatal(err)
		}
		hosts = wrapped.Hosts
	}
	rescore(hosts, time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC))
	var hs, ss []int
	blocks := map[string][]int{}
	for _, h := range hosts {
		hs = append(hs, h.Interestingness)
		for _, s := range h.Services {
			ss = append(ss, s.Interestingness)
		}
		if p := strings.Split(h.IP, "."); len(p) == 4 {
			var third int
			fmt.Sscanf(p[2], "%d", &third)
			key := fmt.Sprintf("%s.%s.%d.0/22", p[0], p[1], third&^3)
			blocks[key] = append(blocks[key], h.Interestingness)
		}
	}
	t.Logf("hosts:\n%s", distOf(hs))
	t.Logf("services:\n%s", distOf(ss))
	keys := make([]string, 0, len(blocks))
	for k := range blocks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d := distOf(blocks[k])
		t.Logf("block %-16s hosts=%3d max=%3d p90=%3d median=%3d >=75:%3d >=90:%2d", k, d.n, d.max(), d.p90, d.median, d.ge75, d.ge90)
	}
	if ip := os.Getenv("DZIECIOL_SCORE_HOST"); ip != "" {
		for _, h := range hosts {
			if h.IP != ip {
				continue
			}
			t.Logf("host %s = %d", h.IP, h.Interestingness)
			for _, f := range h.InterestingFactors {
				t.Logf("   +%-3d (w %3d) %s", f.Points, f.Weight, f.Reason)
			}
			for _, s := range h.Services {
				t.Logf("  %d/%s %s %s = %d", s.Port, s.Protocol, s.Product, s.Version, s.Interestingness)
				for _, f := range s.InterestingFactors {
					t.Logf("     +%-3d (w %3d %s) %s", f.Points, f.Weight, f.Kind, f.Reason)
				}
			}
		}
	}
	if os.Getenv("DZIECIOL_SCORE_TOP") != "" {
		sort.Slice(hosts, func(i, j int) bool { return hosts[i].Interestingness > hosts[j].Interestingness })
		for _, h := range hosts[:min(len(hosts), 25)] {
			t.Logf("%3d %-15s %v", h.Interestingness, h.IP, h.InterestingFactors)
		}
	}
}
