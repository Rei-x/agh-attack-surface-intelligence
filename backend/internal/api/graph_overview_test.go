package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// labHosts builds a /18 lab like the live instance: 64 /24 subnets with ~24 hosts each.
// Every host runs SSH; every third one a PHP site on Apache; every fifth an admin panel;
// scores cycle so each band is present.
func labHosts() []domain.Host {
	var hosts []domain.Host
	scores := []int{20, 45, 60, 80, 95}
	for sub := 0; sub < 64; sub++ {
		for i := 1; i <= 24; i++ {
			n := sub*24 + i
			h := domain.Host{
				ID:              fmt.Sprintf("h%d", n),
				IP:              fmt.Sprintf("10.66.%d.%d", sub, i),
				LifecycleState:  domain.HostStateActive,
				Interestingness: scores[n%len(scores)],
				Services: []domain.Service{{
					ID: fmt.Sprintf("s%d-22", n), Port: 22, Product: "OpenSSH", Interestingness: 20,
					Technologies: []domain.DetectedTechnology{{Name: "OpenSSH", Category: "server", Confidence: 90}},
				}},
			}
			if n%3 == 0 {
				h.Services = append(h.Services, domain.Service{
					ID: fmt.Sprintf("s%d-80", n), Port: 80, Product: "Apache httpd", Interestingness: h.Interestingness,
					Technologies: []domain.DetectedTechnology{
						{Name: "Apache HTTP Server", Category: "server", Confidence: 95},
						{Name: "PHP", Category: "framework", Confidence: 80},
						{Name: "Technology Disclosure Header (X-Powered-By)", Category: "interesting_header", Confidence: 100},
					},
				})
			}
			if n%5 == 0 {
				h.Services = append(h.Services, domain.Service{
					ID: fmt.Sprintf("s%d-8443", n), Port: 8443, IsAdminPanel: true, Interestingness: 90,
					Technologies: []domain.DetectedTechnology{{Name: "Admin Panel / Management Console", Category: "admin_panel", Confidence: 70}},
				})
			}
			if n%7 == 0 {
				h.Environment = "staging"
			}
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func countKinds(nodes []domain.GraphNode) map[string]int {
	out := map[string]int{}
	for _, n := range nodes {
		out[n.Kind]++
	}
	return out
}

func TestChooseBlockPrefix(t *testing.T) {
	cases := []struct {
		name  string
		ips   []string
		want  int
		limit int
	}{
		{"single /24 stays /24", []string{"10.0.0.1", "10.0.0.2"}, 24, 16},
		{"16 subnets fit at /24", genIPs(16), 24, 16},
		{"64 subnets of a /18 give /22", genIPs(64), 22, 16},
		{"64 subnets with limit 4 give /20", genIPs(64), 20, 4},
		{"scattered /8s floor at minBlockPrefix", []string{"1.0.0.1", "2.0.0.1", "3.0.0.1"}, minBlockPrefix, 2},
		{"non-IPv4 ignored", []string{"fe80::1", "10.0.0.1"}, 24, 16},
	}
	for _, c := range cases {
		hosts := make([]domain.Host, len(c.ips))
		for i, ip := range c.ips {
			hosts[i] = domain.Host{IP: ip}
		}
		if got := chooseBlockPrefix(hosts, c.limit); got != c.want {
			t.Errorf("%s: got /%d, want /%d", c.name, got, c.want)
		}
	}
}

func genIPs(subnets int) []string {
	out := make([]string, subnets)
	for i := range out {
		out[i] = fmt.Sprintf("10.66.%d.7", i)
	}
	return out
}

func TestCIDRHelpers(t *testing.T) {
	if got := blockOf("10.66.13.200", 22); got != "10.66.12.0/22" {
		t.Fatalf("blockOf: %s", got)
	}
	if got := blockOf("bogus", 22); got != "other" {
		t.Fatalf("blockOf non-IPv4: %s", got)
	}
	if !cidrContains("10.66.12.0/22", "10.66.15.1") || cidrContains("10.66.12.0/22", "10.66.16.1") {
		t.Fatal("cidrContains")
	}
	if n, p, ok := parseCIDR4("10.66.13.9/22"); !ok || p != 22 || formatCIDR(n, p) != "10.66.12.0/22" {
		t.Fatalf("parseCIDR4 should mask the host bits: %v %d", ok, p)
	}
}

func TestGraphOverviewAggregatesBlocks(t *testing.T) {
	hosts := labHosts()
	resp := BuildGraph(hosts, nil, GraphFilter{Limit: 60})

	if resp.Level != GraphLevelOverview || !resp.Clustered {
		t.Fatalf("expected overview level, got level=%q clustered=%v", resp.Level, resp.Clustered)
	}
	if resp.BlockPrefix != 22 || resp.GroupPrefix != 22 {
		t.Fatalf("expected /22 blocks for a /18, got block=%d group=%d", resp.BlockPrefix, resp.GroupPrefix)
	}
	kinds := countKinds(resp.Nodes)
	if kinds["block"] != 16 {
		t.Fatalf("expected 16 block nodes, got %v", kinds)
	}
	if kinds["service"] != 0 || kinds["host"] != 0 || kinds["scope"] != 0 {
		t.Fatalf("overview must not contain per-service/host nodes: %v", kinds)
	}
	if tech := kinds["technology"] + kinds["signature"]; tech == 0 || tech > laneTechs {
		t.Fatalf("technology lane size %d not in [1..%d]", tech, laneTechs)
	}
	if len(resp.Nodes) > maxBlocks+laneTechs {
		t.Fatalf("overview too large: %d nodes", len(resp.Nodes))
	}

	sum := 0
	prev := ""
	for _, n := range resp.Nodes {
		if n.Kind != "block" {
			continue
		}
		hc := n.Meta["host_count"].(int)
		sum += hc
		sev := n.Meta["severity"].(map[string]int)
		if sev["critical"]+sev["high"]+sev["medium"]+sev["low"] != hc {
			t.Fatalf("%s: severity buckets %v do not add up to %d hosts", n.Label, sev, hc)
		}
		if n.Interestingness != 95 {
			t.Fatalf("%s: top risk %d, want 95", n.Label, n.Interestingness)
		}
		if n.Meta["drill"] != GraphLevelBlock || n.Meta["subnet_count"].(int) != 4 {
			t.Fatalf("%s: drill=%v subnets=%v", n.Label, n.Meta["drill"], n.Meta["subnet_count"])
		}
		if _, ok := n.Meta["service_ids"]; ok {
			t.Fatalf("%s: block nodes must not carry service_ids", n.Label)
		}
		techs := n.Meta["top_techs"].([]map[string]any)
		if len(techs) == 0 || len(techs) > topTechsPerGroup {
			t.Fatalf("%s: top techs %v", n.Label, techs)
		}
		for _, tt := range techs {
			if strings.Contains(tt["name"].(string), "Disclosure") || strings.HasPrefix(tt["name"].(string), "Admin Panel") {
				t.Fatalf("%s: finding-like detection listed as technology: %v", n.Label, tt["name"])
			}
		}
		// Address order, so the grid reads like the network.
		if prev != "" {
			a, _, _ := parseCIDR4(prev)
			b, _, _ := parseCIDR4(n.Label)
			if b <= a {
				t.Fatalf("blocks out of address order: %s after %s", n.Label, prev)
			}
		}
		prev = n.Label
	}
	if sum != len(hosts) {
		t.Fatalf("block host counts add up to %d, want %d", sum, len(hosts))
	}

	// Edges go block -> lane technology, carry a host-count weight and are capped per block.
	ids := map[string]domain.GraphNode{}
	for _, n := range resp.Nodes {
		ids[n.ID] = n
	}
	perBlock := map[string]int{}
	for _, e := range resp.Edges {
		src, okS := ids[e.Source]
		dst, okT := ids[e.Target]
		if !okS || !okT || src.Kind != "block" || (dst.Kind != "technology" && dst.Kind != "signature") {
			t.Fatalf("unexpected edge %s", e.ID)
		}
		if e.Weight <= 0 {
			t.Fatalf("edge %s has no weight", e.ID)
		}
		perBlock[e.Source]++
	}
	for b, n := range perBlock {
		if n > edgesPerGroup {
			t.Fatalf("%s has %d edges, cap is %d", b, n, edgesPerGroup)
		}
	}
	// The SSH edge of the first block counts every host in it (each host runs SSH).
	first := "block:10.66.0.0/22"
	sshEdge := first + "->" + techNodeID("OpenSSH")
	for _, e := range resp.Edges {
		if e.ID == sshEdge && e.Weight != ids[first].Meta["host_count"].(int) {
			t.Fatalf("ssh edge weight %d, want %v", e.Weight, ids[first].Meta["host_count"])
		}
	}
	// Lane nodes get the full member host list for the side panel.
	if hc, _ := ids[techNodeID("OpenSSH")].Meta["host_count"].(int); hc != len(hosts) {
		t.Fatalf("OpenSSH lane node lists %d hosts, want %d", hc, len(hosts))
	}
}

func TestGraphBlockLevelShowsSubnets(t *testing.T) {
	hosts := labHosts()
	resp := BuildGraph(hosts, nil, GraphFilter{Limit: 60, Block: "10.66.4.0/22"})
	if resp.Level != GraphLevelBlock || resp.Block != "10.66.4.0/22" || resp.GroupPrefix != 24 {
		t.Fatalf("level=%q block=%q group=%d", resp.Level, resp.Block, resp.GroupPrefix)
	}
	want := []string{"10.66.4.0/24", "10.66.5.0/24", "10.66.6.0/24", "10.66.7.0/24"}
	var got []string
	for _, n := range resp.Nodes {
		if n.Kind == "block" {
			got = append(got, n.Label)
			if n.Meta["drill"] != GraphLevelSubnet || n.Meta["subnet"] != n.Label {
				t.Fatalf("%s should drill into the subnet: %v", n.Label, n.Meta["drill"])
			}
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("subnets %v, want %v", got, want)
	}
	if resp.MatchedHosts != 4*24 {
		t.Fatalf("matched %d hosts in block, want 96", resp.MatchedHosts)
	}
	// Jump-to-subnet keeps listing every subnet, not only the block's.
	if len(resp.Subnets) != 64 {
		t.Fatalf("subnet list has %d entries, want 64", len(resp.Subnets))
	}
	// A non-canonical block is normalised.
	if r := BuildGraph(hosts, nil, GraphFilter{Limit: 60, Block: "10.66.5.9/22"}); r.Block != "10.66.4.0/22" {
		t.Fatalf("block not normalised: %q", r.Block)
	}
}

func TestGraphSubnetLevelHostGrid(t *testing.T) {
	resp := BuildGraph(labHosts(), nil, GraphFilter{Limit: 150, Subnet: "10.66.6.0/24"})
	if resp.Level != GraphLevelSubnet || resp.Block != "10.66.4.0/22" || resp.Mode != "grid" {
		t.Fatalf("level=%q block=%q mode=%q", resp.Level, resp.Block, resp.Mode)
	}
	kinds := countKinds(resp.Nodes)
	if kinds["host"] != 24 || kinds["service"] != 0 {
		t.Fatalf("expected 24 host cards and no service nodes, got %v", kinds)
	}
	prevScore := 101
	for _, n := range resp.Nodes {
		if n.Kind != "host" {
			continue
		}
		if n.Interestingness > prevScore {
			t.Fatalf("host cards not ordered by risk: %d after %d", n.Interestingness, prevScore)
		}
		prevScore = n.Interestingness
		ports := n.Meta["ports"].([]int)
		ids := n.Meta["service_ids"].([]string)
		if len(ports) == 0 || len(ports) != len(ids) || n.Meta["host_id"] == "" {
			t.Fatalf("%s: ports %v service_ids %v", n.Label, ports, ids)
		}
	}
	for _, e := range resp.Edges {
		if !strings.HasPrefix(e.Source, "host:") || !strings.HasPrefix(e.Target, "tech:") {
			t.Fatalf("unexpected edge %s", e.ID)
		}
	}
	// The tree and the service clusters stay available on request.
	if d := BuildGraph(labHosts(), nil, GraphFilter{Limit: 150, Subnet: "10.66.6.0/24", Mode: "detailed"}); d.Mode != "detailed" || countKinds(d.Nodes)["service"] == 0 {
		t.Fatalf("detailed subnet: mode=%q kinds=%v", d.Mode, countKinds(d.Nodes))
	}
	if c := BuildGraph(labHosts(), nil, GraphFilter{Limit: 150, Subnet: "10.66.6.0/24", Mode: "clustered"}); !c.Clustered || c.Level != GraphLevelSubnet {
		t.Fatalf("clustered subnet: clustered=%v level=%q", c.Clustered, c.Level)
	}
}

func TestGraphOverviewFilters(t *testing.T) {
	hosts := labHosts()
	count := func(f func(h domain.Host) bool) int {
		n := 0
		for _, h := range hosts {
			if f(h) {
				n++
			}
		}
		return n
	}

	risk := BuildGraph(hosts, nil, GraphFilter{Limit: 60, MinScore: 50})
	if risk.Level != GraphLevelOverview || risk.MatchedHosts != count(func(h domain.Host) bool { return h.Interestingness >= 50 }) {
		t.Fatalf("risk filter: level=%q matched=%d", risk.Level, risk.MatchedHosts)
	}
	for _, n := range risk.Nodes {
		if n.Kind == "block" && n.Meta["severity"].(map[string]int)["low"] != 0 {
			t.Fatalf("%s: low-score hosts leaked through the risk filter", n.Label)
		}
	}
	// Blocks do not move when a filter is on.
	if risk.BlockPrefix != 22 {
		t.Fatalf("block prefix changed under a filter: %d", risk.BlockPrefix)
	}

	either := BuildGraph(hosts, nil, GraphFilter{Limit: 60, AdminOrStaging: true})
	want := count(func(h domain.Host) bool { return hostHasAdmin(h) || hostIsStaging(h) })
	if either.MatchedHosts != want {
		t.Fatalf("admin_or_staging matched %d, want %d", either.MatchedHosts, want)
	}
	admin := BuildGraph(hosts, nil, GraphFilter{Limit: 60, AdminOnly: true})
	staging := BuildGraph(hosts, nil, GraphFilter{Limit: 60, StagingOnly: true})
	if either.MatchedHosts <= admin.MatchedHosts || either.MatchedHosts <= staging.MatchedHosts {
		t.Fatalf("union %d should exceed admin %d and staging %d", either.MatchedHosts, admin.MatchedHosts, staging.MatchedHosts)
	}

	// Few matches fall back to the detailed view.
	small := BuildGraph(hosts, nil, GraphFilter{Limit: 60, Query: "10.66.3.1"})
	if small.Level != GraphLevelDetailed || small.Clustered {
		t.Fatalf("small result should be detailed, got level=%q", small.Level)
	}
}

func TestGraphOverviewCapsGroups(t *testing.T) {
	// 40 hosts spread over 40 /8s: even /8 blocks exceed maxGroups, so the riskiest are kept.
	var hosts []domain.Host
	for i := 0; i < 40; i++ {
		hosts = append(hosts, domain.Host{ID: fmt.Sprintf("x%d", i), IP: fmt.Sprintf("%d.1.1.1", i+1), Interestingness: i})
	}
	resp := BuildGraph(hosts, nil, GraphFilter{Mode: "clustered"})
	if got := countKinds(resp.Nodes)["block"]; got != maxGroups || resp.HiddenGroups != 40-maxGroups {
		t.Fatalf("blocks=%d hidden=%d", got, resp.HiddenGroups)
	}
	for _, n := range resp.Nodes {
		if n.Kind == "block" && n.Interestingness < 40-maxGroups {
			t.Fatalf("low-risk block %s kept while riskier ones were hidden", n.Label)
		}
	}
}

func BenchmarkGraphOverview(b *testing.B) {
	hosts := labHosts()
	for i := 0; i < b.N; i++ {
		BuildGraph(hosts, nil, GraphFilter{Limit: 60})
	}
}
