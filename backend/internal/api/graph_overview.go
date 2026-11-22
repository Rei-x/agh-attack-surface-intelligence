package api

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Aggregated graph levels. Large scopes are drawn top-down instead of as one giant column:
//
//	overview: one node per address block (auto-chosen prefix, at most maxBlocks blocks)
//	block:    the /24 subnets inside one block
//	subnet:   hosts and services of one /24 (detailed, or service clusters when it is huge)
//
// Both aggregated levels add a lane with the riskiest technologies and one weighted edge per
// (group, technology) pair, so the rendered size stays a few dozen nodes at any host count.
const (
	GraphLevelOverview = "overview"
	GraphLevelBlock    = "block"
	GraphLevelSubnet   = "subnet"
	GraphLevelDetailed = "detailed"

	// maxBlocks bounds the overview: the block prefix is the longest one that keeps the
	// number of blocks at or below it.
	maxBlocks = 16
	// maxGroups caps group nodes on an aggregated level when even /8 or a wide block holds
	// more; the riskiest groups are kept and the rest are reported as hidden.
	maxGroups = 24
	// laneTechs is the size of the technology lane.
	laneTechs = 10
	// edgesPerGroup keeps only the heaviest group to technology edges.
	edgesPerGroup = 5
	// topTechsPerGroup is how many technology logos a group card shows.
	topTechsPerGroup = 3
	// minBlockPrefix is the widest block the overview will use.
	minBlockPrefix = 8
)

// parseIPv4 returns the address as a uint32.
func parseIPv4(ip string) (uint32, bool) {
	parts := strings.Split(strings.TrimSpace(ip), ".")
	if len(parts) != 4 {
		return 0, false
	}
	var out uint32
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return 0, false
		}
		out = out<<8 | uint32(n)
	}
	return out, true
}

func maskIPv4(ip uint32, prefix int) uint32 {
	if prefix <= 0 {
		return 0
	}
	return ip & (^uint32(0) << (32 - prefix))
}

func formatCIDR(ip uint32, prefix int) string {
	return fmt.Sprintf("%d.%d.%d.%d/%d", ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff, prefix)
}

// parseCIDR4 parses "a.b.c.d/n" into its masked network and prefix.
func parseCIDR4(cidr string) (uint32, int, bool) {
	addr, bits, ok := strings.Cut(strings.TrimSpace(cidr), "/")
	if !ok {
		return 0, 0, false
	}
	prefix, err := strconv.Atoi(bits)
	if err != nil || prefix < 0 || prefix > 32 {
		return 0, 0, false
	}
	ip, ok := parseIPv4(addr)
	if !ok {
		return 0, 0, false
	}
	return maskIPv4(ip, prefix), prefix, true
}

// blockOf returns the CIDR of the /prefix block holding ip ("other" for non-IPv4 hosts).
func blockOf(ip string, prefix int) string {
	n, ok := parseIPv4(ip)
	if !ok {
		return "other"
	}
	return formatCIDR(maskIPv4(n, prefix), prefix)
}

// cidrContains reports whether ip lies inside cidr.
func cidrContains(cidr, ip string) bool {
	net, prefix, ok := parseCIDR4(cidr)
	if !ok {
		return false
	}
	n, ok := parseIPv4(ip)
	return ok && maskIPv4(n, prefix) == net
}

// chooseBlockPrefix picks the longest prefix in [minBlockPrefix, 24] whose blocks number at
// most maxN, so the overview is as fine-grained as it can be while staying readable. It is
// computed over every host (not the filtered set) so blocks do not move when filters change.
func chooseBlockPrefix(hosts []domain.Host, maxN int) int {
	ips := make([]uint32, 0, len(hosts))
	for _, h := range hosts {
		if n, ok := parseIPv4(h.IP); ok {
			ips = append(ips, n)
		}
	}
	for prefix := 24; prefix > minBlockPrefix; prefix-- {
		seen := make(map[uint32]struct{}, maxN+1)
		for _, n := range ips {
			seen[maskIPv4(n, prefix)] = struct{}{}
			if len(seen) > maxN {
				break
			}
		}
		if len(seen) <= maxN {
			return prefix
		}
	}
	return minBlockPrefix
}

// severityBucket maps a score to the four bands used by the UI (critical >= 90, high >= 75,
// medium >= 50, low below).
func severityBucket(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 75:
		return "high"
	case score >= 50:
		return "medium"
	default:
		return "low"
	}
}

func isLiveState(state string) bool {
	return state == domain.HostStateActive || state == domain.HostStateNew || state == domain.HostStateReactivated
}

type techAgg struct {
	name      string
	category  string
	hosts     int
	highRisk  int
	maxScore  int
	techScore int
}

type groupAgg struct {
	cidr     string
	network  uint32
	hosts    int
	active   int
	highRisk int
	maxScore int
	severity map[string]int
	subnets  map[string]struct{}
	techs    map[string]int // technology name -> hosts running it in this group
	risky    map[string]int // technology name -> hosts with score >= 50 running it
	members  nodeMembers
}

// topService is the riskiest service of a host (nil when it has none); its port and title
// make the host list in the side panel more useful.
func topService(h *domain.Host) *domain.Service {
	var best *domain.Service
	for i := range h.Services {
		s := &h.Services[i]
		if best == nil || s.Interestingness > best.Interestingness {
			best = s
		}
	}
	return best
}

// addHostTechs records the product technologies of one host in techs (each counted once per
// host, scored by the riskiest service running it) and returns them with that score.
func addHostTechs(h *domain.Host, techs map[string]*techAgg) map[string]int {
	hostTech := map[string]int{}
	for si := range h.Services {
		s := &h.Services[si]
		for _, t := range s.Technologies {
			if t.Name == "" || !isProductTech(t) {
				continue
			}
			if prev, ok := hostTech[t.Name]; !ok || s.Interestingness > prev {
				hostTech[t.Name] = s.Interestingness
			}
			ta, ok := techs[t.Name]
			if !ok {
				ta = &techAgg{name: t.Name, category: t.Category}
				techs[t.Name] = ta
			}
			if t.Confidence > ta.techScore {
				ta.techScore = t.Confidence
			}
		}
	}
	for name, score := range hostTech {
		ta := techs[name]
		ta.hosts++
		if score > ta.maxScore {
			ta.maxScore = score
		}
		if h.Interestingness >= 50 {
			ta.highRisk++
		}
	}
	return hostTech
}

// techLane returns the lane (riskiest band first, then most widespread) and a membership set.
func techLane(techs map[string]*techAgg) ([]*techAgg, map[string]bool) {
	tlist := make([]*techAgg, 0, len(techs))
	for _, t := range techs {
		if t.hosts > 0 {
			tlist = append(tlist, t)
		}
	}
	sortTechAggs(tlist)
	if len(tlist) > laneTechs {
		tlist = tlist[:laneTechs]
	}
	inLane := make(map[string]bool, len(tlist))
	for _, t := range tlist {
		inLane[t.name] = true
	}
	return tlist, inLane
}

func laneNode(t *techAgg) domain.GraphNode {
	kind := "technology"
	if t.category == "admin_panel" || t.category == "staging" || t.category == "custom" {
		kind = "signature"
	}
	return domain.GraphNode{
		ID:              techNodeID(t.name),
		Kind:            kind,
		Label:           t.name,
		Interestingness: t.maxScore,
		Meta: map[string]any{
			"name":            t.name,
			"category":        t.category,
			"confidence":      t.techScore,
			"max_score":       t.maxScore,
			"high_risk_count": t.highRisk,
			"lane":            true,
		},
	}
}

// buildHostGrid is the subnet level: one card per host (riskiest first) with its open ports
// and main technologies, plus the technology lane. It replaces the tall host, service and
// technology tree, which needs a zoom far below readable for a full /24.
func buildHostGrid(allHosts, matched []domain.Host, subnets []SubnetSummary, limit int) GraphResponse {
	techs := map[string]*techAgg{}
	perHost := make([]map[string]int, len(matched))
	for hi := range matched {
		perHost[hi] = addHostTechs(&matched[hi], techs)
	}
	tlist, inLane := techLane(techs)

	nodes := make([]domain.GraphNode, 0, len(matched)+len(tlist))
	edges := make([]domain.GraphEdge, 0, len(matched)*2)
	for hi := range matched {
		h := &matched[hi]
		svcs := make([]*domain.Service, len(h.Services))
		for i := range h.Services {
			svcs[i] = &h.Services[i]
		}
		sort.SliceStable(svcs, func(i, j int) bool {
			if svcs[i].Interestingness != svcs[j].Interestingness {
				return svcs[i].Interestingness > svcs[j].Interestingness
			}
			return svcs[i].Port < svcs[j].Port
		})
		ports := make([]int, 0, len(svcs))
		serviceIDs := make([]string, 0, len(svcs))
		title := ""
		admin, staging := false, strings.EqualFold(h.Environment, "staging") || strings.EqualFold(h.Environment, "dev")
		for _, s := range svcs {
			ports = append(ports, s.Port)
			if s.ID != "" {
				serviceIDs = append(serviceIDs, s.ID)
			}
			if title == "" && s.HTTP != nil {
				title = s.HTTP.Title
			}
			admin = admin || s.IsAdminPanel
			staging = staging || s.IsStagingEnv
		}

		type ht struct {
			name  string
			score int
		}
		hts := make([]ht, 0, len(perHost[hi]))
		for name, score := range perHost[hi] {
			hts = append(hts, ht{name, score})
		}
		sort.Slice(hts, func(i, j int) bool {
			if hts[i].score != hts[j].score {
				return hts[i].score > hts[j].score
			}
			return hts[i].name < hts[j].name
		})
		top := make([]map[string]any, 0, topTechsPerGroup)
		for _, t := range hts {
			if len(top) == topTechsPerGroup {
				break
			}
			top = append(top, map[string]any{"name": t.name, "hosts": 1})
		}

		id := "host:" + h.ID
		nodes = append(nodes, domain.GraphNode{
			ID:              id,
			Kind:            "host",
			Label:           h.IP,
			State:           h.LifecycleState,
			Interestingness: h.Interestingness,
			Meta: map[string]any{
				"host_id":         h.ID,
				"ip":              h.IP,
				"hostname":        h.Hostname,
				"title":           title,
				"environment":     h.Environment,
				"owner":           h.Owner,
				"stability_score": h.StabilityScore,
				"service_count":   len(h.Services),
				"locked_fields":   h.LockedFields,
				"ports":           ports,
				"service_ids":     serviceIDs,
				"top_techs":       top,
				"is_admin_panel":  admin,
				"is_staging_env":  staging,
			},
		})
		n := 0
		for _, t := range hts {
			if !inLane[t.name] || n == edgesPerGroup {
				continue
			}
			n++
			tid := techNodeID(t.name)
			edges = append(edges, domain.GraphEdge{ID: id + "->" + tid, Source: id, Target: tid, Label: "runs", Weight: 1})
		}
	}
	for _, t := range tlist {
		nodes = append(nodes, laneNode(t))
	}
	return GraphResponse{
		Nodes:        nodes,
		Edges:        edges,
		TotalHosts:   len(allHosts),
		MatchedHosts: len(matched),
		ShownHosts:   len(matched),
		Clustered:    false,
		Mode:         "grid",
		Level:        GraphLevelSubnet,
		GroupPrefix:  32,
		Limit:        limit,
		Subnets:      subnets,
	}
}

// buildAggregateGraph groups matched hosts into /groupPrefix nodes plus a technology lane.
func buildAggregateGraph(allHosts, matched []domain.Host, subnets []SubnetSummary, groupPrefix int, level string, limit int) GraphResponse {
	groups := map[string]*groupAgg{}
	techs := map[string]*techAgg{}

	for hi := range matched {
		h := &matched[hi]
		key := blockOf(h.IP, groupPrefix)
		g, ok := groups[key]
		if !ok {
			g = &groupAgg{cidr: key, severity: map[string]int{}, subnets: map[string]struct{}{}, techs: map[string]int{}, risky: map[string]int{}}
			if n, _, ok := parseCIDR4(key); ok {
				g.network = n
			} else {
				g.network = ^uint32(0)
			}
			groups[key] = g
		}
		g.hosts++
		if isLiveState(h.LifecycleState) {
			g.active++
		}
		if h.Interestingness >= 50 {
			g.highRisk++
		}
		if h.Interestingness > g.maxScore {
			g.maxScore = h.Interestingness
		}
		g.severity[severityBucket(h.Interestingness)]++
		g.subnets[subnet24(h.IP)] = struct{}{}
		g.members.add(h, topService(h))

		for name := range addHostTechs(h, techs) {
			g.techs[name]++
			if h.Interestingness >= 50 {
				g.risky[name]++
			}
		}
	}

	// Groups: keep the riskiest when there are too many, then draw in address order.
	list := make([]*groupAgg, 0, len(groups))
	for _, g := range groups {
		list = append(list, g)
	}
	hidden := 0
	if len(list) > maxGroups {
		sort.Slice(list, func(i, j int) bool {
			if list[i].maxScore != list[j].maxScore {
				return list[i].maxScore > list[j].maxScore
			}
			if list[i].highRisk != list[j].highRisk {
				return list[i].highRisk > list[j].highRisk
			}
			return list[i].hosts > list[j].hosts
		})
		hidden = len(list) - maxGroups
		list = list[:maxGroups]
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].network != list[j].network {
			return list[i].network < list[j].network
		}
		return list[i].cidr < list[j].cidr
	})

	tlist, inLane := techLane(techs)

	nodes := make([]domain.GraphNode, 0, len(list)+len(tlist))
	edges := make([]domain.GraphEdge, 0, len(list)*edgesPerGroup)

	drill := GraphLevelBlock
	if groupPrefix >= 24 {
		drill = GraphLevelSubnet
	}
	for _, g := range list {
		id := "block:" + g.cidr
		state := domain.HostStateActive
		if g.active == 0 {
			state = domain.HostStateInactive
		}
		meta := map[string]any{
			"is_cluster":      true,
			"cidr":            g.cidr,
			"prefix":          groupPrefix,
			"drill":           drill,
			"active_count":    g.active,
			"high_risk_count": g.highRisk,
			"subnet_count":    len(g.subnets),
			"severity": map[string]int{
				"critical": g.severity["critical"],
				"high":     g.severity["high"],
				"medium":   g.severity["medium"],
				"low":      g.severity["low"],
			},
			"top_techs": topGroupTechs(g, techs),
		}
		if drill == GraphLevelSubnet {
			meta["subnet"] = g.cidr
		}
		g.members.writeMeta(meta)
		// A block stands for whole subnets; pushing every service of it to DefectDojo from a
		// single click is not intended, so it carries hosts only.
		delete(meta, "service_ids")
		nodes = append(nodes, domain.GraphNode{
			ID:              id,
			Kind:            "block",
			Label:           g.cidr,
			State:           state,
			Interestingness: g.maxScore,
			Meta:            meta,
		})

		type wEdge struct {
			name string
			w    int
		}
		ws := make([]wEdge, 0, len(g.techs))
		for name, w := range g.techs {
			if inLane[name] {
				ws = append(ws, wEdge{name, w})
			}
		}
		sort.Slice(ws, func(i, j int) bool {
			if ws[i].w != ws[j].w {
				return ws[i].w > ws[j].w
			}
			return ws[i].name < ws[j].name
		})
		if len(ws) > edgesPerGroup {
			ws = ws[:edgesPerGroup]
		}
		for _, e := range ws {
			tid := techNodeID(e.name)
			edges = append(edges, domain.GraphEdge{
				ID:     id + "->" + tid,
				Source: id,
				Target: tid,
				Label:  fmt.Sprintf("%d hosts", e.w),
				Weight: e.w,
			})
		}
	}

	for _, t := range tlist {
		nodes = append(nodes, laneNode(t))
	}

	return GraphResponse{
		Nodes:        nodes,
		Edges:        edges,
		TotalHosts:   len(allHosts),
		MatchedHosts: len(matched),
		ShownHosts:   len(matched),
		Clustered:    true,
		Mode:         "clustered",
		Level:        level,
		GroupPrefix:  groupPrefix,
		HiddenGroups: hidden,
		Limit:        limit,
		Subnets:      subnets,
	}
}

func sortTechAggs(list []*techAgg) {
	band := func(s int) int {
		switch severityBucket(s) {
		case "critical":
			return 3
		case "high":
			return 2
		case "medium":
			return 1
		}
		return 0
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if band(a.maxScore) != band(b.maxScore) {
			return band(a.maxScore) > band(b.maxScore)
		}
		if a.hosts != b.hosts {
			return a.hosts > b.hosts
		}
		if a.maxScore != b.maxScore {
			return a.maxScore > b.maxScore
		}
		return a.name < b.name
	})
}

// isProductTech keeps real products (servers, frameworks, CMSs, devices, named admin tools)
// and drops finding-like detections such as disclosure headers, cookie flags, TLS problems or
// the generic "Admin Panel / Management Console" signature: they are not technologies to map.
func isProductTech(t domain.DetectedTechnology) bool {
	switch t.Category {
	case "interesting_header", "interesting_cookie", "custom", "staging":
		return false
	case "admin_panel":
		return !strings.Contains(t.Name, "/")
	}
	return true
}

// topGroupTechs returns the technologies of a group that sit on the most risky hosts (score
// >= 50; ties broken by all hosts, then overall risk) for the logos on its card.
func topGroupTechs(g *groupAgg, all map[string]*techAgg) []map[string]any {
	type tc struct {
		name  string
		risky int
		n     int
		score int
	}
	list := make([]tc, 0, len(g.techs))
	for name, n := range g.techs {
		list = append(list, tc{name, g.risky[name], n, all[name].maxScore})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].risky != list[j].risky {
			return list[i].risky > list[j].risky
		}
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		if list[i].score != list[j].score {
			return list[i].score > list[j].score
		}
		return list[i].name < list[j].name
	})
	if len(list) > topTechsPerGroup {
		list = list[:topTechsPerGroup]
	}
	out := make([]map[string]any, len(list))
	for i, t := range list {
		out[i] = map[string]any{"name": t.name, "hosts": t.n}
	}
	return out
}
