package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// GraphFilter filters and scales nodes returned by GET /api/v1/graph.
type GraphFilter struct {
	State       string
	MinScore    int
	AdminOnly   bool
	StagingOnly bool
	// AdminOrStaging keeps hosts that pass either the admin or the staging check (one request
	// for the "Admin / staging" quick filter instead of merging two graphs).
	AdminOrStaging bool
	Subnet         string
	Block          string // CIDR of an overview block: shows its /24 subnets
	Query          string
	Mode           string // auto (default), clustered, detailed
	Limit          int    // max detailed hosts before auto-clustering (default 50, max 150)
}

// SubnetSummary summarizes a /24 subnet for drill-down UI selectors.
type SubnetSummary struct {
	Subnet        string `json:"subnet"`
	HostCount     int    `json:"host_count"`
	ActiveCount   int    `json:"active_count"`
	HighRiskCount int    `json:"high_risk_count"`
	MaxScore      int    `json:"max_score"`
}

// GraphResponse is returned by GET /api/v1/graph.
type GraphResponse struct {
	Nodes        []domain.GraphNode `json:"nodes"`
	Edges        []domain.GraphEdge `json:"edges"`
	TotalHosts   int                `json:"total_hosts"`
	MatchedHosts int                `json:"matched_hosts"`
	ShownHosts   int                `json:"shown_hosts"`
	Clustered    bool               `json:"clustered"`
	Mode         string             `json:"mode"`
	// Level is overview, block, subnet or detailed (see graph_overview.go).
	Level string `json:"level"`
	// BlockPrefix is the prefix of overview blocks, stable for a data set so the UI can
	// build breadcrumbs (e.g. 22 for "10.66.0.0/22").
	BlockPrefix int `json:"block_prefix"`
	// GroupPrefix is the prefix of group nodes on an aggregated level (BlockPrefix on the
	// overview, 24 inside a block).
	GroupPrefix int `json:"group_prefix,omitempty"`
	// Block is the block being shown (block level) or holding the subnet (subnet level).
	Block        string          `json:"block,omitempty"`
	HiddenGroups int             `json:"hidden_groups,omitempty"`
	Limit        int             `json:"limit"`
	Subnets      []SubnetSummary `json:"subnets"`
}

// BuildGraph constructs the interactive Attack Surface Topology:
//   - Detailed (<= limit hosts or mode=detailed):
//     Scope/Subnet -> Host (state, score) -> Service (port/proto) -> Technology / Signature.
//   - Overview (> limit hosts or mode=clustered): one node per address block plus a lane of
//     the riskiest technologies; block=<cidr> shows the /24 subnets of one block. See
//     graph_overview.go. Rendered size stays a few dozen nodes at any host count.
//   - subnet=<cidr>: a grid of host cards (buildHostGrid); mode=detailed gives the tree,
//     mode=clustered the per-port service clusters (buildClusteredGraph).
func BuildGraph(hosts []domain.Host, targets []domain.Target, filter GraphFilter) GraphResponse {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 150 {
		limit = 150
	}
	mode := strings.ToLower(strings.TrimSpace(filter.Mode))
	if mode == "" {
		mode = "auto"
	}

	qLower := strings.ToLower(strings.TrimSpace(filter.Query))
	subnetFilter := strings.TrimSpace(filter.Subnet)
	blockFilter := strings.TrimSpace(filter.Block)
	if blockFilter != "" {
		if n, p, ok := parseCIDR4(blockFilter); ok {
			blockFilter = formatCIDR(n, p)
		} else {
			blockFilter = ""
		}
	}
	blockPrefix := chooseBlockPrefix(hosts, maxBlocks)

	// 1. Filter hosts and compute subnet summaries across all matched hosts.
	matched := make([]domain.Host, 0, len(hosts))
	subnetMap := make(map[string]*SubnetSummary)

	for _, h := range hosts {
		if filter.State != "" && !strings.EqualFold(h.LifecycleState, filter.State) {
			continue
		}
		if filter.MinScore > 0 && h.Interestingness < filter.MinScore {
			continue
		}
		if filter.AdminOnly && !hostHasAdmin(h) {
			continue
		}
		if filter.StagingOnly && !hostIsStaging(h) {
			continue
		}
		if filter.AdminOrStaging && !hostHasAdmin(h) && !hostIsStaging(h) {
			continue
		}
		if qLower != "" && !hostMatchesQuery(h, qLower) {
			continue
		}

		sub := subnet24(h.IP)
		ss, ok := subnetMap[sub]
		if !ok {
			ss = &SubnetSummary{Subnet: sub}
			subnetMap[sub] = ss
		}
		ss.HostCount++
		if h.LifecycleState == domain.HostStateActive || h.LifecycleState == domain.HostStateNew || h.LifecycleState == domain.HostStateReactivated {
			ss.ActiveCount++
		}
		if h.Interestingness >= 50 {
			ss.HighRiskCount++
		}
		if h.Interestingness > ss.MaxScore {
			ss.MaxScore = h.Interestingness
		}

		if subnetFilter != "" && sub != subnetFilter {
			continue
		}
		if subnetFilter == "" && blockFilter != "" && !cidrContains(blockFilter, h.IP) {
			continue
		}
		matched = append(matched, h)
	}

	subnets := make([]SubnetSummary, 0, len(subnetMap))
	for _, ss := range subnetMap {
		subnets = append(subnets, *ss)
	}
	sort.Slice(subnets, func(i, j int) bool {
		if subnets[i].HighRiskCount != subnets[j].HighRiskCount {
			return subnets[i].HighRiskCount > subnets[j].HighRiskCount
		}
		if subnets[i].MaxScore != subnets[j].MaxScore {
			return subnets[i].MaxScore > subnets[j].MaxScore
		}
		if subnets[i].HostCount != subnets[j].HostCount {
			return subnets[i].HostCount > subnets[j].HostCount
		}
		return subnets[i].Subnet < subnets[j].Subnet
	})

	// Sort matched hosts by Interestingness DESC so highest-risk attack paths surface first.
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Interestingness != matched[j].Interestingness {
			return matched[i].Interestingness > matched[j].Interestingness
		}
		return matched[i].IP < matched[j].IP
	})

	var resp GraphResponse
	switch {
	case subnetFilter != "":
		// One /24: a grid of host cards by default; the host, service and technology tree
		// (detailed) or service clusters (clustered) on request.
		switch mode {
		case "clustered":
			resp = buildClusteredGraph(hosts, matched, subnets, targets, limit)
		case "detailed":
			resp = buildDetailedGraph(hosts, matched, subnets, targets, limit)
		default:
			resp = buildHostGrid(hosts, matched, subnets, limit)
		}
		resp.Level = GraphLevelSubnet
		if blockPrefix < 24 {
			resp.Block = blockOf(strings.TrimSuffix(subnetFilter, "/24"), blockPrefix)
		}
	case mode == "detailed":
		resp = buildDetailedGraph(hosts, matched, subnets, targets, limit)
		resp.Level = GraphLevelDetailed
	case blockFilter != "":
		resp = buildAggregateGraph(hosts, matched, subnets, 24, GraphLevelBlock, limit)
		resp.Block = blockFilter
	case mode == "clustered" || len(matched) > limit:
		resp = buildAggregateGraph(hosts, matched, subnets, blockPrefix, GraphLevelOverview, limit)
	default:
		resp = buildDetailedGraph(hosts, matched, subnets, targets, limit)
		resp.Level = GraphLevelDetailed
	}
	resp.BlockPrefix = blockPrefix
	attachTechHosts(resp.Nodes, matched)
	return resp
}

func hostHasAdmin(h domain.Host) bool {
	for _, s := range h.Services {
		if s.IsAdminPanel {
			return true
		}
	}
	return false
}

func hostIsStaging(h domain.Host) bool {
	if strings.EqualFold(h.Environment, "staging") || strings.EqualFold(h.Environment, "dev") {
		return true
	}
	for _, s := range h.Services {
		if s.IsStagingEnv {
			return true
		}
	}
	return false
}

// maxNodeHosts caps the host list embedded in one cluster/technology node; host_count and
// host_ids still carry the full membership.
const maxNodeHosts = 100

// GraphHostRef is one member host of a clustered service or technology node: enough for the
// side panel to list it (IP, title, score) and open the asset inspector.
type GraphHostRef struct {
	HostID    string `json:"host_id"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	Title     string `json:"title,omitempty"`
	Score     int    `json:"score"`
	ServiceID string `json:"service_id,omitempty"`
	Port      int    `json:"port,omitempty"`
	Owner     string `json:"owner,omitempty"`
}

// nodeMembers accumulates the hosts/services behind an aggregated graph node.
type nodeMembers struct {
	refs       []GraphHostRef
	hostSeen   map[string]bool
	serviceIDs []string
}

func (m *nodeMembers) add(h *domain.Host, s *domain.Service) {
	if m.hostSeen == nil {
		m.hostSeen = map[string]bool{}
	}
	if s != nil && s.ID != "" {
		m.serviceIDs = append(m.serviceIDs, s.ID)
	}
	if m.hostSeen[h.ID] {
		return
	}
	m.hostSeen[h.ID] = true
	ref := GraphHostRef{HostID: h.ID, IP: h.IP, Hostname: h.Hostname, Score: h.Interestingness, Owner: h.Owner}
	if s != nil {
		ref.ServiceID, ref.Port = s.ID, s.Port
		if s.HTTP != nil {
			ref.Title = s.HTTP.Title
		}
	}
	m.refs = append(m.refs, ref)
}

// writeMeta stores host_ids / service_ids / hosts (sorted by score, capped) / host_count.
func (m *nodeMembers) writeMeta(dst map[string]any) {
	sort.SliceStable(m.refs, func(i, j int) bool {
		if m.refs[i].Score != m.refs[j].Score {
			return m.refs[i].Score > m.refs[j].Score
		}
		return m.refs[i].IP < m.refs[j].IP
	})
	ids := make([]string, len(m.refs))
	for i, r := range m.refs {
		ids[i] = r.HostID
	}
	refs := m.refs
	if len(refs) > maxNodeHosts {
		refs = refs[:maxNodeHosts]
	}
	if refs == nil {
		refs = []GraphHostRef{}
	}
	dst["host_ids"] = ids
	dst["service_ids"] = append([]string{}, m.serviceIDs...)
	dst["hosts"] = refs
	dst["host_count"] = len(ids)
}

func techNodeID(name string) string {
	return "tech:" + strings.ToLower(strings.ReplaceAll(name, " ", "_"))
}

// attachTechHosts gives every technology/signature node the full list of matched hosts
// running it (not only the rendered ones), so the side panel can list and open them.
func attachTechHosts(nodes []domain.GraphNode, matched []domain.Host) {
	idx := map[string]*nodeMembers{}
	for i := range nodes {
		if nodes[i].Kind == "technology" || nodes[i].Kind == "signature" {
			idx[nodes[i].ID] = &nodeMembers{}
		}
	}
	if len(idx) == 0 {
		return
	}
	for hi := range matched {
		h := &matched[hi]
		for si := range h.Services {
			s := &h.Services[si]
			for _, t := range s.Technologies {
				if m, ok := idx[techNodeID(t.Name)]; ok {
					m.add(h, s)
				}
			}
		}
	}
	for i := range nodes {
		m, ok := idx[nodes[i].ID]
		if !ok {
			continue
		}
		if nodes[i].Meta == nil {
			nodes[i].Meta = map[string]any{}
		}
		m.writeMeta(nodes[i].Meta)
	}
}

func buildClusteredGraph(
	allHosts []domain.Host,
	matched []domain.Host,
	subnets []SubnetSummary,
	targets []domain.Target,
	limit int,
) GraphResponse {
	nodes := make([]domain.GraphNode, 0, 128)
	edges := make([]domain.GraphEdge, 0, 160)
	nodeSeen := make(map[string]bool)
	edgeSeen := make(map[string]bool)

	addNode := func(n domain.GraphNode) {
		if !nodeSeen[n.ID] {
			nodeSeen[n.ID] = true
			nodes = append(nodes, n)
		}
	}
	addEdge := func(src, dst, label string) {
		id := src + "->" + dst
		if !edgeSeen[id] {
			edgeSeen[id] = true
			edges = append(edges, domain.GraphEdge{
				ID:     id,
				Source: src,
				Target: dst,
				Label:  label,
			})
		}
	}

	rootID := "scope:all"
	rootLabel := fmt.Sprintf("All targets (%d hosts)", len(matched))
	if len(targets) == 1 && targets[0].Value != "" {
		rootLabel = fmt.Sprintf("%s (%d hosts)", targets[0].Value, len(matched))
	}
	addNode(domain.GraphNode{
		ID:    rootID,
		Kind:  "scope",
		Label: rootLabel,
		Meta: map[string]any{
			"host_count":   len(matched),
			"subnet_count": len(subnets),
			"is_cluster":   true,
		},
	})

	// Cap visible /24 subnet clusters to top 16 highest-risk/largest subnets.
	maxSubnets := 16
	if len(subnets) < maxSubnets {
		maxSubnets = len(subnets)
	}
	allowedSubnets := make(map[string]bool, maxSubnets)
	for i := 0; i < maxSubnets; i++ {
		ss := subnets[i]
		allowedSubnets[ss.Subnet] = true
		subNodeID := "host:cluster:" + ss.Subnet
		state := domain.HostStateActive
		if ss.ActiveCount == 0 {
			state = domain.HostStateInactive
		}
		addNode(domain.GraphNode{
			ID:              subNodeID,
			Kind:            "host",
			Label:           fmt.Sprintf("%s (%d hosts)", ss.Subnet, ss.HostCount),
			State:           state,
			Interestingness: ss.MaxScore,
			Meta: map[string]any{
				"is_cluster":      true,
				"subnet":          ss.Subnet,
				"ip":              ss.Subnet,
				"hostname":        fmt.Sprintf("%d active · %d high risk", ss.ActiveCount, ss.HighRiskCount),
				"host_count":      ss.HostCount,
				"active_count":    ss.ActiveCount,
				"high_risk_count": ss.HighRiskCount,
			},
		})
		addEdge(rootID, subNodeID, fmt.Sprintf("%d IP", ss.HostCount))
	}

	// Aggregate services per subnet by (port, product/service) so each subnet shows its top service clusters.
	type svcBucket struct {
		subnet      string
		port        int
		proto       string
		product     string
		serviceName string
		count       int
		maxScore    int
		isAdmin     bool
		isStaging   bool
		isIoT       bool
		members     nodeMembers
		techs       map[string]domain.DetectedTechnology
	}
	bySubnetBuckets := make(map[string]map[string]*svcBucket)

	for hi := range matched {
		h := &matched[hi]
		sub := subnet24(h.IP)
		if !allowedSubnets[sub] {
			continue
		}
		bmap, ok := bySubnetBuckets[sub]
		if !ok {
			bmap = make(map[string]*svcBucket)
			bySubnetBuckets[sub] = bmap
		}
		for si := range h.Services {
			s := &h.Services[si]
			prod := s.Product
			if prod == "" {
				prod = s.ServiceName
			}
			key := fmt.Sprintf("%d:%s", s.Port, strings.ToLower(prod))
			b, exists := bmap[key]
			if !exists {
				b = &svcBucket{
					subnet:      sub,
					port:        s.Port,
					proto:       s.Protocol,
					product:     s.Product,
					serviceName: s.ServiceName,
					techs:       make(map[string]domain.DetectedTechnology),
				}
				bmap[key] = b
			}
			b.count++
			b.members.add(h, s)
			if s.Interestingness > b.maxScore {
				b.maxScore = s.Interestingness
			}
			b.isAdmin = b.isAdmin || s.IsAdminPanel
			b.isStaging = b.isStaging || s.IsStagingEnv
			b.isIoT = b.isIoT || s.IsIoT
			for _, t := range s.Technologies {
				if prev, ok := b.techs[t.Name]; !ok || t.Confidence > prev.Confidence {
					b.techs[t.Name] = t
				}
			}
		}
	}

	// Emit up to top 3 service clusters per subnet (keeps total nodes ~50-110 even at 10,000+ hosts!).
	for i := 0; i < maxSubnets; i++ {
		sub := subnets[i].Subnet
		subNodeID := "host:cluster:" + sub
		bmap := bySubnetBuckets[sub]
		list := make([]*svcBucket, 0, len(bmap))
		for _, b := range bmap {
			list = append(list, b)
		}
		sort.Slice(list, func(a, b int) bool {
			if list[a].maxScore != list[b].maxScore {
				return list[a].maxScore > list[b].maxScore
			}
			return list[a].count > list[b].count
		})
		if len(list) > 3 {
			list = list[:3]
		}
		for _, b := range list {
			name := b.product
			if name == "" {
				name = b.serviceName
			}
			svcID := fmt.Sprintf("service:cluster:%s:%d:%s", sub, b.port, strings.ToLower(strings.ReplaceAll(name, " ", "_")))
			svcMeta := map[string]any{
				"is_cluster":     true,
				"subnet":         sub,
				"port":           b.port,
				"protocol":       b.proto,
				"product":        name,
				"count":          b.count,
				"is_admin_panel": b.isAdmin,
				"is_staging_env": b.isStaging,
				"is_iot":         b.isIoT,
			}
			// Full membership instead of one representative host/service: the inspector and
			// the DefectDojo push act on every service of the cluster.
			b.members.writeMeta(svcMeta)
			addNode(domain.GraphNode{
				ID:              svcID,
				Kind:            "service",
				Label:           fmt.Sprintf(":%d %s (%d×)", b.port, name, b.count),
				State:           "open",
				Interestingness: b.maxScore,
				Meta:            svcMeta,
			})
			addEdge(subNodeID, svcID, fmt.Sprintf("%d× :%d", b.count, b.port))

			// Connect top 2 technologies per service cluster.
			tlist := make([]domain.DetectedTechnology, 0, len(b.techs))
			for _, t := range b.techs {
				tlist = append(tlist, t)
			}
			sort.Slice(tlist, func(x, y int) bool { return tlist[x].Confidence > tlist[y].Confidence })
			if len(tlist) > 2 {
				tlist = tlist[:2]
			}
			for _, tech := range tlist {
				techID := techNodeID(tech.Name)
				techLabel := tech.Name
				if tech.Version != "" {
					techLabel += " " + tech.Version
				}
				kind := "technology"
				if tech.Category == "admin_panel" || tech.Category == "staging" || tech.Category == "custom" {
					kind = "signature"
				}
				addNode(domain.GraphNode{
					ID:              techID,
					Kind:            kind,
					Label:           techLabel,
					Interestingness: tech.Confidence,
					Meta: map[string]any{
						"name":       tech.Name,
						"category":   tech.Category,
						"confidence": tech.Confidence,
						"version":    tech.Version,
					},
				})
				addEdge(svcID, techID, fmt.Sprintf("%d%%", tech.Confidence))
			}
		}
	}

	return GraphResponse{
		Nodes:        nodes,
		Edges:        edges,
		TotalHosts:   len(allHosts),
		MatchedHosts: len(matched),
		ShownHosts:   len(matched),
		Clustered:    true,
		Mode:         "clustered",
		Limit:        limit,
		Subnets:      subnets,
	}
}

func buildDetailedGraph(
	allHosts []domain.Host,
	matched []domain.Host,
	subnets []SubnetSummary,
	targets []domain.Target,
	limit int,
) GraphResponse {
	shown := matched
	if len(shown) > limit {
		shown = shown[:limit]
	}

	nodes := make([]domain.GraphNode, 0, len(shown)*3)
	edges := make([]domain.GraphEdge, 0, len(shown)*3)
	nodeSeen := make(map[string]bool)
	edgeSeen := make(map[string]bool)

	addNode := func(n domain.GraphNode) {
		if !nodeSeen[n.ID] {
			nodeSeen[n.ID] = true
			nodes = append(nodes, n)
		}
	}
	addEdge := func(src, dst, label string) {
		id := src + "->" + dst
		if !edgeSeen[id] {
			edgeSeen[id] = true
			edges = append(edges, domain.GraphEdge{
				ID:     id,
				Source: src,
				Target: dst,
				Label:  label,
			})
		}
	}

	// Pre-register configured targets as scopes if no hosts exist yet
	if len(shown) == 0 {
		for _, t := range targets {
			if !t.Enabled {
				continue
			}
			sid := "scope:" + t.Value
			label := t.Value
			if t.Label != "" {
				label = t.Label + " (" + t.Value + ")"
			}
			addNode(domain.GraphNode{
				ID:    sid,
				Kind:  "scope",
				Label: label,
				Meta:  map[string]any{"target": t.Value, "kind": t.Kind},
			})
		}
	}

	subnetCounts := make(map[string]int)
	for _, h := range shown {
		subnetCounts[subnet24(h.IP)]++
	}

	for _, h := range shown {
		subnet := subnet24(h.IP)
		scopeID := "scope:" + subnet
		addNode(domain.GraphNode{
			ID:    scopeID,
			Kind:  "scope",
			Label: subnet,
			Meta:  map[string]any{"subnet": subnet, "host_count": subnetCounts[subnet]},
		})

		hostID := "host:" + h.ID
		hostLabel := h.IP
		if h.Hostname != "" {
			hostLabel = fmt.Sprintf("%s (%s)", h.IP, h.Hostname)
		}
		addNode(domain.GraphNode{
			ID:              hostID,
			Kind:            "host",
			Label:           hostLabel,
			State:           h.LifecycleState,
			Interestingness: h.Interestingness,
			Meta: map[string]any{
				"host_id":         h.ID,
				"ip":              h.IP,
				"hostname":        h.Hostname,
				"environment":     h.Environment,
				"owner":           h.Owner,
				"stability_score": h.StabilityScore,
				"service_count":   len(h.Services),
				"locked_fields":   h.LockedFields,
			},
		})
		addEdge(scopeID, hostID, "contains")

		for _, s := range h.Services {
			svcNodeID := "service:" + s.ID
			svcLabel := fmt.Sprintf(":%d/%s %s", s.Port, s.Protocol, s.ServiceName)
			if s.Product != "" {
				svcLabel = fmt.Sprintf(":%d %s", s.Port, s.Product)
			}
			svcMeta := map[string]any{
				"service_id":     s.ID,
				"host_id":        h.ID,
				"port":           s.Port,
				"protocol":       s.Protocol,
				"product":        s.Product,
				"service_name":   s.ServiceName,
				"version":        s.Version,
				"state":          s.State,
				"is_admin_panel": s.IsAdminPanel,
				"is_staging_env": s.IsStagingEnv,
				"is_iot":         s.IsIoT,
			}
			if s.HTTP != nil {
				if s.HTTP.Title != "" {
					svcMeta["http_title"] = s.HTTP.Title
				}
				if s.HTTP.TLS != nil && (s.HTTP.TLS.IsSelfSigned || s.HTTP.TLS.IsExpired || s.HTTP.TLS.DaysToExpiry <= 30) {
					svcMeta["tls_warning"] = true
				}
			}
			addNode(domain.GraphNode{
				ID:              svcNodeID,
				Kind:            "service",
				Label:           svcLabel,
				State:           s.State,
				Interestingness: s.Interestingness,
				Meta:            svcMeta,
			})
			addEdge(hostID, svcNodeID, fmt.Sprintf("port %d", s.Port))

			for _, tech := range s.Technologies {
				techID := techNodeID(tech.Name)
				techLabel := tech.Name
				if tech.Version != "" {
					techLabel += " " + tech.Version
				}
				kind := "technology"
				if tech.Category == "admin_panel" || tech.Category == "staging" || tech.Category == "custom" {
					kind = "signature"
				}
				addNode(domain.GraphNode{
					ID:              techID,
					Kind:            kind,
					Label:           techLabel,
					Interestingness: tech.Confidence,
					Meta: map[string]any{
						"name":       tech.Name,
						"category":   tech.Category,
						"confidence": tech.Confidence,
						"version":    tech.Version,
					},
				})
				addEdge(svcNodeID, techID, fmt.Sprintf("%d%%", tech.Confidence))
			}
		}
	}

	return GraphResponse{
		Nodes:        nodes,
		Edges:        edges,
		TotalHosts:   len(allHosts),
		MatchedHosts: len(matched),
		ShownHosts:   len(shown),
		Clustered:    false,
		Mode:         "detailed",
		Limit:        limit,
		Subnets:      subnets,
	}
}

func hostMatchesQuery(h domain.Host, qLower string) bool {
	if strings.Contains(strings.ToLower(h.IP), qLower) ||
		strings.Contains(strings.ToLower(h.Hostname), qLower) ||
		strings.Contains(strings.ToLower(h.Environment), qLower) {
		return true
	}
	for _, s := range h.Services {
		if strings.Contains(strings.ToLower(s.Product), qLower) ||
			strings.Contains(strings.ToLower(s.ServiceName), qLower) ||
			fmt.Sprintf("%d", s.Port) == qLower {
			return true
		}
		if s.HTTP != nil && strings.Contains(strings.ToLower(s.HTTP.Title), qLower) {
			return true
		}
		for _, t := range s.Technologies {
			if strings.Contains(strings.ToLower(t.Name), qLower) {
				return true
			}
		}
	}
	return false
}

func subnet24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
	}
	return "default-scope"
}
