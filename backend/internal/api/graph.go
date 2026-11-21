package api

import (
	"fmt"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// GraphFilter filters nodes returned by GET /api/v1/graph.
type GraphFilter struct {
	State       string
	MinScore    int
	AdminOnly   bool
	StagingOnly bool
}

// GraphResponse is returned by GET /api/v1/graph.
type GraphResponse struct {
	Nodes []domain.GraphNode `json:"nodes"`
	Edges []domain.GraphEdge `json:"edges"`
}

// BuildGraph constructs the interactive Attack Surface Topology:
// Scope/Subnet -> Host (state, score) -> Service (port/proto) -> Technology / Signature.
func BuildGraph(hosts []domain.Host, targets []domain.Target, filter GraphFilter) GraphResponse {
	nodes := make([]domain.GraphNode, 0, len(hosts)*3)
	edges := make([]domain.GraphEdge, 0, len(hosts)*3)
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

	// Pre-register configured targets as scopes if present
	scopeByPrefix := make(map[string]string)
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		sid := "scope:" + t.Value
		label := t.Value
		if t.Label != "" {
			label = t.Label + " (" + t.Value + ")"
		}
		scopeByPrefix[t.Value] = sid
		addNode(domain.GraphNode{
			ID:    sid,
			Kind:  "scope",
			Label: label,
			Meta:  map[string]any{"target": t.Value, "kind": t.Kind},
		})
	}

	for _, h := range hosts {
		if filter.State != "" && !strings.EqualFold(h.LifecycleState, filter.State) {
			continue
		}
		if filter.MinScore > 0 && h.Interestingness < filter.MinScore {
			continue
		}
		if filter.AdminOnly {
			ok := false
			for _, s := range h.Services {
				if s.IsAdminPanel {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if filter.StagingOnly {
			ok := strings.EqualFold(h.Environment, "staging") || strings.EqualFold(h.Environment, "dev")
			for _, s := range h.Services {
				if s.IsStagingEnv {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}

		// Group host under /24 subnet scope node
		subnet := subnet24(h.IP)
		scopeID := "scope:" + subnet
		addNode(domain.GraphNode{
			ID:    scopeID,
			Kind:  "scope",
			Label: subnet,
			Meta:  map[string]any{"subnet": subnet},
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
				"state":          s.State,
				"is_admin_panel": s.IsAdminPanel,
				"is_staging_env": s.IsStagingEnv,
				"is_iot":         s.IsIoT,
			}
			if s.HTTP != nil && s.HTTP.Title != "" {
				svcMeta["http_title"] = s.HTTP.Title
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
				techID := "tech:" + strings.ToLower(strings.ReplaceAll(tech.Name, " ", "_"))
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
		Nodes: nodes,
		Edges: edges,
	}
}

func subnet24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
	}
	return "default-scope"
}
