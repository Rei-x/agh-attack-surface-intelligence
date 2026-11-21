package db

import (
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func matchesHostFilter(h *domain.Host, f HostFilter) bool {
	if f.State != "" && !strings.EqualFold(h.LifecycleState, f.State) {
		return false
	}
	if f.Env != "" && !strings.EqualFold(h.Environment, f.Env) {
		return false
	}
	if f.MinScore > 0 && h.Interestingness < f.MinScore {
		return false
	}
	if f.Tag != "" && !hasTag(h.Tags, f.Tag) {
		foundInSvc := false
		for _, s := range h.Services {
			if hasTag(s.Tags, f.Tag) {
				foundInSvc = true
				break
			}
		}
		if !foundInSvc {
			return false
		}
	}
	if f.HasAdmin {
		hasAdmin := false
		for _, s := range h.Services {
			if s.IsAdminPanel {
				hasAdmin = true
				break
			}
		}
		if !hasAdmin {
			return false
		}
	}
	if aq := cachedAssetQuery(f.Query); aq != nil && !aq.MatchHost(h) {
		return false
	}
	return true
}

func hostMatchesQuery(h *domain.Host, q string) bool {
	if strings.Contains(strings.ToLower(h.IP), q) ||
		strings.Contains(strings.ToLower(h.Hostname), q) ||
		strings.Contains(strings.ToLower(h.OSGuess), q) ||
		strings.Contains(strings.ToLower(h.Notes), q) ||
		strings.Contains(strings.ToLower(h.Owner), q) ||
		strings.Contains(strings.ToLower(h.Environment), q) {
		return true
	}
	for _, d := range h.Domains {
		if strings.Contains(strings.ToLower(d), q) {
			return true
		}
	}
	for _, t := range h.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	for _, s := range h.Services {
		if serviceMatchesQuery(&s, q) {
			return true
		}
	}
	return false
}

func matchesServiceFilter(s *domain.Service, f ServiceFilter) bool {
	if f.HostID != "" && s.HostID != f.HostID {
		return false
	}
	if f.Port > 0 && s.Port != f.Port {
		return false
	}
	if f.State != "" && !strings.EqualFold(s.State, f.State) {
		return false
	}
	if f.MinScore > 0 && s.Interestingness < f.MinScore {
		return false
	}
	if f.HasAdmin && !s.IsAdminPanel {
		return false
	}
	if f.Tag != "" && !hasTag(s.Tags, f.Tag) {
		return false
	}
	if aq := cachedAssetQuery(f.Query); aq != nil && !aq.MatchService(s) {
		return false
	}
	return true
}

func serviceMatchesQuery(s *domain.Service, q string) bool {
	if strings.Contains(strings.ToLower(s.HostIP), q) ||
		strings.Contains(strings.ToLower(s.ServiceName), q) ||
		strings.Contains(strings.ToLower(s.Product), q) ||
		strings.Contains(strings.ToLower(s.Version), q) ||
		strings.Contains(strings.ToLower(s.Banner), q) ||
		strings.Contains(strings.ToLower(s.Notes), q) {
		return true
	}
	if s.HTTP != nil {
		if strings.Contains(strings.ToLower(s.HTTP.Title), q) ||
			strings.Contains(strings.ToLower(s.HTTP.URL), q) ||
			strings.Contains(strings.ToLower(s.HTTP.ServerHeader), q) {
			return true
		}
	}
	for _, tech := range s.Technologies {
		if strings.Contains(strings.ToLower(tech.Name), q) || strings.Contains(strings.ToLower(tech.Category), q) {
			return true
		}
	}
	for _, t := range s.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}
