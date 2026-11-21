package api

import (
	"context"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// withOwners fills after.owner on change events recorded before the pipeline stamped the
// CIDR-rule owner onto every event, so the change list always answers "kto tym zarządza?".
func (s *Server) withOwners(ctx context.Context, events []domain.ChangeEvent) {
	owners := map[string]string{}
	for i := range events {
		ev := &events[i]
		if ev.HostID == "" {
			continue
		}
		if _, ok := ev.After["owner"]; ok {
			continue
		}
		owner, cached := owners[ev.HostID]
		if !cached {
			if h, err := s.store.GetHost(ctx, ev.HostID); err == nil && h != nil {
				owner = h.Owner
			}
			owners[ev.HostID] = owner
		}
		if owner == "" {
			continue
		}
		if ev.After == nil {
			ev.After = map[string]any{}
		}
		ev.After["owner"] = owner
	}
}
