package ingest

import (
	"fmt"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
)

// EventOutdatedVersion is emitted when a service is first seen running an end-of-life
// version (new service, version change, or first time the EOL table flags it).
const EventOutdatedVersion = "OUTDATED_VERSION"

// outdatedEvent builds the OUTDATED_VERSION change for curr (already annotated by
// eol.ApplyScore). prev is only read when existed. Unchanged EOL services stay quiet.
func outdatedEvent(existed bool, prev, curr *domain.Service) (domain.ChangeEvent, bool) {
	if len(curr.Outdated) == 0 {
		return domain.ChangeEvent{}, false
	}
	if existed && prev.Version == curr.Version && prev.Product == curr.Product && hasTagFold(prev.Tags, eol.TagEOL) {
		return domain.ChangeEvent{}, false
	}
	labels := make([]string, 0, len(curr.Outdated))
	items := make([]map[string]any, 0, len(curr.Outdated))
	for _, o := range curr.Outdated {
		labels = append(labels, o.Label)
		items = append(items, map[string]any{
			"product": o.Product, "version": o.Version, "branch": o.Branch,
			"eol_date": o.EOLDate, "days_since_eol": o.DaysSinceEOL, "evidence": o.Evidence, "source": o.Source,
		})
	}
	return domain.ChangeEvent{
		Port:      curr.Port,
		EventType: EventOutdatedVersion,
		Severity:  "medium",
		Summary:   fmt.Sprintf("End-of-life version on %s:%d/%s: %s", curr.HostIP, curr.Port, curr.Protocol, strings.Join(labels, "; ")),
		Before:    map[string]any{"product": prev.Product, "version": prev.Version},
		After:     map[string]any{"product": curr.Product, "version": curr.Version, "outdated": items},
	}, true
}

func hasTagFold(tags []string, t string) bool {
	for _, x := range tags {
		if strings.EqualFold(x, t) {
			return true
		}
	}
	return false
}
