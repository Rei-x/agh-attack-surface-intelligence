package screenshot

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// EventScreenshotChanged is the change event type for a web page that now looks different.
const EventScreenshotChanged = "screenshot_changed"

// Sink is the ingest.ScreenshotSink that stores captures and records a change event when a
// service's page looks visibly different from its previous screenshot.
type Sink struct {
	Store *Store
	DB    db.Store // optional: change events
	Emit  func(domain.LiveEvent)
}

// StoreScreenshots implements ingest.ScreenshotSink.
func (s *Sink) StoreScreenshots(ctx context.Context, scanRunID string, observations []domain.ObservedHost) {
	if s == nil || s.Store == nil {
		return
	}
	var items []Item
	for _, o := range observations {
		for _, svc := range o.Services {
			if svc.Screenshot != nil {
				items = append(items, Item{Key: Key{IP: o.IP, Port: svc.Port, Protocol: svc.Protocol}, Shot: svc.Screenshot})
			}
		}
	}
	if len(items) == 0 {
		return
	}
	results, err := s.Store.PutBatch(items, scanRunID)
	if err != nil {
		log.Printf("[WARN] screenshot store: %v", err)
	}
	stored := 0
	for _, r := range results {
		if r.Err != nil {
			log.Printf("[WARN] screenshot %s:%d rejected: %v", r.Key.IP, r.Key.Port, r.Err)
			continue
		}
		stored++
		if r.Changed && r.Previous != nil {
			s.recordChange(ctx, scanRunID, r)
		}
	}
	if s.Emit != nil && stored > 0 {
		s.Emit(domain.LiveEvent{
			Type:      "screenshots.stored",
			ScanRunID: scanRunID,
			Timestamp: time.Now().UTC(),
			Payload:   map[string]any{"count": stored},
		})
	}
}

func (s *Sink) recordChange(ctx context.Context, scanRunID string, r ItemResult) {
	if s.DB == nil {
		return
	}
	host, err := s.DB.GetHostByIP(ctx, r.Key.IP)
	if err != nil || host == nil {
		return
	}
	ev := domain.ChangeEvent{
		ID:        db.NewID(),
		ScanRunID: scanRunID,
		HostID:    host.ID,
		HostIP:    r.Key.IP,
		Port:      r.Key.Port,
		EventType: EventScreenshotChanged,
		Severity:  "info",
		Summary:   fmt.Sprintf("Web page on %s:%d looks different", r.Key.IP, r.Key.Port),
		Before:    map[string]any{"screenshot": r.Previous.ID, "title": r.Previous.Title, "captured_at": r.Previous.CapturedAt},
		After:     map[string]any{"screenshot": r.Entry.ID, "title": r.Entry.Title, "distance": r.Distance},
	}
	for _, svc := range host.Services {
		if svc.Port == r.Key.Port && (svc.Protocol == "" || svc.Protocol == r.Key.Protocol) {
			ev.ServiceID = svc.ID
			break
		}
	}
	now := time.Now().UTC()
	ev.TimeSlot = domain.TimeSlotFor(now)
	ev.CreatedAt = now
	if err := s.DB.AddChangeEvent(ctx, &ev); err != nil {
		log.Printf("[WARN] screenshot change event: %v", err)
	}
}
