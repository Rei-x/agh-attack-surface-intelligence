package ingest

import (
	"context"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// PostIngestHook runs after every pipeline run (imports, local scan segments, remote agent
// uploads) once the inventory is persisted. It returns extra change events (e.g. zone
// policy violations that appeared or resolved); the pipeline records them with the run like
// its own events, so they reach the change list, live stream and alert webhook.
type PostIngestHook func(ctx context.Context, run *domain.ScanRun) []domain.ChangeEvent

type postIngestBox struct{ h PostIngestHook }

// SetPostIngestHook registers the hook (nil clears it).
func (p *Pipeline) SetPostIngestHook(h PostIngestHook) {
	p.postIngest.Store(postIngestBox{h: h})
}

func (p *Pipeline) runPostIngest(ctx context.Context, run *domain.ScanRun) []domain.ChangeEvent {
	if box, ok := p.postIngest.Load().(postIngestBox); ok && box.h != nil {
		return box.h(ctx, run)
	}
	return nil
}
