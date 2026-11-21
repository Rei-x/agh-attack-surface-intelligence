package ingest

import (
	"context"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ScreenshotSink receives the landing-page screenshots carried by active scan observations
// (local engine or remote agent) and stores them outside the asset store
// (internal/screenshot). Implementations must not keep references to the observations.
type ScreenshotSink interface {
	StoreScreenshots(ctx context.Context, scanRunID string, observations []domain.ObservedHost)
}

type screenshotSinkBox struct{ s ScreenshotSink }

// SetScreenshotSink registers where screenshots go. Without a sink they are dropped.
func (p *Pipeline) SetScreenshotSink(s ScreenshotSink) {
	p.screenshots.Store(screenshotSinkBox{s: s})
}

// takeScreenshots hands screenshots to the sink and strips them from the observations, so
// image bytes never reach the asset store, snapshots or evidence receipts. Only ACTIVE runs
// may carry screenshots: imports and manual entries are user supplied and are just stripped.
func (p *Pipeline) takeScreenshots(ctx context.Context, req *IngestRequest) {
	hasShot := func(o *domain.ObservedHost) bool {
		for j := range o.Services {
			if o.Services[j].Screenshot != nil {
				return true
			}
		}
		return false
	}
	found := false
	for i := range req.Observations {
		if hasShot(&req.Observations[i]) {
			found = true
			break
		}
	}
	if !found {
		return
	}
	// Work on copies so the caller's observations keep their screenshots untouched.
	req.Observations = append([]domain.ObservedHost(nil), req.Observations...)
	var withShots []domain.ObservedHost
	for i := range req.Observations {
		o := &req.Observations[i]
		if !hasShot(o) {
			continue
		}
		withShots = append(withShots, *o)
		svcs := make([]domain.ObservedService, len(o.Services))
		copy(svcs, o.Services)
		for j := range svcs {
			svcs[j].Screenshot = nil
		}
		o.Services = svcs
	}
	if len(withShots) == 0 || req.RunType != domain.ScanTypeActive {
		return
	}
	if box, ok := p.screenshots.Load().(screenshotSinkBox); ok && box.s != nil {
		box.s.StoreScreenshots(ctx, req.ScanRunID, withShots)
	}
}
