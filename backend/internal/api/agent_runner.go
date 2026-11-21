package api

import (
	"context"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// AgentAwareRunner routes runs of agent-bound profiles (ScanProfile.AgentID) to the agent job
// queue and everything else to the local runner. Scheduler, run-now and pause/resume/stop all
// go through it, so the rest of the server does not care where a scan executes.
type AgentAwareRunner struct {
	ScanRunner
	Agents *agenthub.Coordinator
}

// NewAgentAwareRunner wraps a local runner (idempotent).
func NewAgentAwareRunner(local ScanRunner, agents *agenthub.Coordinator) *AgentAwareRunner {
	if ar, ok := local.(*AgentAwareRunner); ok {
		return ar
	}
	return &AgentAwareRunner{ScanRunner: local, Agents: agents}
}

func (r *AgentAwareRunner) StartScan(ctx context.Context, run *domain.ScanRun, profile *domain.ScanProfile, exclusions []domain.TargetExclusion) error {
	if profile != nil && profile.AgentID != "" && r.Agents != nil {
		return r.Agents.Enqueue(ctx, run, profile)
	}
	return r.ScanRunner.StartScan(ctx, run, profile, exclusions)
}

func (r *AgentAwareRunner) PauseScan(ctx context.Context, id string) error {
	if r.Agents != nil && r.Agents.IsAgentRun(id) {
		return r.Agents.Pause(ctx, id)
	}
	return r.ScanRunner.PauseScan(ctx, id)
}

func (r *AgentAwareRunner) ResumeScan(ctx context.Context, id string) error {
	if r.Agents != nil && r.Agents.IsAgentRun(id) {
		return r.Agents.Resume(ctx, id)
	}
	return r.ScanRunner.ResumeScan(ctx, id)
}

func (r *AgentAwareRunner) StopScan(ctx context.Context, id string) error {
	if r.Agents != nil && r.Agents.IsAgentRun(id) {
		return r.Agents.Stop(ctx, id)
	}
	return r.ScanRunner.StopScan(ctx, id)
}

// RecoverInterrupted forwards the scheduler's boot recovery to the local runner (which skips
// agent runs: those keep running on the agent across a server restart).
func (r *AgentAwareRunner) RecoverInterrupted(ctx context.Context) (int, error) {
	if rec, ok := r.ScanRunner.(interface {
		RecoverInterrupted(context.Context) (int, error)
	}); ok {
		return rec.RecoverInterrupted(ctx)
	}
	return 0, nil
}

// PublishEvent forwards scheduler events to the local runner's hub.
func (r *AgentAwareRunner) PublishEvent(ev domain.LiveEvent) {
	if p, ok := r.ScanRunner.(interface{ PublishEvent(domain.LiveEvent) }); ok {
		p.PublishEvent(ev)
	}
}
