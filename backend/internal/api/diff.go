package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

// ChangedServiceDiff describes a before/after diff for a service between two scans.
type ChangedServiceDiff struct {
	HostID   string         `json:"host_id"`
	HostIP   string         `json:"host_ip"`
	Port     int            `json:"port"`
	Protocol string         `json:"protocol"`
	Before   map[string]any `json:"before"`
	After    map[string]any `json:"after"`
	Summary  string         `json:"summary"`
}

// ScanDiffSummary holds aggregate counters for GET /api/v1/scans/diff.
type ScanDiffSummary struct {
	NewHostsCount        int `json:"new_hosts"`
	MissingHostsCount    int `json:"missing_hosts"`
	NewServicesCount     int `json:"new_services"`
	ClosedServicesCount  int `json:"closed_services"`
	ChangedServicesCount int `json:"changed_services"`
	TimeAnomaliesCount   int `json:"time_anomalies"`
}

// ScanDiffResponse is returned by GET /api/v1/scans/diff?from=A&to=B.
type ScanDiffResponse struct {
	FromScanID      string               `json:"from_scan_id"`
	ToScanID        string               `json:"to_scan_id"`
	NewHosts        []domain.Host        `json:"new_hosts"`
	MissingHosts    []domain.Host        `json:"missing_hosts"`
	NewServices     []domain.Service     `json:"new_services"`
	ClosedServices  []domain.Service     `json:"closed_services"`
	ChangedServices []ChangedServiceDiff `json:"changed_services"`
	TimeAnomalies   []domain.ChangeEvent `json:"time_anomalies"`
	Summary         ScanDiffSummary      `json:"summary"`
}

// RetiredSnapshotError explains why a run has no inventory snapshot when history retention
// removed it (db.RetentionPolicy.SnapshotRuns): the run completed and found hosts, so it
// had one. It returns nil for every other lookup error (empty or failed runs never had a
// snapshot and keep diffing against an empty inventory).
func RetiredSnapshotError(ctx context.Context, store db.Store, runID string, lookupErr error) error {
	if !errors.Is(lookupErr, db.ErrNotFound) {
		return nil
	}
	run, err := store.GetScanRun(ctx, runID)
	if err != nil || run.Status != domain.ScanStatusCompleted || run.ActiveHosts == 0 {
		return nil
	}
	return fmt.Errorf("the inventory snapshot of run %q was removed by history retention, which keeps snapshots of the newest runs (DZIECIOL_RETENTION_SNAPSHOTS); compare newer runs", run.Name)
}

// ComputeScanDiff compares two scan snapshots and associated change events.
func ComputeScanDiff(fromID, toID string, fromHosts, toHosts []domain.Host, toChanges []domain.ChangeEvent) ScanDiffResponse {
	resp := ScanDiffResponse{
		FromScanID:      fromID,
		ToScanID:        toID,
		NewHosts:        []domain.Host{},
		MissingHosts:    []domain.Host{},
		NewServices:     []domain.Service{},
		ClosedServices:  []domain.Service{},
		ChangedServices: []ChangedServiceDiff{},
		TimeAnomalies:   []domain.ChangeEvent{},
	}

	fromMap := make(map[string]domain.Host, len(fromHosts))
	for _, h := range fromHosts {
		fromMap[h.IP] = h
	}
	toMap := make(map[string]domain.Host, len(toHosts))
	for _, h := range toHosts {
		toMap[h.IP] = h
	}

	for ip, th := range toMap {
		fh, existed := fromMap[ip]
		if !existed {
			resp.NewHosts = append(resp.NewHosts, th)
			resp.NewServices = append(resp.NewServices, th.Services...)
			continue
		}
		if (th.LifecycleState == domain.HostStateMissing || th.LifecycleState == domain.HostStateInactive) &&
			fh.LifecycleState != domain.HostStateMissing && fh.LifecycleState != domain.HostStateInactive {
			resp.MissingHosts = append(resp.MissingHosts, th)
		}

		fromSvcs := make(map[string]domain.Service, len(fh.Services))
		for _, s := range fh.Services {
			fromSvcs[fmt.Sprintf("%d/%s", s.Port, s.Protocol)] = s
		}
		toSvcs := make(map[string]domain.Service, len(th.Services))
		for _, s := range th.Services {
			toSvcs[fmt.Sprintf("%d/%s", s.Port, s.Protocol)] = s
		}

		for k, ts := range toSvcs {
			fs, ok := fromSvcs[k]
			if !ok {
				resp.NewServices = append(resp.NewServices, ts)
				continue
			}
			if ts.State == "closed" && fs.State == "open" {
				resp.ClosedServices = append(resp.ClosedServices, ts)
				continue
			}
			if ts.State == "open" && fs.State != "" && fs.State != "open" {
				resp.NewServices = append(resp.NewServices, ts) // reopened
				continue
			}
			before := map[string]any{}
			after := map[string]any{}
			// An empty new value is "not observed this time", not a change.
			if fs.Product != ts.Product && ts.Product != "" {
				before["product"] = fs.Product
				after["product"] = ts.Product
			}
			if fs.Version != ts.Version && ts.Version != "" {
				before["version"] = fs.Version
				after["version"] = ts.Version
			}
			if fs.Banner != ts.Banner && ts.Banner != "" {
				before["banner"] = fs.Banner
				after["banner"] = ts.Banner
			}
			if fs.IsAdminPanel != ts.IsAdminPanel {
				before["is_admin_panel"] = fs.IsAdminPanel
				after["is_admin_panel"] = ts.IsAdminPanel
			}
			fsTitle, tsTitle := "", ""
			if fs.HTTP != nil {
				fsTitle = fs.HTTP.Title
			}
			if ts.HTTP != nil {
				tsTitle = ts.HTTP.Title
			}
			if fsTitle != tsTitle && tsTitle != "" {
				before["http_title"] = fsTitle
				after["http_title"] = tsTitle
			}
			if fs.HTTP != nil && ts.HTTP != nil {
				b, a := ingest.ServiceResponseMs(fs.HTTP), ingest.ServiceResponseMs(ts.HTTP)
				if slower, faster := ingest.ResponseTimeJump(b, a); slower || faster {
					before["response_time_ms"] = b
					after["response_time_ms"] = a
				}
			}
			if len(after) > 0 {
				resp.ChangedServices = append(resp.ChangedServices, ChangedServiceDiff{
					HostID:   th.ID,
					HostIP:   th.IP,
					Port:     ts.Port,
					Protocol: ts.Protocol,
					Before:   before,
					After:    after,
					Summary:  fmt.Sprintf("%s:%d/%s attributes changed", th.IP, ts.Port, ts.Protocol),
				})
			}
		}

		for k, fs := range fromSvcs {
			if _, ok := toSvcs[k]; !ok {
				resp.ClosedServices = append(resp.ClosedServices, fs)
			}
		}
	}

	for ip, fh := range fromMap {
		if _, ok := toMap[ip]; !ok {
			resp.MissingHosts = append(resp.MissingHosts, fh)
		}
	}

	for _, ev := range toChanges {
		if ev.IsTimeAnomaly {
			resp.TimeAnomalies = append(resp.TimeAnomalies, ev)
		}
	}

	resp.Summary = ScanDiffSummary{
		NewHostsCount:        len(resp.NewHosts),
		MissingHostsCount:    len(resp.MissingHosts),
		NewServicesCount:     len(resp.NewServices),
		ClosedServicesCount:  len(resp.ClosedServices),
		ChangedServicesCount: len(resp.ChangedServices),
		TimeAnomaliesCount:   len(resp.TimeAnomalies),
	}
	return resp
}
