package db

import (
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// AllowedHostOverrideFields lists fields analysts may pin on a Host.
var AllowedHostOverrideFields = map[string]bool{
	"hostname":        true,
	"environment":     true,
	"owner":           true,
	"notes":           true,
	"tags":            true,
	"lifecycle_state": true,
	"triage":          true, // domain.TriageInfo (accepted_risk / false_positive with reason + expiry)
}

// AllowedServiceOverrideFields lists fields analysts may pin on a Service.
var AllowedServiceOverrideFields = map[string]bool{
	"service_name":  true,
	"product":       true,
	"version":       true,
	"http_title":    true,
	"notes":         true,
	"tags":          true,
	"triage_status": true,
	"triage":        true, // domain.TriageInfo (accepted_risk / false_positive with reason + expiry)
}

// MergeHostWithOverrides overlays analyst-pinned fields onto a scanner-observed Host.
// Later scans never overwrite analyst overrides; whenever the scanner observes a
// different value than the override, the observed value is exposed in ScannerObserved.
func MergeHostWithOverrides(host *domain.Host, overrides map[string]any) {
	if host == nil || len(overrides) == 0 {
		return
	}
	locked := make([]string, 0, len(overrides))
	observed := make(map[string]any)

	for field, val := range overrides {
		if !AllowedHostOverrideFields[field] {
			continue
		}
		locked = append(locked, field)

		switch field {
		case "hostname":
			s := toString(val)
			if host.Hostname != "" && host.Hostname != s {
				observed[field] = host.Hostname
			}
			host.Hostname = s
		case "environment":
			s := toString(val)
			if host.Environment != "" && host.Environment != s {
				observed[field] = host.Environment
			}
			host.Environment = s
		case "owner":
			s := toString(val)
			if host.Owner != "" && host.Owner != s {
				observed[field] = host.Owner
			}
			host.Owner = s
		case "notes":
			s := toString(val)
			if host.Notes != "" && host.Notes != s {
				observed[field] = host.Notes
			}
			host.Notes = s
		case "lifecycle_state":
			s := toString(val)
			if host.LifecycleState != "" && host.LifecycleState != s {
				observed[field] = host.LifecycleState
			}
			host.LifecycleState = s
		case "tags":
			tags := toStringSlice(val)
			if len(host.Tags) > 0 && !reflect.DeepEqual(host.Tags, tags) {
				observed[field] = host.Tags
			}
			host.Tags = tags
		case "triage":
			t := DecodeTriage(val)
			if t == nil {
				continue
			}
			host.Triage = t
			if t.Expired {
				host.TriageStatus = ""
			} else {
				host.TriageStatus = t.Status
			}
		}
	}

	sort.Strings(locked)
	host.LockedFields = locked
	if len(observed) > 0 {
		host.ScannerObserved = observed
	} else {
		host.ScannerObserved = nil
	}
}

// MergeServiceWithOverrides overlays analyst-pinned fields onto a scanner-observed Service.
func MergeServiceWithOverrides(svc *domain.Service, overrides map[string]any) {
	if svc == nil || len(overrides) == 0 {
		return
	}
	locked := make([]string, 0, len(overrides))
	observed := make(map[string]any)

	for field, val := range overrides {
		if !AllowedServiceOverrideFields[field] {
			continue
		}
		locked = append(locked, field)

		switch field {
		case "service_name":
			s := toString(val)
			if svc.ServiceName != "" && svc.ServiceName != s {
				observed[field] = svc.ServiceName
			}
			svc.ServiceName = s
		case "product":
			s := toString(val)
			if svc.Product != "" && svc.Product != s {
				observed[field] = svc.Product
			}
			svc.Product = s
		case "version":
			s := toString(val)
			if svc.Version != "" && svc.Version != s {
				observed[field] = svc.Version
			}
			svc.Version = s
		case "http_title":
			s := toString(val)
			if svc.HTTP == nil {
				svc.HTTP = &domain.HTTPFingerprint{}
			}
			if svc.HTTP.Title != "" && svc.HTTP.Title != s {
				observed[field] = svc.HTTP.Title
			}
			svc.HTTP.Title = s
		case "notes":
			s := toString(val)
			if svc.Notes != "" && svc.Notes != s {
				observed[field] = svc.Notes
			}
			svc.Notes = s
		case "triage_status":
			s := toString(val)
			if svc.TriageStatus != "" && svc.TriageStatus != s {
				observed[field] = svc.TriageStatus
			}
			svc.TriageStatus = s
		case "tags":
			tags := toStringSlice(val)
			if len(svc.Tags) > 0 && !reflect.DeepEqual(svc.Tags, tags) {
				observed[field] = svc.Tags
			}
			svc.Tags = tags
		case "triage":
			t := DecodeTriage(val)
			if t == nil {
				continue
			}
			svc.Triage = t
			base := svc.TriageStatus
			if base == domain.TriageAcceptedRisk || base == domain.TriageFalsePositive {
				// An observed row can carry a decision copied from an earlier merged read;
				// never let it outlive the override.
				base = domain.TriageNew
			}
			if base == "" {
				base = domain.TriageNew
			}
			if t.Expired {
				// Expired acceptance: the finding is active again.
				svc.TriageStatus = base
			} else {
				observed["triage_status"] = base
				svc.TriageStatus = t.Status
			}
		}
	}

	sort.Strings(locked)
	svc.LockedFields = locked
	if len(observed) > 0 {
		svc.ScannerObserved = observed
	} else {
		svc.ScannerObserved = nil
	}
}

// DecodeTriage converts a decrypted "triage" override value into a TriageInfo and evaluates
// its expiry against the current time. Returns nil for malformed values.
func DecodeTriage(v any) *domain.TriageInfo {
	return decodeTriageAt(v, time.Now())
}

func decodeTriageAt(v any, now time.Time) *domain.TriageInfo {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var t domain.TriageInfo
	if err := json.Unmarshal(raw, &t); err != nil || t.Status == "" {
		return nil
	}
	t.Expired = t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)
	return &t
}

func toString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toStringSlice(v any) []string {
	if v == nil {
		return []string{}
	}
	switch t := v.(type) {
	case []string:
		out := make([]string, len(t))
		copy(out, t)
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{}
	}
}
