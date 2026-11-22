package verify

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Settings keys (encrypted app_settings documents, so no schema change is needed).
const (
	settingResults  = "verify_results"
	settingProfiles = "verify_profiles"
)

// ProfileConfig is the per-profile opt-in. Both switches are off by default.
type ProfileConfig struct {
	Enabled      bool      `json:"enabled"`
	DefaultCreds bool      `json:"default_creds"`
	UpdatedBy    string    `json:"updated_by,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// Store keeps the latest verified findings per service and the per-profile configuration,
// cached in memory and persisted through db.SettingsStore.
type Store struct {
	settings db.SettingsStore // nil: memory only

	mu        sync.RWMutex
	loaded    bool
	byService map[string][]domain.VerifiedFinding
	profiles  map[string]ProfileConfig
	lastRun   map[string]RunSummary // profile id -> last run
}

// NewStore opens the store on a settings backend (nil keeps everything in memory).
func NewStore(settings db.SettingsStore) *Store {
	return &Store{settings: settings, byService: map[string][]domain.VerifiedFinding{}, profiles: map[string]ProfileConfig{}, lastRun: map[string]RunSummary{}}
}

type persisted struct {
	ByService map[string][]domain.VerifiedFinding `json:"by_service"`
	LastRun   map[string]RunSummary               `json:"last_run"`
}

func (s *Store) load(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded {
		return
	}
	s.loaded = true
	if s.settings == nil {
		return
	}
	var p persisted
	if ok, err := s.settings.GetSetting(ctx, settingResults, &p); err == nil && ok {
		if p.ByService != nil {
			s.byService = p.ByService
		}
		if p.LastRun != nil {
			s.lastRun = p.LastRun
		}
	}
	var profiles map[string]ProfileConfig
	if ok, err := s.settings.GetSetting(ctx, settingProfiles, &profiles); err == nil && ok && profiles != nil {
		s.profiles = profiles
	}
}

// ForService returns the latest verified findings of a service.
func (s *Store) ForService(id string) []domain.VerifiedFinding {
	if id == "" {
		return nil
	}
	s.load(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	f := s.byService[id]
	if len(f) == 0 {
		return nil
	}
	return append([]domain.VerifiedFinding(nil), f...)
}

// Record replaces the findings of every checked service (a check that answered without
// confirming clears its earlier finding: the exposure was fixed) and stores the run summary.
// Findings of checks that could not complete this time (inconclusive: service down,
// timeout) are kept.
func (s *Store) Record(ctx context.Context, checked []string, findings []domain.VerifiedFinding, sum RunSummary, inconclusive map[string][]string) error {
	s.load(ctx)
	s.mu.Lock()
	for _, id := range checked {
		var kept []domain.VerifiedFinding
		for _, f := range s.byService[id] {
			for _, c := range inconclusive[id] {
				if c == f.CheckID {
					kept = append(kept, f)
					break
				}
			}
		}
		if len(kept) > 0 {
			s.byService[id] = kept
		} else {
			delete(s.byService, id)
		}
	}
	for _, f := range findings {
		s.byService[f.ServiceID] = append(s.byService[f.ServiceID], f)
	}
	if sum.ProfileID != "" {
		s.lastRun[sum.ProfileID] = sum
	}
	p := persisted{ByService: s.byService, LastRun: s.lastRun}
	var err error
	if s.settings != nil {
		err = s.settings.SaveSetting(ctx, settingResults, p)
	}
	s.mu.Unlock()
	return err
}

// All returns every stored finding, most severe first.
func (s *Store) All() []domain.VerifiedFinding {
	s.load(context.Background())
	s.mu.RLock()
	var out []domain.VerifiedFinding
	for _, f := range s.byService {
		out = append(out, f...)
	}
	s.mu.RUnlock()
	return sortFindings(out)
}

// LastRun returns the summary of a profile's last verification run.
func (s *Store) LastRun(profileID string) (RunSummary, bool) {
	s.load(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.lastRun[profileID]
	return r, ok
}

// Profile returns a profile's configuration (zero value = off).
func (s *Store) Profile(id string) ProfileConfig {
	s.load(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.profiles[id]
}

// Profiles returns every configured profile.
func (s *Store) Profiles() map[string]ProfileConfig {
	s.load(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]ProfileConfig, len(s.profiles))
	for k, v := range s.profiles {
		out[k] = v
	}
	return out
}

// SetProfile saves a profile's configuration. Default credentials require Verify itself.
func (s *Store) SetProfile(ctx context.Context, id string, cfg ProfileConfig) error {
	s.load(ctx)
	if !cfg.Enabled {
		cfg.DefaultCreds = false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profiles[id] = cfg
	if s.settings == nil {
		return nil
	}
	return s.settings.SaveSetting(ctx, settingProfiles, s.profiles)
}

// RunSummary describes one verification run.
type RunSummary struct {
	ProfileID   string         `json:"profile_id"`
	ProfileName string         `json:"profile_name"`
	ScanRunID   string         `json:"scan_run_id,omitempty"`
	Trigger     string         `json:"trigger"` // scan, manual
	StartedAt   time.Time      `json:"started_at"`
	FinishedAt  time.Time      `json:"finished_at"`
	Stats       Stats          `json:"stats"`
	BySeverity  map[string]int `json:"by_severity"`
	Checks      []string       `json:"checks"` // ids of the checks that confirmed something
	Error       string         `json:"error,omitempty"`
}

func summarize(f []domain.VerifiedFinding) (map[string]int, []string) {
	sev := map[string]int{}
	ids := map[string]bool{}
	for _, x := range f {
		sev[x.Severity]++
		ids[x.CheckID] = true
	}
	var list []string
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)
	return sev, list
}
