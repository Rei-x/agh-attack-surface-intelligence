package db

import (
	"context"
	"errors"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// DefectDojo settings kept in the settings store (no schema change for the config table).
const (
	SettingDojoOptions = "defectdojo_options"
	SettingDojoSync    = "defectdojo_sync"
	SettingDojoLogin   = "defectdojo_login"
)

// LoadDefectDojoLogin returns the DefectDojo login shown in the header chip, nil when none
// is set. Like every settings document it is encrypted at rest with the vault.
func LoadDefectDojoLogin(ctx context.Context, store Store) (*domain.DefectDojoLogin, error) {
	ss, ok := store.(SettingsStore)
	if !ok {
		return nil, nil
	}
	var l domain.DefectDojoLogin
	if found, err := ss.GetSetting(ctx, SettingDojoLogin, &l); err != nil || !found {
		return nil, err
	}
	if l.Username == "" {
		return nil, nil
	}
	return &l, nil
}

// SaveDefectDojoLogin stores the login shown in the header chip; nil clears it.
func SaveDefectDojoLogin(ctx context.Context, store Store, l *domain.DefectDojoLogin) error {
	ss, ok := store.(SettingsStore)
	if !ok {
		return errors.New("store does not support settings")
	}
	if l == nil {
		l = &domain.DefectDojoLogin{}
	}
	return ss.SaveSetting(ctx, SettingDojoLogin, l)
}

type dojoOptions struct {
	AutoPushFindings bool `json:"auto_push_findings"`
}

// LoadDefectDojoConfig returns the stored DefectDojo config with the options kept in the
// settings store (auto_push_findings, on unless explicitly turned off).
func LoadDefectDojoConfig(ctx context.Context, store Store) (*domain.DefectDojoConfig, error) {
	cfg, err := store.GetDefectDojoConfig(ctx)
	if err != nil || cfg == nil {
		return cfg, err
	}
	opts := dojoOptions{AutoPushFindings: true}
	if ss, ok := store.(SettingsStore); ok {
		_, _ = ss.GetSetting(ctx, SettingDojoOptions, &opts)
	}
	cfg.AutoPushFindings = opts.AutoPushFindings
	return cfg, nil
}

// SaveDefectDojoOptions persists the settings-store part of the DefectDojo config.
func SaveDefectDojoOptions(ctx context.Context, store Store, cfg *domain.DefectDojoConfig) error {
	ss, ok := store.(SettingsStore)
	if !ok {
		return nil
	}
	return ss.SaveSetting(ctx, SettingDojoOptions, dojoOptions{AutoPushFindings: cfg.AutoPushFindings})
}

// LoadDefectDojoSync returns the last automatic sync state (zero value when none).
func LoadDefectDojoSync(ctx context.Context, store Store) domain.DefectDojoSyncState {
	var st domain.DefectDojoSyncState
	if ss, ok := store.(SettingsStore); ok {
		_, _ = ss.GetSetting(ctx, SettingDojoSync, &st)
	}
	return st
}

// SaveDefectDojoSync persists the sync state.
func SaveDefectDojoSync(ctx context.Context, store Store, st domain.DefectDojoSyncState) error {
	ss, ok := store.(SettingsStore)
	if !ok {
		return nil
	}
	return ss.SaveSetting(ctx, SettingDojoSync, st)
}
