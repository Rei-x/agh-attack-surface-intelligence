package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Setting keys.
const (
	SettingTagRules = "tag_rules"
	SettingWebhook  = "webhook"
)

// SettingsStore is an optional extension (implemented by MemoryStore, FileStore and
// PostgresStore) holding small JSON settings documents, each encrypted at rest with the
// vault (AAD "app_settings:<key>:value"). Like ScheduleStateStore it is not part of Store so other
// Store implementations keep compiling; callers type-assert it.
type SettingsStore interface {
	// GetSetting decodes the setting into dst; found=false when it was never saved.
	GetSetting(ctx context.Context, key string, dst any) (bool, error)
	SaveSetting(ctx context.Context, key string, value any) error
}

var (
	_ SettingsStore = (*MemoryStore)(nil)
	_ SettingsStore = (*PostgresStore)(nil)
)

// settingAAD follows the "<table>:<id>:<column>" AAD convention so ReEncryptAll can rotate it.
func settingAAD(key string) string { return "app_settings:" + key + ":value" }

func (m *MemoryStore) GetSetting(_ context.Context, key string, dst any) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	enc, ok := m.settings[key]
	if !ok || enc == "" {
		return false, nil
	}
	if err := m.vault.DecryptJSON(enc, settingAAD(key), dst); err != nil {
		return false, err
	}
	return true, nil
}

func (m *MemoryStore) SaveSetting(_ context.Context, key string, value any) error {
	enc, err := m.vault.EncryptJSON(value, settingAAD(key))
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.unlockDirty() // persisted by the encrypted file store snapshot
	if m.settings == nil {
		m.settings = make(map[string]string)
	}
	m.settings[key] = enc
	return nil
}

func (s *PostgresStore) GetSetting(ctx context.Context, key string, dst any) (bool, error) {
	var enc string
	err := s.pool.QueryRow(ctx, `SELECT value_enc FROM app_settings WHERE key=$1`, key).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := s.vault.DecryptJSON(enc, settingAAD(key), dst); err != nil {
		return false, err
	}
	return true, nil
}

func (s *PostgresStore) SaveSetting(ctx context.Context, key string, value any) error {
	enc, err := s.vault.EncryptJSON(value, settingAAD(key))
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO app_settings (key, value_enc, updated_at) VALUES ($1,$2,$3)
		ON CONFLICT (key) DO UPDATE SET value_enc=EXCLUDED.value_enc, updated_at=EXCLUDED.updated_at`,
		key, enc, time.Now().UTC())
	return err
}
