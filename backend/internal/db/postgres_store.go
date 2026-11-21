package db

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

//go:embed migrations/001_init.sql
var initMigrationSQL string

// PostgresStore implements Store backed by PostgreSQL 17 with AES-256-GCM encryption at rest.
type PostgresStore struct {
	pool  *pgxpool.Pool
	vault *crypto.Vault
}

// NewPostgresStore connects to PostgreSQL, executes embedded migrations, and restores/persists DEKs.
func NewPostgresStore(ctx context.Context, databaseURL string, vault *crypto.Vault) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	s := &PostgresStore{pool: pool, vault: vault}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	// Restore existing wrapped DEKs or persist initial DEK
	keys, activeKID, err := s.LoadCryptoKeys(ctx)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("load crypto keys: %w", err)
	}
	if len(keys) > 0 {
		if err := vault.LoadWrappedDEKs(keys, activeKID); err != nil {
			pool.Close()
			return nil, fmt.Errorf("unwrap crypto keys: %w", err)
		}
	} else {
		wrappedMap, active := vault.ExportWrappedDEKs()
		for kid, w := range wrappedMap {
			if err := s.SaveCryptoKey(ctx, kid, w, kid == active); err != nil {
				pool.Close()
				return nil, fmt.Errorf("persist initial DEK: %w", err)
			}
		}
	}
	return s, nil
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, initMigrationSQL); err != nil {
		return fmt.Errorf("run 001_init.sql migration: %w", err)
	}
	return nil
}

func (s *PostgresStore) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
func (s *PostgresStore) Close()                         { s.pool.Close() }
func (s *PostgresStore) BackendName() string            { return "postgres" }

// --- Crypto Keys & Rotation ---

func (s *PostgresStore) LoadCryptoKeys(ctx context.Context) (map[string]string, string, error) {
	rows, err := s.pool.Query(ctx, `SELECT kid, wrapped_dek, is_active FROM crypto_keys`)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := make(map[string]string)
	active := ""
	for rows.Next() {
		var kid, wrapped string
		var isActive bool
		if err := rows.Scan(&kid, &wrapped, &isActive); err != nil {
			return nil, "", err
		}
		out[kid] = wrapped
		if isActive {
			active = kid
		}
	}
	return out, active, rows.Err()
}

func (s *PostgresStore) SaveCryptoKey(ctx context.Context, kid, wrapped string, active bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if active {
		if _, err := tx.Exec(ctx, `UPDATE crypto_keys SET is_active = FALSE WHERE is_active = TRUE`); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO crypto_keys (kid, wrapped_dek, is_active)
		VALUES ($1, $2, $3)
		ON CONFLICT (kid) DO UPDATE SET wrapped_dek = EXCLUDED.wrapped_dek, is_active = EXCLUDED.is_active`,
		kid, wrapped, active)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ReEncryptAll(ctx context.Context) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	count := 0

	reencCol := func(table, col, idCol string) error {
		rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT %s, %s FROM %s WHERE %s <> ''`, idCol, col, table, col))
		if err != nil {
			return err
		}
		type item struct{ id, val string }
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.val); err != nil {
				rows.Close()
				return err
			}
			items = append(items, it)
		}
		rows.Close()
		aadCol := strings.TrimSuffix(col, "_enc")
		for _, it := range items {
			aad := table + ":" + it.id + ":" + aadCol
			newCT, changed, err := s.vault.ReEncrypt(it.val, aad)
			if err != nil {
				return err
			}
			if changed {
				if _, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s = $2`, table, col, idCol), newCT, it.id); err != nil {
					return err
				}
				count++
			}
		}
		return nil
	}

	cols := [][3]string{
		{"users", "email_enc", "id"},
		{"hosts", "ip_enc", "id"},
		{"hosts", "hostname_enc", "id"},
		{"hosts", "domains_enc", "id"},
		{"hosts", "os_guess_enc", "id"},
		{"hosts", "notes_enc", "id"},
		{"services", "banner_enc", "id"},
		{"services", "http_enc", "id"},
		{"services", "notes_enc", "id"},
		{"service_observations", "banner_enc", "id"},
		{"service_observations", "http_enc", "id"},
		{"scan_runs", "notes_enc", "id"},
		{"scan_runs", "raw_nmap_xml_enc", "id"},
		{"change_events", "host_ip_enc", "id"},
		{"change_events", "before_enc", "id"},
		{"change_events", "after_enc", "id"},
		{"scan_snapshots", "payload_enc", "scan_run_id"},
		{"defectdojo_config", "api_token_enc", "id"},
	}
	for _, c := range cols {
		if err := reencCol(c[0], c[1], c[2]); err != nil {
			return count, err
		}
	}

	// Re-encrypt asset_overrides (composite PK)
	ovRows, err := tx.Query(ctx, `SELECT entity_type, entity_id, field, value_enc FROM asset_overrides`)
	if err != nil {
		return count, err
	}
	type ovItem struct{ et, eid, field, val string }
	var ovs []ovItem
	for ovRows.Next() {
		var o ovItem
		if err := ovRows.Scan(&o.et, &o.eid, &o.field, &o.val); err != nil {
			ovRows.Close()
			return count, err
		}
		ovs = append(ovs, o)
	}
	ovRows.Close()
	for _, o := range ovs {
		aad := "asset_overrides:" + o.et + ":" + o.eid + ":" + o.field
		newCT, changed, err := s.vault.ReEncrypt(o.val, aad)
		if err != nil {
			return count, err
		}
		if changed {
			_, err := tx.Exec(ctx, `UPDATE asset_overrides SET value_enc = $1 WHERE entity_type=$2 AND entity_id=$3 AND field=$4`,
				newCT, o.et, o.eid, o.field)
			if err != nil {
				return count, err
			}
			count++
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return count, err
	}
	return count, nil
}

func (s *PostgresStore) GetCryptoProofSample(ctx context.Context) (*CryptoProofSample, error) {
	var id, ipEnc, ipHMAC string
	err := s.pool.QueryRow(ctx, `SELECT id, ip_enc, ip_hmac FROM hosts WHERE ip_enc <> '' ORDER BY last_seen DESC LIMIT 1`).Scan(&id, &ipEnc, &ipHMAC)
	if err == nil {
		aad := "hosts:" + id + ":ip"
		plain, decErr := s.vault.Decrypt(ipEnc, aad)
		if decErr != nil {
			return nil, decErr
		}
		return &CryptoProofSample{
			Table:           "hosts",
			RecordID:        id,
			Column:          "ip_enc",
			AAD:             aad,
			RawCiphertext:   ipEnc,
			DecryptedSample: plain,
			BlindIndexCol:   "ip_hmac",
			BlindIndexValue: ipHMAC,
		}, nil
	}
	var uid, emailEnc string
	err = s.pool.QueryRow(ctx, `SELECT id, email_enc FROM users WHERE email_enc <> '' LIMIT 1`).Scan(&uid, &emailEnc)
	if err == nil {
		aad := "users:" + uid + ":email"
		plain, decErr := s.vault.Decrypt(emailEnc, aad)
		if decErr != nil {
			return nil, decErr
		}
		return &CryptoProofSample{
			Table:           "users",
			RecordID:        uid,
			Column:          "email_enc",
			AAD:             aad,
			RawCiphertext:   emailEnc,
			DecryptedSample: plain,
		}, nil
	}
	aad := "crypto_self_test:sample:payload"
	sample := "172.28.0.10"
	ct, err := s.vault.Encrypt(sample, aad)
	if err != nil {
		return nil, err
	}
	return &CryptoProofSample{
		Table:           "crypto_self_test",
		RecordID:        "sample",
		Column:          "payload",
		AAD:             aad,
		RawCiphertext:   ct,
		DecryptedSample: sample,
		BlindIndexCol:   "ip_hmac",
		BlindIndexValue: s.vault.BlindIndex(sample),
	}, nil
}

// --- Roles & Users ---

func (s *PostgresStore) loadRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT permission FROM role_permissions WHERE role_id = $1 ORDER BY permission`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	perms := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

func (s *PostgresStore) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, slug, name, description, is_system, created_at FROM roles ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Role
	for rows.Next() {
		var r domain.Role
		if err := rows.Scan(&r.ID, &r.Slug, &r.Name, &r.Description, &r.IsSystem, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		perms, err := s.loadRolePermissions(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Permissions = perms
	}
	return out, nil
}

func (s *PostgresStore) GetRole(ctx context.Context, id string) (*domain.Role, error) {
	var r domain.Role
	err := s.pool.QueryRow(ctx, `SELECT id, slug, name, description, is_system, created_at FROM roles WHERE id = $1`, id).
		Scan(&r.ID, &r.Slug, &r.Name, &r.Description, &r.IsSystem, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Permissions, err = s.loadRolePermissions(ctx, r.ID)
	return &r, err
}

func (s *PostgresStore) GetRoleBySlug(ctx context.Context, slug string) (*domain.Role, error) {
	var r domain.Role
	err := s.pool.QueryRow(ctx, `SELECT id, slug, name, description, is_system, created_at FROM roles WHERE slug = $1`, slug).
		Scan(&r.ID, &r.Slug, &r.Name, &r.Description, &r.IsSystem, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Permissions, err = s.loadRolePermissions(ctx, r.ID)
	return &r, err
}

func (s *PostgresStore) CreateRole(ctx context.Context, role *domain.Role) error {
	if role.ID == "" {
		role.ID = NewID()
	}
	if role.CreatedAt.IsZero() {
		role.CreatedAt = time.Now().UTC()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO roles (id, slug, name, description, is_system, created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		role.ID, role.Slug, role.Name, role.Description, role.IsSystem, role.CreatedAt)
	if err != nil {
		return err
	}
	for _, p := range role.Permissions {
		if _, err := tx.Exec(ctx, `INSERT INTO role_permissions (role_id, permission) VALUES ($1,$2) ON CONFLICT DO NOTHING`, role.ID, p); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) UpdateRole(ctx context.Context, role *domain.Role) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE roles SET name=$1, description=$2 WHERE id=$3`, role.Name, role.Description, role.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1`, role.ID); err != nil {
		return err
	}
	for _, p := range role.Permissions {
		if _, err := tx.Exec(ctx, `INSERT INTO role_permissions (role_id, permission) VALUES ($1,$2) ON CONFLICT DO NOTHING`, role.ID, p); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) DeleteRole(ctx context.Context, id string) error {
	var isSys bool
	err := s.pool.QueryRow(ctx, `SELECT is_system FROM roles WHERE id=$1`, id).Scan(&isSys)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if isSys {
		return errors.New("cannot delete system role")
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM roles WHERE id=$1`, id)
	return err
}

func (s *PostgresStore) scanUser(ctx context.Context, query string, arg any) (*domain.User, error) {
	var u domain.User
	var emailEnc string
	err := s.pool.QueryRow(ctx, query, arg).Scan(
		&u.ID, &u.Username, &emailEnc, &u.PasswordHash, &u.RoleID, &u.Active, &u.CreatedAt, &u.RoleSlug, &u.RoleName,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Email, err = s.vault.Decrypt(emailEnc, "users:"+u.ID+":email")
	if err != nil {
		return nil, err
	}
	u.Permissions, err = s.loadRolePermissions(ctx, u.RoleID)
	return &u, err
}

func (s *PostgresStore) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.username, u.email_enc, u.password_hash, u.role_id, u.active, u.created_at, r.slug, r.name
		FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		var u domain.User
		var emailEnc string
		if err := rows.Scan(&u.ID, &u.Username, &emailEnc, &u.PasswordHash, &u.RoleID, &u.Active, &u.CreatedAt, &u.RoleSlug, &u.RoleName); err != nil {
			return nil, err
		}
		u.Email, err = s.vault.Decrypt(emailEnc, "users:"+u.ID+":email")
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Permissions, err = s.loadRolePermissions(ctx, out[i].RoleID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *PostgresStore) GetUser(ctx context.Context, id string) (*domain.User, error) {
	return s.scanUser(ctx, `
		SELECT u.id, u.username, u.email_enc, u.password_hash, u.role_id, u.active, u.created_at, r.slug, r.name
		FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1`, id)
}

func (s *PostgresStore) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	return s.scanUser(ctx, `
		SELECT u.id, u.username, u.email_enc, u.password_hash, u.role_id, u.active, u.created_at, r.slug, r.name
		FROM users u JOIN roles r ON r.id = u.role_id WHERE LOWER(u.username) = LOWER($1)`, username)
}

func (s *PostgresStore) CreateUser(ctx context.Context, user *domain.User) error {
	if user.ID == "" {
		user.ID = NewID()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	emailEnc, err := s.vault.Encrypt(user.Email, "users:"+user.ID+":email")
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO users (id, username, email_enc, password_hash, role_id, active, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		user.ID, user.Username, emailEnc, user.PasswordHash, user.RoleID, user.Active, user.CreatedAt)
	return err
}

func (s *PostgresStore) UpdateUser(ctx context.Context, user *domain.User) error {
	existing, err := s.GetUser(ctx, user.ID)
	if err != nil {
		return err
	}
	email := existing.Email
	if user.Email != "" {
		email = user.Email
	}
	emailEnc, err := s.vault.Encrypt(email, "users:"+user.ID+":email")
	if err != nil {
		return err
	}
	pw := existing.PasswordHash
	if user.PasswordHash != "" {
		pw = user.PasswordHash
	}
	roleID := existing.RoleID
	if user.RoleID != "" {
		roleID = user.RoleID
	}
	_, err = s.pool.Exec(ctx, `UPDATE users SET email_enc=$1, password_hash=$2, role_id=$3, active=$4 WHERE id=$5`,
		emailEnc, pw, roleID, user.Active, user.ID)
	return err
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Targets & Exclusions ---

func (s *PostgresStore) ListTargets(ctx context.Context) ([]domain.Target, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, value, kind, label, tags, enabled, created_by, created_at FROM targets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Target{}
	for rows.Next() {
		var t domain.Target
		var tagsRaw []byte
		if err := rows.Scan(&t.ID, &t.Value, &t.Kind, &t.Label, &tagsRaw, &t.Enabled, &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tagsRaw, &t.Tags)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateTarget(ctx context.Context, t *domain.Target) error {
	if t.ID == "" {
		t.ID = NewID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	tagsJSON, _ := json.Marshal(nonNilSlice(t.Tags))
	_, err := s.pool.Exec(ctx, `INSERT INTO targets (id, value, kind, label, tags, enabled, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		t.ID, t.Value, t.Kind, t.Label, tagsJSON, t.Enabled, t.CreatedBy, t.CreatedAt)
	return err
}

func (s *PostgresStore) DeleteTarget(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM targets WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) ListExclusions(ctx context.Context) ([]domain.TargetExclusion, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, value, reason, created_by, created_at FROM target_exclusions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.TargetExclusion{}
	for rows.Next() {
		var ex domain.TargetExclusion
		if err := rows.Scan(&ex.ID, &ex.Value, &ex.Reason, &ex.CreatedBy, &ex.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, ex)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateExclusion(ctx context.Context, ex *domain.TargetExclusion) error {
	if ex.ID == "" {
		ex.ID = NewID()
	}
	if ex.CreatedAt.IsZero() {
		ex.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO target_exclusions (id, value, reason, created_by, created_at) VALUES ($1,$2,$3,$4,$5)`,
		ex.ID, ex.Value, ex.Reason, ex.CreatedBy, ex.CreatedAt)
	return err
}

func (s *PostgresStore) DeleteExclusion(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM target_exclusions WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Profiles ---

func (s *PostgresStore) ListProfiles(ctx context.Context) ([]domain.ScanProfile, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, description, targets, allowed_ports, max_rate_pps, http_rps, concurrency, chunk_target_sec,
		       schedule_cron, window_enabled, window_start, window_end, timezone, missing_threshold, grace_period_hours,
		       retry_unstable_count, enable_http_fingerprint, user_agent, enabled, created_at, updated_at
		FROM scan_profiles ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ScanProfile{}
	for rows.Next() {
		var p domain.ScanProfile
		var targetsRaw []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &targetsRaw, &p.AllowedPorts, &p.MaxRatePPS, &p.HTTPRPS, &p.Concurrency,
			&p.ChunkTargetSec, &p.ScheduleCron, &p.WindowEnabled, &p.WindowStart, &p.WindowEnd, &p.Timezone, &p.MissingThreshold,
			&p.GracePeriodHours, &p.RetryUnstableCount, &p.EnableHTTPFingerprint, &p.UserAgent, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targetsRaw, &p.Targets)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetProfile(ctx context.Context, id string) (*domain.ScanProfile, error) {
	var p domain.ScanProfile
	var targetsRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, description, targets, allowed_ports, max_rate_pps, http_rps, concurrency, chunk_target_sec,
		       schedule_cron, window_enabled, window_start, window_end, timezone, missing_threshold, grace_period_hours,
		       retry_unstable_count, enable_http_fingerprint, user_agent, enabled, created_at, updated_at
		FROM scan_profiles WHERE id=$1`, id).
		Scan(&p.ID, &p.Name, &p.Description, &targetsRaw, &p.AllowedPorts, &p.MaxRatePPS, &p.HTTPRPS, &p.Concurrency,
			&p.ChunkTargetSec, &p.ScheduleCron, &p.WindowEnabled, &p.WindowStart, &p.WindowEnd, &p.Timezone, &p.MissingThreshold,
			&p.GracePeriodHours, &p.RetryUnstableCount, &p.EnableHTTPFingerprint, &p.UserAgent, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(targetsRaw, &p.Targets)
	return &p, nil
}

func (s *PostgresStore) CreateProfile(ctx context.Context, p *domain.ScanProfile) error {
	if p.ID == "" {
		p.ID = NewID()
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	targetsJSON, _ := json.Marshal(nonNilSlice(p.Targets))
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_profiles (id, name, description, targets, allowed_ports, max_rate_pps, http_rps, concurrency, chunk_target_sec,
		       schedule_cron, window_enabled, window_start, window_end, timezone, missing_threshold, grace_period_hours,
		       retry_unstable_count, enable_http_fingerprint, user_agent, enabled, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
		p.ID, p.Name, p.Description, targetsJSON, p.AllowedPorts, p.MaxRatePPS, p.HTTPRPS, p.Concurrency, p.ChunkTargetSec,
		p.ScheduleCron, p.WindowEnabled, p.WindowStart, p.WindowEnd, p.Timezone, p.MissingThreshold, p.GracePeriodHours,
		p.RetryUnstableCount, p.EnableHTTPFingerprint, p.UserAgent, p.Enabled, p.CreatedAt, p.UpdatedAt)
	return err
}

func (s *PostgresStore) UpdateProfile(ctx context.Context, p *domain.ScanProfile) error {
	p.UpdatedAt = time.Now().UTC()
	targetsJSON, _ := json.Marshal(nonNilSlice(p.Targets))
	tag, err := s.pool.Exec(ctx, `
		UPDATE scan_profiles SET name=$1, description=$2, targets=$3, allowed_ports=$4, max_rate_pps=$5, http_rps=$6,
		       concurrency=$7, chunk_target_sec=$8, schedule_cron=$9, window_enabled=$10, window_start=$11, window_end=$12,
		       timezone=$13, missing_threshold=$14, grace_period_hours=$15, retry_unstable_count=$16,
		       enable_http_fingerprint=$17, user_agent=$18, enabled=$19, updated_at=$20
		WHERE id=$21`,
		p.Name, p.Description, targetsJSON, p.AllowedPorts, p.MaxRatePPS, p.HTTPRPS, p.Concurrency, p.ChunkTargetSec,
		p.ScheduleCron, p.WindowEnabled, p.WindowStart, p.WindowEnd, p.Timezone, p.MissingThreshold, p.GracePeriodHours,
		p.RetryUnstableCount, p.EnableHTTPFingerprint, p.UserAgent, p.Enabled, p.UpdatedAt, p.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) DeleteProfile(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scan_profiles WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Scan Runs & Chunks ---

func (s *PostgresStore) ListScanRuns(ctx context.Context, limit int) ([]domain.ScanRun, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, profile_id, name, run_type, status, notes_enc, total_ips, scanned_ips, total_chunks, completed_chunks,
		       active_hosts, services_found, changes_detected, hosts_per_sec, eta_seconds, duration_ms, window_paused_count,
		       has_raw_nmap_xml, triggered_by, started_at, finished_at
		FROM scan_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ScanRun{}
	for rows.Next() {
		var r domain.ScanRun
		var notesEnc string
		if err := rows.Scan(&r.ID, &r.ProfileID, &r.Name, &r.RunType, &r.Status, &notesEnc, &r.TotalIPs, &r.ScannedIPs,
			&r.TotalChunks, &r.CompletedChunks, &r.ActiveHosts, &r.ServicesFound, &r.ChangesDetected, &r.HostsPerSec,
			&r.ETASeconds, &r.DurationMs, &r.WindowPausedCount, &r.HasRawNmapXML, &r.TriggeredBy, &r.StartedAt, &r.FinishedAt); err != nil {
			return nil, err
		}
		r.Notes, _ = s.vault.Decrypt(notesEnc, "scan_runs:"+r.ID+":notes")
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetScanRun(ctx context.Context, id string) (*domain.ScanRun, error) {
	var r domain.ScanRun
	var notesEnc, xmlEnc string
	err := s.pool.QueryRow(ctx, `
		SELECT id, profile_id, name, run_type, status, notes_enc, total_ips, scanned_ips, total_chunks, completed_chunks,
		       active_hosts, services_found, changes_detected, hosts_per_sec, eta_seconds, duration_ms, window_paused_count,
		       raw_nmap_xml_enc, has_raw_nmap_xml, triggered_by, started_at, finished_at
		FROM scan_runs WHERE id=$1`, id).
		Scan(&r.ID, &r.ProfileID, &r.Name, &r.RunType, &r.Status, &notesEnc, &r.TotalIPs, &r.ScannedIPs,
			&r.TotalChunks, &r.CompletedChunks, &r.ActiveHosts, &r.ServicesFound, &r.ChangesDetected, &r.HostsPerSec,
			&r.ETASeconds, &r.DurationMs, &r.WindowPausedCount, &xmlEnc, &r.HasRawNmapXML, &r.TriggeredBy, &r.StartedAt, &r.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Notes, err = s.vault.Decrypt(notesEnc, "scan_runs:"+r.ID+":notes")
	if err != nil {
		return nil, err
	}
	r.RawNmapXML, err = s.vault.Decrypt(xmlEnc, "scan_runs:"+r.ID+":raw_nmap_xml")
	if err != nil {
		return nil, err
	}
	r.Chunks, err = s.GetScanChunks(ctx, id)
	return &r, err
}

func (s *PostgresStore) CreateScanRun(ctx context.Context, run *domain.ScanRun) error {
	if run.ID == "" {
		run.ID = NewID()
	}
	if run.StartedAt.IsZero() {
		run.StartedAt = time.Now().UTC()
	}
	notesEnc, err := s.vault.Encrypt(run.Notes, "scan_runs:"+run.ID+":notes")
	if err != nil {
		return err
	}
	xmlEnc, err := s.vault.Encrypt(run.RawNmapXML, "scan_runs:"+run.ID+":raw_nmap_xml")
	if err != nil {
		return err
	}
	hasXML := run.RawNmapXML != ""
	_, err = s.pool.Exec(ctx, `
		INSERT INTO scan_runs (id, profile_id, name, run_type, status, notes_enc, total_ips, scanned_ips, total_chunks, completed_chunks,
		       active_hosts, services_found, changes_detected, hosts_per_sec, eta_seconds, duration_ms, window_paused_count,
		       raw_nmap_xml_enc, has_raw_nmap_xml, triggered_by, started_at, finished_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
		run.ID, run.ProfileID, run.Name, run.RunType, run.Status, notesEnc, run.TotalIPs, run.ScannedIPs, run.TotalChunks,
		run.CompletedChunks, run.ActiveHosts, run.ServicesFound, run.ChangesDetected, run.HostsPerSec, run.ETASeconds,
		run.DurationMs, run.WindowPausedCount, xmlEnc, hasXML, run.TriggeredBy, run.StartedAt, run.FinishedAt)
	return err
}

func (s *PostgresStore) UpdateScanRun(ctx context.Context, run *domain.ScanRun) error {
	notesEnc, err := s.vault.Encrypt(run.Notes, "scan_runs:"+run.ID+":notes")
	if err != nil {
		return err
	}
	if run.RawNmapXML != "" {
		xmlEnc, err := s.vault.Encrypt(run.RawNmapXML, "scan_runs:"+run.ID+":raw_nmap_xml")
		if err != nil {
			return err
		}
		_, err = s.pool.Exec(ctx, `
			UPDATE scan_runs SET name=$1, status=$2, notes_enc=$3, total_ips=$4, scanned_ips=$5, total_chunks=$6,
			       completed_chunks=$7, active_hosts=$8, services_found=$9, changes_detected=$10, hosts_per_sec=$11,
			       eta_seconds=$12, duration_ms=$13, window_paused_count=$14, raw_nmap_xml_enc=$15, has_raw_nmap_xml=TRUE,
			       finished_at=$16
			WHERE id=$17`,
			run.Name, run.Status, notesEnc, run.TotalIPs, run.ScannedIPs, run.TotalChunks, run.CompletedChunks,
			run.ActiveHosts, run.ServicesFound, run.ChangesDetected, run.HostsPerSec, run.ETASeconds, run.DurationMs,
			run.WindowPausedCount, xmlEnc, run.FinishedAt, run.ID)
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE scan_runs SET name=$1, status=$2, notes_enc=$3, total_ips=$4, scanned_ips=$5, total_chunks=$6,
		       completed_chunks=$7, active_hosts=$8, services_found=$9, changes_detected=$10, hosts_per_sec=$11,
		       eta_seconds=$12, duration_ms=$13, window_paused_count=$14, finished_at=$15
		WHERE id=$16`,
		run.Name, run.Status, notesEnc, run.TotalIPs, run.ScannedIPs, run.TotalChunks, run.CompletedChunks,
		run.ActiveHosts, run.ServicesFound, run.ChangesDetected, run.HostsPerSec, run.ETASeconds, run.DurationMs,
		run.WindowPausedCount, run.FinishedAt, run.ID)
	return err
}

func (s *PostgresStore) UpdateScanRunMeta(ctx context.Context, id, name, notes string) (*domain.ScanRun, error) {
	notesEnc, err := s.vault.Encrypt(notes, "scan_runs:"+id+":notes")
	if err != nil {
		return nil, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE scan_runs SET name = COALESCE(NULLIF($1,''), name), notes_enc=$2 WHERE id=$3`, name, notesEnc, id)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetScanRun(ctx, id)
}

func (s *PostgresStore) DeleteScanRun(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scan_runs WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) SaveScanChunks(ctx context.Context, scanRunID string, chunks []domain.ScanChunk) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM scan_chunks WHERE scan_run_id=$1`, scanRunID); err != nil {
		return err
	}
	for _, c := range chunks {
		if c.ID == "" {
			c.ID = NewID()
		}
		targetsJSON, _ := json.Marshal(nonNilSlice(c.Targets))
		_, err := tx.Exec(ctx, `
			INSERT INTO scan_chunks (id, scan_run_id, chunk_index, targets, ip_count, status, active_hosts, services_found, duration_ms, error, started_at, finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			c.ID, scanRunID, c.ChunkIndex, targetsJSON, c.IPCount, c.Status, c.ActiveHosts, c.Services, c.DurationMs, c.Error, c.StartedAt, c.FinishedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) UpdateScanChunk(ctx context.Context, chunk *domain.ScanChunk) error {
	if chunk.ID == "" {
		chunk.ID = NewID()
	}
	targetsJSON, _ := json.Marshal(nonNilSlice(chunk.Targets))
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_chunks (id, scan_run_id, chunk_index, targets, ip_count, status, active_hosts, services_found, duration_ms, error, started_at, finished_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, active_hosts=EXCLUDED.active_hosts, services_found=EXCLUDED.services_found,
		       duration_ms=EXCLUDED.duration_ms, error=EXCLUDED.error, started_at=EXCLUDED.started_at, finished_at=EXCLUDED.finished_at`,
		chunk.ID, chunk.ScanRunID, chunk.ChunkIndex, targetsJSON, chunk.IPCount, chunk.Status, chunk.ActiveHosts, chunk.Services,
		chunk.DurationMs, chunk.Error, chunk.StartedAt, chunk.FinishedAt)
	return err
}

func (s *PostgresStore) GetScanChunks(ctx context.Context, scanRunID string) ([]domain.ScanChunk, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, scan_run_id, chunk_index, targets, ip_count, status, active_hosts, services_found, duration_ms, error, started_at, finished_at
		FROM scan_chunks WHERE scan_run_id=$1 ORDER BY chunk_index ASC`, scanRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ScanChunk{}
	for rows.Next() {
		var c domain.ScanChunk
		var targetsRaw []byte
		if err := rows.Scan(&c.ID, &c.ScanRunID, &c.ChunkIndex, &targetsRaw, &c.IPCount, &c.Status, &c.ActiveHosts, &c.Services, &c.DurationMs, &c.Error, &c.StartedAt, &c.FinishedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targetsRaw, &c.Targets)
		out = append(out, c)
	}
	return out, rows.Err()
}

// --- Hosts, Services, Observations & Overrides ---

func (s *PostgresStore) GetOverrides(ctx context.Context, entityType, entityID string) (map[string]any, error) {
	rows, err := s.pool.Query(ctx, `SELECT field, value_enc FROM asset_overrides WHERE entity_type=$1 AND entity_id=$2`, entityType, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]any)
	for rows.Next() {
		var field, valEnc string
		if err := rows.Scan(&field, &valEnc); err != nil {
			return nil, err
		}
		var val any
		aad := "asset_overrides:" + entityType + ":" + entityID + ":" + field
		if err := s.vault.DecryptJSON(valEnc, aad, &val); err != nil {
			return nil, err
		}
		out[field] = val
	}
	return out, rows.Err()
}

func (s *PostgresStore) PatchOverrides(ctx context.Context, entityType, entityID string, patch map[string]any, unlockFields []string, updatedBy string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, uf := range unlockFields {
		if _, err := tx.Exec(ctx, `DELETE FROM asset_overrides WHERE entity_type=$1 AND entity_id=$2 AND field=$3`, entityType, entityID, uf); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	for field, val := range patch {
		aad := "asset_overrides:" + entityType + ":" + entityID + ":" + field
		enc, err := s.vault.EncryptJSON(val, aad)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO asset_overrides (entity_type, entity_id, field, value_enc, updated_by, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (entity_type, entity_id, field) DO UPDATE SET value_enc=EXCLUDED.value_enc, updated_by=EXCLUDED.updated_by, updated_at=EXCLUDED.updated_at`,
			entityType, entityID, field, enc, updatedBy, now)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) scanHostRow(ctx context.Context, row pgx.Row) (*domain.Host, error) {
	var h domain.Host
	var ipEnc, hostnameEnc, domainsEnc, osEnc, notesEnc string
	var tagsRaw, factorsRaw, todRaw []byte
	err := row.Scan(&h.ID, &ipEnc, &hostnameEnc, &domainsEnc, &osEnc, &h.LifecycleState, &h.Environment, &h.Owner,
		&notesEnc, &tagsRaw, &h.FirstSeen, &h.LastSeen, &h.TotalScansSeen, &h.TotalScansChecked, &h.ConsecutiveMisses,
		&h.StateTransitions, &h.StabilityScore, &h.Interestingness, &factorsRaw, &todRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.hydrateHost(ctx, &h, ipEnc, hostnameEnc, domainsEnc, osEnc, notesEnc, tagsRaw, factorsRaw, todRaw)
}

func (s *PostgresStore) hydrateHost(ctx context.Context, h *domain.Host, ipEnc, hostnameEnc, domainsEnc, osEnc, notesEnc string, tagsRaw, factorsRaw, todRaw []byte) (*domain.Host, error) {
	var err error
	if h.IP, err = s.vault.Decrypt(ipEnc, "hosts:"+h.ID+":ip"); err != nil {
		return nil, err
	}
	if h.Hostname, err = s.vault.Decrypt(hostnameEnc, "hosts:"+h.ID+":hostname"); err != nil {
		return nil, err
	}
	if domainsEnc != "" {
		if err = s.vault.DecryptJSON(domainsEnc, "hosts:"+h.ID+":domains", &h.Domains); err != nil {
			return nil, err
		}
	}
	if h.OSGuess, err = s.vault.Decrypt(osEnc, "hosts:"+h.ID+":os_guess"); err != nil {
		return nil, err
	}
	if h.Notes, err = s.vault.Decrypt(notesEnc, "hosts:"+h.ID+":notes"); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(tagsRaw, &h.Tags)
	if h.Tags == nil {
		h.Tags = []string{}
	}
	_ = json.Unmarshal(factorsRaw, &h.InterestingFactors)
	_ = json.Unmarshal(todRaw, &h.TimeOfDayStats)

	svcs, err := s.ListServicesByHost(ctx, h.ID)
	if err != nil {
		return nil, err
	}
	for i := range svcs {
		svcs[i].HostIP = h.IP
	}
	h.Services = svcs
	h.ServiceCount = len(svcs)

	ov, err := s.GetOverrides(ctx, "host", h.ID)
	if err != nil {
		return nil, err
	}
	MergeHostWithOverrides(h, ov)
	return h, nil
}

func (s *PostgresStore) ListHosts(ctx context.Context, filter HostFilter) ([]domain.Host, int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, ip_enc, hostname_enc, domains_enc, os_guess_enc, lifecycle_state, environment, owner,
		       notes_enc, tags, first_seen, last_seen, total_scans_seen, total_scans_checked, consecutive_misses,
		       state_transitions, stability_score, interestingness, interesting_factors, time_of_day_stats
		FROM hosts ORDER BY interestingness DESC, last_seen DESC`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	type rawHost struct {
		h                                              domain.Host
		ipEnc, hostnameEnc, domainsEnc, osEnc, notesEnc string
		tagsRaw, factorsRaw, todRaw                    []byte
	}
	var rawList []rawHost
	for rows.Next() {
		var r rawHost
		if err := rows.Scan(&r.h.ID, &r.ipEnc, &r.hostnameEnc, &r.domainsEnc, &r.osEnc, &r.h.LifecycleState,
			&r.h.Environment, &r.h.Owner, &r.notesEnc, &r.tagsRaw, &r.h.FirstSeen, &r.h.LastSeen, &r.h.TotalScansSeen,
			&r.h.TotalScansChecked, &r.h.ConsecutiveMisses, &r.h.StateTransitions, &r.h.StabilityScore,
			&r.h.Interestingness, &r.factorsRaw, &r.todRaw); err != nil {
			return nil, 0, err
		}
		rawList = append(rawList, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	matched := make([]domain.Host, 0, len(rawList))
	for i := range rawList {
		r := &rawList[i]
		h, err := s.hydrateHost(ctx, &r.h, r.ipEnc, r.hostnameEnc, r.domainsEnc, r.osEnc, r.notesEnc, r.tagsRaw, r.factorsRaw, r.todRaw)
		if err != nil {
			return nil, 0, err
		}
		if matchesHostFilter(h, filter) {
			matched = append(matched, *h)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Interestingness != matched[j].Interestingness {
			return matched[i].Interestingness > matched[j].Interestingness
		}
		return matched[i].IP < matched[j].IP
	})
	total := len(matched)
	if filter.Limit > 0 {
		page := filter.Page
		if page < 1 {
			page = 1
		}
		start := (page - 1) * filter.Limit
		if start >= total {
			return []domain.Host{}, total, nil
		}
		end := start + filter.Limit
		if end > total {
			end = total
		}
		matched = matched[start:end]
	}
	return matched, total, nil
}

func (s *PostgresStore) GetHost(ctx context.Context, id string) (*domain.Host, error) {
	return s.scanHostRow(ctx, s.pool.QueryRow(ctx, `
		SELECT id, ip_enc, hostname_enc, domains_enc, os_guess_enc, lifecycle_state, environment, owner,
		       notes_enc, tags, first_seen, last_seen, total_scans_seen, total_scans_checked, consecutive_misses,
		       state_transitions, stability_score, interestingness, interesting_factors, time_of_day_stats
		FROM hosts WHERE id=$1`, id))
}

func (s *PostgresStore) GetHostByIP(ctx context.Context, ip string) (*domain.Host, error) {
	hmacIdx := s.vault.BlindIndex(ip)
	return s.scanHostRow(ctx, s.pool.QueryRow(ctx, `
		SELECT id, ip_enc, hostname_enc, domains_enc, os_guess_enc, lifecycle_state, environment, owner,
		       notes_enc, tags, first_seen, last_seen, total_scans_seen, total_scans_checked, consecutive_misses,
		       state_transitions, stability_score, interestingness, interesting_factors, time_of_day_stats
		FROM hosts WHERE ip_hmac=$1`, hmacIdx))
}

func (s *PostgresStore) UpsertObservedHost(ctx context.Context, host *domain.Host) (*domain.Host, error) {
	hmacIdx := s.vault.BlindIndex(host.IP)
	var existingID string
	err := s.pool.QueryRow(ctx, `SELECT id FROM hosts WHERE ip_hmac=$1`, hmacIdx).Scan(&existingID)
	if err == nil && existingID != "" {
		host.ID = existingID
	} else if host.ID == "" {
		host.ID = NewID()
	}

	ipEnc, err := s.vault.Encrypt(host.IP, "hosts:"+host.ID+":ip")
	if err != nil {
		return nil, err
	}
	hostnameEnc, err := s.vault.Encrypt(host.Hostname, "hosts:"+host.ID+":hostname")
	if err != nil {
		return nil, err
	}
	domainsEnc, err := s.vault.EncryptJSON(host.Domains, "hosts:"+host.ID+":domains")
	if err != nil {
		return nil, err
	}
	osEnc, err := s.vault.Encrypt(host.OSGuess, "hosts:"+host.ID+":os_guess")
	if err != nil {
		return nil, err
	}
	notesEnc, err := s.vault.Encrypt(host.Notes, "hosts:"+host.ID+":notes")
	if err != nil {
		return nil, err
	}
	tagsJSON, _ := json.Marshal(nonNilSlice(host.Tags))
	factorsJSON, _ := json.Marshal(host.InterestingFactors)
	todJSON, _ := json.Marshal(host.TimeOfDayStats)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO hosts (id, ip_hmac, ip_enc, hostname_enc, domains_enc, os_guess_enc, lifecycle_state, environment, owner,
		       notes_enc, tags, first_seen, last_seen, total_scans_seen, total_scans_checked, consecutive_misses,
		       state_transitions, stability_score, interestingness, interesting_factors, time_of_day_stats)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		ON CONFLICT (ip_hmac) DO UPDATE SET
		       ip_enc=EXCLUDED.ip_enc, hostname_enc=EXCLUDED.hostname_enc, domains_enc=EXCLUDED.domains_enc,
		       os_guess_enc=EXCLUDED.os_guess_enc, lifecycle_state=EXCLUDED.lifecycle_state, environment=EXCLUDED.environment,
		       owner=EXCLUDED.owner, notes_enc=EXCLUDED.notes_enc, tags=EXCLUDED.tags, last_seen=EXCLUDED.last_seen,
		       total_scans_seen=EXCLUDED.total_scans_seen, total_scans_checked=EXCLUDED.total_scans_checked,
		       consecutive_misses=EXCLUDED.consecutive_misses, state_transitions=EXCLUDED.state_transitions,
		       stability_score=EXCLUDED.stability_score, interestingness=EXCLUDED.interestingness,
		       interesting_factors=EXCLUDED.interesting_factors, time_of_day_stats=EXCLUDED.time_of_day_stats`,
		host.ID, hmacIdx, ipEnc, hostnameEnc, domainsEnc, osEnc, host.LifecycleState, host.Environment, host.Owner,
		notesEnc, tagsJSON, host.FirstSeen, host.LastSeen, host.TotalScansSeen, host.TotalScansChecked,
		host.ConsecutiveMisses, host.StateTransitions, host.StabilityScore, host.Interestingness, factorsJSON, todJSON)
	if err != nil {
		return nil, err
	}
	return s.GetHost(ctx, host.ID)
}

func (s *PostgresStore) DeleteHost(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, _ = tx.Exec(ctx, `DELETE FROM asset_overrides WHERE entity_type='host' AND entity_id=$1`, id)
	_, _ = tx.Exec(ctx, `DELETE FROM asset_overrides WHERE entity_type='service' AND entity_id IN (SELECT id FROM services WHERE host_id=$1)`, id)
	tag, err := tx.Exec(ctx, `DELETE FROM hosts WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) hydrateService(ctx context.Context, svc *domain.Service, bannerEnc, httpEnc, notesEnc string, techRaw, sigRaw, factorsRaw, tagsRaw []byte) (*domain.Service, error) {
	var err error
	if svc.Banner, err = s.vault.Decrypt(bannerEnc, "services:"+svc.ID+":banner"); err != nil {
		return nil, err
	}
	if httpEnc != "" {
		var fp domain.HTTPFingerprint
		if err = s.vault.DecryptJSON(httpEnc, "services:"+svc.ID+":http", &fp); err != nil {
			return nil, err
		}
		svc.HTTP = &fp
	}
	if svc.Notes, err = s.vault.Decrypt(notesEnc, "services:"+svc.ID+":notes"); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(techRaw, &svc.Technologies)
	if svc.Technologies == nil {
		svc.Technologies = []domain.DetectedTechnology{}
	}
	_ = json.Unmarshal(sigRaw, &svc.MatchedSignatures)
	if svc.MatchedSignatures == nil {
		svc.MatchedSignatures = []string{}
	}
	_ = json.Unmarshal(factorsRaw, &svc.InterestingFactors)
	_ = json.Unmarshal(tagsRaw, &svc.Tags)
	if svc.Tags == nil {
		svc.Tags = []string{}
	}
	ov, err := s.GetOverrides(ctx, "service", svc.ID)
	if err != nil {
		return nil, err
	}
	MergeServiceWithOverrides(svc, ov)
	return svc, nil
}

func (s *PostgresStore) ListServices(ctx context.Context, filter ServiceFilter) ([]domain.Service, error) {
	q := `
		SELECT sv.id, sv.host_id, h.ip_enc, sv.port, sv.protocol, sv.state, sv.service_name, sv.product, sv.version, sv.cpe,
		       sv.banner_enc, sv.http_enc, sv.technologies, sv.matched_signatures, sv.is_admin_panel, sv.is_staging_env, sv.is_iot,
		       sv.cluster_key, sv.interestingness, sv.interesting_factors, sv.triage_status, sv.notes_enc, sv.tags, sv.first_seen, sv.last_seen
		FROM services sv JOIN hosts h ON h.id = sv.host_id`
	var args []any
	if filter.HostID != "" {
		q += ` WHERE sv.host_id = $1`
		args = append(args, filter.HostID)
	}
	q += ` ORDER BY sv.interestingness DESC, sv.port ASC`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type rawSvc struct {
		svc                                     domain.Service
		hostIPEnc, bannerEnc, httpEnc, notesEnc string
		techRaw, sigRaw, factorsRaw, tagsRaw    []byte
	}
	var list []rawSvc
	for rows.Next() {
		var r rawSvc
		if err := rows.Scan(&r.svc.ID, &r.svc.HostID, &r.hostIPEnc, &r.svc.Port, &r.svc.Protocol, &r.svc.State,
			&r.svc.ServiceName, &r.svc.Product, &r.svc.Version, &r.svc.CPE, &r.bannerEnc, &r.httpEnc, &r.techRaw,
			&r.sigRaw, &r.svc.IsAdminPanel, &r.svc.IsStagingEnv, &r.svc.IsIoT, &r.svc.ClusterKey, &r.svc.Interestingness,
			&r.factorsRaw, &r.svc.TriageStatus, &r.notesEnc, &r.tagsRaw, &r.svc.FirstSeen, &r.svc.LastSeen); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]domain.Service, 0, len(list))
	for i := range list {
		r := &list[i]
		r.svc.HostIP, _ = s.vault.Decrypt(r.hostIPEnc, "hosts:"+r.svc.HostID+":ip")
		svc, err := s.hydrateService(ctx, &r.svc, r.bannerEnc, r.httpEnc, r.notesEnc, r.techRaw, r.sigRaw, r.factorsRaw, r.tagsRaw)
		if err != nil {
			return nil, err
		}
		if matchesServiceFilter(svc, filter) {
			out = append(out, *svc)
		}
	}
	return out, nil
}

func (s *PostgresStore) ListServicesByHost(ctx context.Context, hostID string) ([]domain.Service, error) {
	return s.ListServices(ctx, ServiceFilter{HostID: hostID})
}

func (s *PostgresStore) GetService(ctx context.Context, id string) (*domain.Service, error) {
	var svc domain.Service
	var hostIPEnc, bannerEnc, httpEnc, notesEnc string
	var techRaw, sigRaw, factorsRaw, tagsRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT sv.id, sv.host_id, h.ip_enc, sv.port, sv.protocol, sv.state, sv.service_name, sv.product, sv.version, sv.cpe,
		       sv.banner_enc, sv.http_enc, sv.technologies, sv.matched_signatures, sv.is_admin_panel, sv.is_staging_env, sv.is_iot,
		       sv.cluster_key, sv.interestingness, sv.interesting_factors, sv.triage_status, sv.notes_enc, sv.tags, sv.first_seen, sv.last_seen
		FROM services sv JOIN hosts h ON h.id = sv.host_id WHERE sv.id=$1`, id).
		Scan(&svc.ID, &svc.HostID, &hostIPEnc, &svc.Port, &svc.Protocol, &svc.State, &svc.ServiceName, &svc.Product,
			&svc.Version, &svc.CPE, &bannerEnc, &httpEnc, &techRaw, &sigRaw, &svc.IsAdminPanel, &svc.IsStagingEnv,
			&svc.IsIoT, &svc.ClusterKey, &svc.Interestingness, &factorsRaw, &svc.TriageStatus, &notesEnc, &tagsRaw,
			&svc.FirstSeen, &svc.LastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	svc.HostIP, _ = s.vault.Decrypt(hostIPEnc, "hosts:"+svc.HostID+":ip")
	return s.hydrateService(ctx, &svc, bannerEnc, httpEnc, notesEnc, techRaw, sigRaw, factorsRaw, tagsRaw)
}

func (s *PostgresStore) UpsertObservedService(ctx context.Context, svc *domain.Service) (*domain.Service, error) {
	if svc.Protocol == "" {
		svc.Protocol = "tcp"
	}
	var existingID string
	err := s.pool.QueryRow(ctx, `SELECT id FROM services WHERE host_id=$1 AND port=$2 AND protocol=$3`,
		svc.HostID, svc.Port, svc.Protocol).Scan(&existingID)
	if err == nil && existingID != "" {
		svc.ID = existingID
	} else if svc.ID == "" {
		svc.ID = NewID()
	}
	if svc.TriageStatus == "" {
		svc.TriageStatus = "new"
	}

	bannerEnc, err := s.vault.Encrypt(svc.Banner, "services:"+svc.ID+":banner")
	if err != nil {
		return nil, err
	}
	httpEnc, err := s.vault.EncryptJSON(svc.HTTP, "services:"+svc.ID+":http")
	if err != nil {
		return nil, err
	}
	notesEnc, err := s.vault.Encrypt(svc.Notes, "services:"+svc.ID+":notes")
	if err != nil {
		return nil, err
	}
	techJSON, _ := json.Marshal(svc.Technologies)
	sigJSON, _ := json.Marshal(nonNilSlice(svc.MatchedSignatures))
	factorsJSON, _ := json.Marshal(svc.InterestingFactors)
	tagsJSON, _ := json.Marshal(nonNilSlice(svc.Tags))

	_, err = s.pool.Exec(ctx, `
		INSERT INTO services (id, host_id, port, protocol, state, service_name, product, version, cpe, banner_enc, http_enc,
		       technologies, matched_signatures, is_admin_panel, is_staging_env, is_iot, cluster_key, interestingness,
		       interesting_factors, triage_status, notes_enc, tags, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
		ON CONFLICT (host_id, port, protocol) DO UPDATE SET
		       state=EXCLUDED.state, service_name=EXCLUDED.service_name, product=EXCLUDED.product, version=EXCLUDED.version,
		       cpe=EXCLUDED.cpe, banner_enc=EXCLUDED.banner_enc, http_enc=EXCLUDED.http_enc, technologies=EXCLUDED.technologies,
		       matched_signatures=EXCLUDED.matched_signatures, is_admin_panel=EXCLUDED.is_admin_panel,
		       is_staging_env=EXCLUDED.is_staging_env, is_iot=EXCLUDED.is_iot, cluster_key=EXCLUDED.cluster_key,
		       interestingness=EXCLUDED.interestingness, interesting_factors=EXCLUDED.interesting_factors,
		       notes_enc=EXCLUDED.notes_enc, tags=EXCLUDED.tags, last_seen=EXCLUDED.last_seen`,
		svc.ID, svc.HostID, svc.Port, svc.Protocol, svc.State, svc.ServiceName, svc.Product, svc.Version, svc.CPE,
		bannerEnc, httpEnc, techJSON, sigJSON, svc.IsAdminPanel, svc.IsStagingEnv, svc.IsIoT, svc.ClusterKey,
		svc.Interestingness, factorsJSON, svc.TriageStatus, notesEnc, tagsJSON, svc.FirstSeen, svc.LastSeen)
	if err != nil {
		return nil, err
	}
	return s.GetService(ctx, svc.ID)
}

func (s *PostgresStore) AddObservation(ctx context.Context, obs *ServiceObservation) error {
	if obs.ID == "" {
		obs.ID = NewID()
	}
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now().UTC()
	}
	bannerEnc, err := s.vault.Encrypt(obs.Banner, "service_observations:"+obs.ID+":banner")
	if err != nil {
		return err
	}
	httpEnc, err := s.vault.EncryptJSON(obs.HTTP, "service_observations:"+obs.ID+":http")
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO service_observations (id, scan_run_id, host_id, service_id, port, protocol, state, service_name, product, version, banner_enc, http_enc, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		obs.ID, obs.ScanRunID, obs.HostID, obs.ServiceID, obs.Port, obs.Protocol, obs.State, obs.ServiceName, obs.Product, obs.Version, bannerEnc, httpEnc, obs.ObservedAt)
	return err
}

func (s *PostgresStore) ListServiceObservations(ctx context.Context, serviceID string, limit int) ([]ServiceObservation, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, scan_run_id, host_id, service_id, port, protocol, state, service_name, product, version, banner_enc, http_enc, observed_at
		FROM service_observations WHERE service_id=$1 ORDER BY observed_at DESC LIMIT $2`, serviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ServiceObservation{}
	for rows.Next() {
		var o ServiceObservation
		var bannerEnc, httpEnc string
		if err := rows.Scan(&o.ID, &o.ScanRunID, &o.HostID, &o.ServiceID, &o.Port, &o.Protocol, &o.State, &o.ServiceName, &o.Product, &o.Version, &bannerEnc, &httpEnc, &o.ObservedAt); err != nil {
			return nil, err
		}
		o.Banner, err = s.vault.Decrypt(bannerEnc, "service_observations:"+o.ID+":banner")
		if err != nil {
			return nil, err
		}
		if httpEnc != "" {
			var fp domain.HTTPFingerprint
			if err := s.vault.DecryptJSON(httpEnc, "service_observations:"+o.ID+":http", &fp); err != nil {
				return nil, err
			}
			o.HTTP = &fp
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// --- Changes & Snapshots ---

func (s *PostgresStore) AddChangeEvent(ctx context.Context, ev *domain.ChangeEvent) error {
	if ev.ID == "" {
		ev.ID = NewID()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	ipEnc, err := s.vault.Encrypt(ev.HostIP, "change_events:"+ev.ID+":host_ip")
	if err != nil {
		return err
	}
	beforeEnc, err := s.vault.EncryptJSON(ev.Before, "change_events:"+ev.ID+":before")
	if err != nil {
		return err
	}
	afterEnc, err := s.vault.EncryptJSON(ev.After, "change_events:"+ev.ID+":after")
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO change_events (id, scan_run_id, prev_scan_run_id, host_id, host_ip_enc, service_id, port, event_type, severity,
		       summary, time_slot, is_expected_schedule, is_time_anomaly, before_enc, after_enc, acknowledged_by, acknowledged_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		ev.ID, ev.ScanRunID, ev.PrevScanRunID, ev.HostID, ipEnc, ev.ServiceID, ev.Port, ev.EventType, ev.Severity,
		ev.Summary, ev.TimeSlot, ev.IsExpectedSchedule, ev.IsTimeAnomaly, beforeEnc, afterEnc, ev.AcknowledgedBy, ev.AcknowledgedAt, ev.CreatedAt)
	return err
}

func (s *PostgresStore) ListChangeEvents(ctx context.Context, filter ChangeFilter) ([]domain.ChangeEvent, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, scan_run_id, prev_scan_run_id, host_id, host_ip_enc, service_id, port, event_type, severity,
		       summary, time_slot, is_expected_schedule, is_time_anomaly, before_enc, after_enc, acknowledged_by, acknowledged_at, created_at
		FROM change_events ORDER BY created_at DESC LIMIT $1`, limit*2)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ChangeEvent{}
	for rows.Next() {
		var ev domain.ChangeEvent
		var ipEnc, beforeEnc, afterEnc string
		if err := rows.Scan(&ev.ID, &ev.ScanRunID, &ev.PrevScanRunID, &ev.HostID, &ipEnc, &ev.ServiceID, &ev.Port,
			&ev.EventType, &ev.Severity, &ev.Summary, &ev.TimeSlot, &ev.IsExpectedSchedule, &ev.IsTimeAnomaly,
			&beforeEnc, &afterEnc, &ev.AcknowledgedBy, &ev.AcknowledgedAt, &ev.CreatedAt); err != nil {
			return nil, err
		}
		if filter.ScanRunID != "" && ev.ScanRunID != filter.ScanRunID {
			continue
		}
		if filter.Severity != "" && !strings.EqualFold(ev.Severity, filter.Severity) {
			continue
		}
		if filter.EventType != "" && !strings.EqualFold(ev.EventType, filter.EventType) {
			continue
		}
		if filter.AnomalyOnly && !ev.IsTimeAnomaly {
			continue
		}
		ev.HostIP, _ = s.vault.Decrypt(ipEnc, "change_events:"+ev.ID+":host_ip")
		if beforeEnc != "" {
			_ = s.vault.DecryptJSON(beforeEnc, "change_events:"+ev.ID+":before", &ev.Before)
		}
		if afterEnc != "" {
			_ = s.vault.DecryptJSON(afterEnc, "change_events:"+ev.ID+":after", &ev.After)
		}
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

func (s *PostgresStore) AcknowledgeChange(ctx context.Context, id, username string) (*domain.ChangeEvent, error) {
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `UPDATE change_events SET acknowledged_by=$1, acknowledged_at=$2 WHERE id=$3`, username, now, id)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	list, err := s.ListChangeEvents(ctx, ChangeFilter{Limit: 500})
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, ErrNotFound
}

func (s *PostgresStore) SaveScanSnapshot(ctx context.Context, scanRunID string, hosts []domain.Host) error {
	enc, err := s.vault.EncryptJSON(hosts, "scan_snapshots:"+scanRunID+":payload")
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO scan_snapshots (scan_run_id, payload_enc, created_at) VALUES ($1,$2,NOW())
		ON CONFLICT (scan_run_id) DO UPDATE SET payload_enc=EXCLUDED.payload_enc`, scanRunID, enc)
	return err
}

func (s *PostgresStore) GetScanSnapshot(ctx context.Context, scanRunID string) ([]domain.Host, error) {
	var enc string
	err := s.pool.QueryRow(ctx, `SELECT payload_enc FROM scan_snapshots WHERE scan_run_id=$1`, scanRunID).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var hosts []domain.Host
	if err := s.vault.DecryptJSON(enc, "scan_snapshots:"+scanRunID+":payload", &hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

// --- Signatures ---

func (s *PostgresStore) ListSignatures(ctx context.Context) ([]domain.Signature, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, description, category, match_mode, matchers, confidence_weight, interesting_points, tags, is_builtin, enabled, created_by, created_at, updated_at
		FROM signatures ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Signature{}
	for rows.Next() {
		var sig domain.Signature
		var matchersRaw, tagsRaw []byte
		if err := rows.Scan(&sig.ID, &sig.Name, &sig.Description, &sig.Category, &sig.MatchMode, &matchersRaw,
			&sig.ConfidenceWeight, &sig.InterestingPts, &tagsRaw, &sig.IsBuiltin, &sig.Enabled, &sig.CreatedBy, &sig.CreatedAt, &sig.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(matchersRaw, &sig.Matchers)
		_ = json.Unmarshal(tagsRaw, &sig.Tags)
		out = append(out, sig)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetSignature(ctx context.Context, id string) (*domain.Signature, error) {
	var sig domain.Signature
	var matchersRaw, tagsRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, description, category, match_mode, matchers, confidence_weight, interesting_points, tags, is_builtin, enabled, created_by, created_at, updated_at
		FROM signatures WHERE id=$1`, id).
		Scan(&sig.ID, &sig.Name, &sig.Description, &sig.Category, &sig.MatchMode, &matchersRaw,
			&sig.ConfidenceWeight, &sig.InterestingPts, &tagsRaw, &sig.IsBuiltin, &sig.Enabled, &sig.CreatedBy, &sig.CreatedAt, &sig.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(matchersRaw, &sig.Matchers)
	_ = json.Unmarshal(tagsRaw, &sig.Tags)
	return &sig, nil
}

func (s *PostgresStore) CreateSignature(ctx context.Context, sig *domain.Signature) error {
	if sig.ID == "" {
		sig.ID = NewID()
	}
	now := time.Now().UTC()
	if sig.CreatedAt.IsZero() {
		sig.CreatedAt = now
	}
	sig.UpdatedAt = now
	matchersJSON, _ := json.Marshal(sig.Matchers)
	tagsJSON, _ := json.Marshal(nonNilSlice(sig.Tags))
	_, err := s.pool.Exec(ctx, `
		INSERT INTO signatures (id, name, description, category, match_mode, matchers, confidence_weight, interesting_points, tags, is_builtin, enabled, created_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		sig.ID, sig.Name, sig.Description, sig.Category, sig.MatchMode, matchersJSON, sig.ConfidenceWeight, sig.InterestingPts, tagsJSON, sig.IsBuiltin, sig.Enabled, sig.CreatedBy, sig.CreatedAt, sig.UpdatedAt)
	return err
}

func (s *PostgresStore) UpdateSignature(ctx context.Context, sig *domain.Signature) error {
	sig.UpdatedAt = time.Now().UTC()
	matchersJSON, _ := json.Marshal(sig.Matchers)
	tagsJSON, _ := json.Marshal(nonNilSlice(sig.Tags))
	tag, err := s.pool.Exec(ctx, `
		UPDATE signatures SET name=$1, description=$2, category=$3, match_mode=$4, matchers=$5, confidence_weight=$6,
		       interesting_points=$7, tags=$8, enabled=$9, updated_at=$10 WHERE id=$11`,
		sig.Name, sig.Description, sig.Category, sig.MatchMode, matchersJSON, sig.ConfidenceWeight, sig.InterestingPts, tagsJSON, sig.Enabled, sig.UpdatedAt, sig.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) DeleteSignature(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM signatures WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- DefectDojo ---

func (s *PostgresStore) GetDefectDojoConfig(ctx context.Context) (*domain.DefectDojoConfig, error) {
	var cfg domain.DefectDojoConfig
	var tokEnc string
	err := s.pool.QueryRow(ctx, `SELECT url, api_token_enc, product_id, engagement_id, verify_tls, auto_push_nmap FROM defectdojo_config WHERE id='default'`).
		Scan(&cfg.URL, &tokEnc, &cfg.ProductID, &cfg.EngagementID, &cfg.VerifyTLS, &cfg.AutoPushNmap)
	if errors.Is(err, pgx.ErrNoRows) {
		return &domain.DefectDojoConfig{VerifyTLS: true}, nil
	}
	if err != nil {
		return nil, err
	}
	cfg.APIToken, err = s.vault.Decrypt(tokEnc, "defectdojo_config:default:api_token")
	if err != nil {
		return nil, err
	}
	cfg.HasAPIToken = cfg.APIToken != ""
	return &cfg, nil
}

func (s *PostgresStore) SaveDefectDojoConfig(ctx context.Context, cfg *domain.DefectDojoConfig) error {
	var tokEnc string
	if cfg.APIToken != "" {
		var err error
		tokEnc, err = s.vault.Encrypt(cfg.APIToken, "defectdojo_config:default:api_token")
		if err != nil {
			return err
		}
	} else {
		_ = s.pool.QueryRow(ctx, `SELECT api_token_enc FROM defectdojo_config WHERE id='default'`).Scan(&tokEnc)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO defectdojo_config (id, url, api_token_enc, product_id, engagement_id, verify_tls, auto_push_nmap, updated_at)
		VALUES ('default',$1,$2,$3,$4,$5,$6,NOW())
		ON CONFLICT (id) DO UPDATE SET url=EXCLUDED.url, api_token_enc=EXCLUDED.api_token_enc, product_id=EXCLUDED.product_id,
		       engagement_id=EXCLUDED.engagement_id, verify_tls=EXCLUDED.verify_tls, auto_push_nmap=EXCLUDED.auto_push_nmap, updated_at=NOW()`,
		cfg.URL, tokEnc, cfg.ProductID, cfg.EngagementID, cfg.VerifyTLS, cfg.AutoPushNmap)
	return err
}

func (s *PostgresStore) AddDefectDojoExport(ctx context.Context, exp *domain.DefectDojoExport) error {
	if exp.ID == "" {
		exp.ID = NewID()
	}
	if exp.CreatedAt.IsZero() {
		exp.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO defectdojo_exports (id, export_type, source_id, title, external_id, external_url, status, error_message, exported_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		exp.ID, exp.ExportType, exp.SourceID, exp.Title, exp.ExternalID, exp.ExternalURL, exp.Status, exp.ErrorMessage, exp.ExportedBy, exp.CreatedAt)
	return err
}

func (s *PostgresStore) ListDefectDojoExports(ctx context.Context, limit int) ([]domain.DefectDojoExport, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, export_type, source_id, title, external_id, external_url, status, error_message, exported_by, created_at
		FROM defectdojo_exports ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.DefectDojoExport{}
	for rows.Next() {
		var e domain.DefectDojoExport
		if err := rows.Scan(&e.ID, &e.ExportType, &e.SourceID, &e.Title, &e.ExternalID, &e.ExternalURL, &e.Status, &e.ErrorMessage, &e.ExportedBy, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- Audit Logs ---

func (s *PostgresStore) AddAuditLog(ctx context.Context, entry *domain.AuditLog) error {
	if entry.ID == "" {
		entry.ID = NewID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	detailsJSON, _ := json.Marshal(entry.Details)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs (id, user_id, username, role_slug, action, resource, resource_id, status, details, ip_address, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		entry.ID, entry.UserID, entry.Username, entry.RoleSlug, entry.Action, entry.Resource, entry.ResourceID, entry.Status, detailsJSON, entry.IPAddress, entry.CreatedAt)
	return err
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, username, role_slug, action, resource, resource_id, status, details, ip_address, created_at
		FROM audit_logs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.AuditLog{}
	for rows.Next() {
		var a domain.AuditLog
		var detailsRaw []byte
		if err := rows.Scan(&a.ID, &a.UserID, &a.Username, &a.RoleSlug, &a.Action, &a.Resource, &a.ResourceID, &a.Status, &detailsRaw, &a.IPAddress, &a.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detailsRaw, &a.Details)
		out = append(out, a)
	}
	return out, rows.Err()
}

func nonNilSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
