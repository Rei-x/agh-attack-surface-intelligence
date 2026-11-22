package outbound

import (
	"context"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
)

func memStore(t *testing.T) *db.MemoryStore {
	t.Helper()
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatal(err)
	}
	return db.NewMemoryStore(vault)
}

func TestNoticeSettingsDefaultsAndMigration(t *testing.T) {
	ctx := context.Background()

	// New install: nothing saved yet, Polish notices in Warsaw time.
	fresh := memStore(t)
	s := Load(ctx, fresh)
	if s.NoticeLanguage != locale.PL || s.Timezone != "Europe/Warsaw" || s.Location().String() != "Europe/Warsaw" {
		t.Fatalf("new install: %+v", s)
	}

	// An install that saved its channels with an older version keeps English notices.
	old := memStore(t)
	if err := old.SaveSetting(ctx, SettingDelivery, map[string]any{"webhook_format": "teams", "use_alert_webhook": true}); err != nil {
		t.Fatal(err)
	}
	s = Load(ctx, old)
	if s.NoticeLanguage != locale.EN || s.Timezone != "Europe/Warsaw" || s.WebhookFormat != FormatTeams {
		t.Fatalf("older install: %+v", s)
	}
	// Saving from a client that does not know the new fields keeps them.
	if err := Save(ctx, old, &Settings{WebhookFormat: FormatSlack}, false, false); err != nil {
		t.Fatal(err)
	}
	if s = Load(ctx, old); s.NoticeLanguage != locale.EN {
		t.Fatalf("language lost on save: %+v", s)
	}
	if err := Save(ctx, old, &Settings{NoticeLanguage: "PL", Timezone: "Europe/London", SLADays: map[string]int{"medium": 60}}, false, false); err != nil {
		t.Fatal(err)
	}
	s = Load(ctx, old)
	if s.NoticeLanguage != locale.PL || s.Timezone != "Europe/London" || s.SLADays["medium"] != 60 {
		t.Fatalf("saved notice settings: %+v", s)
	}
	// nil keeps the overrides, an empty map clears them.
	_ = Save(ctx, old, &Settings{}, false, false)
	if s = Load(ctx, old); s.SLADays["medium"] != 60 {
		t.Fatalf("overrides lost: %+v", s.SLADays)
	}
	_ = Save(ctx, old, &Settings{SLADays: map[string]int{}}, false, false)
	if s = Load(ctx, old); len(s.SLADays) != 0 {
		t.Fatalf("overrides not cleared: %+v", s.SLADays)
	}

	for _, bad := range []*Settings{
		{NoticeLanguage: "de"},
		{Timezone: "Mars/Olympus"},
		{SLADays: map[string]int{"urgent": 3}},
		{SLADays: map[string]int{"high": 0}},
	} {
		if err := Save(ctx, old, bad, false, false); err == nil {
			t.Errorf("expected %+v to be refused", bad)
		}
	}
}
