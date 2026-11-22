package db

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// A store file written by earlier releases (json.Marshal of the whole state, uncompressed
// per-row snapshot and raw XML payloads, a field this release does not know) must load.
func TestFileStoreLoadsLegacyFile(t *testing.T) {
	ctx := context.Background()
	vault, err := crypto.NewVault(testMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	mem := NewMemoryStore(vault)
	now := time.Now().UTC().Truncate(time.Second)
	h, err := mem.UpsertObservedHost(ctx, &domain.Host{IP: "10.1.2.3", Hostname: "legacy.example", LifecycleState: domain.HostStateActive, FirstSeen: now, LastSeen: now})
	if err != nil {
		t.Fatal(err)
	}
	run := &domain.ScanRun{ID: NewID(), Name: "legacy run", Status: domain.ScanStatusCompleted, StartedAt: now}
	if err := mem.CreateScanRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	// Legacy payloads: plain vault envelopes without the gzip layer.
	legacyHosts := []domain.Host{{ID: h.ID, IP: "10.1.2.3", LifecycleState: domain.HostStateActive}}
	snapEnc, err := vault.EncryptJSON(legacyHosts, "scan_snapshots:"+run.ID+":payload")
	if err != nil {
		t.Fatal(err)
	}
	xmlEnc, err := vault.Encrypt("<nmaprun>legacy</nmaprun>", "scan_runs:"+run.ID+":raw_nmap_xml")
	if err != nil {
		t.Fatal(err)
	}
	mem.mu.Lock()
	mem.snapshots[run.ID] = snapEnc
	row := mem.scanRuns[run.ID]
	row.RawNmapXMLEnc, row.HasRawNmapXML = xmlEnc, true
	mem.scanRuns[run.ID] = row
	st := memoryState{
		Version: memorySnapshotVersion, CryptoKeys: mem.cryptoKeys, ActiveKID: mem.activeKID, Roles: mem.roles,
		Users: mem.users, Targets: mem.targets, Exclusions: mem.exclusions, Profiles: mem.profiles,
		ScanRuns: mem.scanRuns, ScanChunks: mem.scanChunks, Hosts: mem.hosts, HostByIPHMAC: mem.hostByIPHMAC,
		Services: mem.services, Observations: mem.observations, Overrides: mem.overrides, Changes: mem.changes,
		Snapshots: mem.snapshots, Signatures: mem.signatures,
	}
	mem.mu.Unlock()
	raw, err := json.Marshal(&st)
	if err != nil {
		t.Fatal(err)
	}
	// A field from a future or past release is skipped, not an error.
	raw = append([]byte(`{"some_retired_field":{"a":[1,2,3]},`), raw[1:]...)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	sealed, err := vault.SealBlob(gz.Bytes(), fileStoreAAD)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "store.enc")
	if err := os.WriteFile(path, append(append([]byte{}, fileStoreMagic...), sealed...), 0o600); err != nil {
		t.Fatal(err)
	}

	fs, err := OpenFileStore(path, vault, FileStoreOptions{})
	if err != nil {
		t.Fatalf("open legacy store: %v", err)
	}
	defer fs.Close()
	got, err := fs.GetHostByIP(ctx, "10.1.2.3")
	if err != nil || got.Hostname != "legacy.example" {
		t.Fatalf("host after legacy load: %+v %v", got, err)
	}
	snap, err := fs.GetScanSnapshot(ctx, run.ID)
	if err != nil || len(snap) != 1 || snap[0].IP != "10.1.2.3" {
		t.Fatalf("legacy snapshot: %+v %v", snap, err)
	}
	gotRun, err := fs.GetScanRun(ctx, run.ID)
	if err != nil || gotRun.RawNmapXML != "<nmaprun>legacy</nmaprun>" || !gotRun.HasRawNmapXML {
		t.Fatalf("legacy raw XML: %+v %v", gotRun, err)
	}

	// New writes are compressed and still round-trip through the file.
	if err := fs.SaveScanSnapshot(ctx, run.ID, []domain.Host{{ID: h.ID, IP: "10.1.2.3", LifecycleState: domain.HostStateMissing}}); err != nil {
		t.Fatal(err)
	}
	fs.Close()
	fs2, err := OpenFileStore(path, vault, FileStoreOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	snap, err = fs2.GetScanSnapshot(ctx, run.ID)
	if err != nil || len(snap) != 1 || snap[0].LifecycleState != domain.HostStateMissing {
		t.Fatalf("snapshot after reopen: %+v %v", snap, err)
	}
	fs2.mu.RLock()
	enc := fs2.snapshots[run.ID]
	fs2.mu.RUnlock()
	plain, err := vault.DecryptBytes(enc, "scan_snapshots:"+run.ID+":payload")
	if err != nil || !isGzip(plain) {
		t.Fatalf("new snapshot payload should be gzipped inside the envelope (err %v)", err)
	}
}
