package screenshot

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// page renders a fake 1280x800 "web page": a header bar, a login box and text lines. variant
// moves things around so two variants look different to the perceptual hash.
func page(t *testing.T, variant int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, ViewportWidth, ViewportHeight))
	for y := 0; y < ViewportHeight; y++ {
		for x := 0; x < ViewportWidth; x++ {
			c := color.RGBA{250, 250, 250, 255}
			switch {
			case variant == 0 && y < 80:
				c = color.RGBA{40, 60, 120, 255}
			case variant == 0 && x > 440 && x < 840 && y > 250 && y < 550:
				c = color.RGBA{220, 220, 230, 255}
			case variant == 1:
				// Dark theme fading to the right: almost every dHash bit flips.
				g := uint8(240 - x*200/ViewportWidth)
				c = color.RGBA{g, g, g, 255}
			}
			img.SetRGBA(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProcessDownscalesAndHashes(t *testing.T) {
	p, err := Process(page(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	if p.Width != FullWidth || p.Height != FullHeight {
		t.Fatalf("full size %dx%d", p.Width, p.Height)
	}
	if len(p.Full) == 0 || len(p.Full) > fullBudget {
		t.Fatalf("full jpeg %d bytes", len(p.Full))
	}
	if len(p.Thumb) == 0 || len(p.Thumb) >= len(p.Full) {
		t.Fatalf("thumb %d bytes vs full %d", len(p.Thumb), len(p.Full))
	}
	if _, _, err := Validate(p.Full, p.Thumb); err != nil {
		t.Fatalf("own output does not validate: %v", err)
	}
	again, _ := Process(page(t, 0))
	if Distance(p.PHash, again.PHash) != 0 {
		t.Fatal("same page, different hash")
	}
	other, _ := Process(page(t, 1))
	if d := Distance(p.PHash, other.PHash); d < ChangeDistance {
		t.Fatalf("different pages only %d bits apart", d)
	}
	if h, ok := ParseHash(FormatHash(p.PHash)); !ok || h != p.PHash {
		t.Fatal("hash round trip")
	}
}

func TestProcessRejectsJunk(t *testing.T) {
	if _, err := Process([]byte("<html>not an image</html>")); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := Validate([]byte("x"), []byte("y")); err == nil {
		t.Fatal("expected validate error")
	}
	png0 := page(t, 0)
	if _, _, err := Validate(png0, png0); err == nil {
		t.Fatal("PNG must not pass as stored JPEG")
	}
}

// fakeBrowser renders canned pages.
type fakeBrowser struct {
	pages  map[string][]byte
	delay  time.Duration
	calls  atomic.Int32
	closed atomic.Bool
}

func (f *fakeBrowser) Screenshot(ctx context.Context, url string) ([]byte, string, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	raw, ok := f.pages[url]
	if !ok {
		return nil, "", errors.New("net::ERR_CONNECTION_REFUSED")
	}
	return raw, "Login - " + url, nil
}
func (f *fakeBrowser) Alive() bool  { return !f.closed.Load() }
func (f *fakeBrowser) Close() error { f.closed.Store(true); return nil }

func TestCapturerLaunchesLazilyAndProcesses(t *testing.T) {
	fb := &fakeBrowser{pages: map[string][]byte{"http://10.0.0.1/": page(t, 0)}}
	var launches atomic.Int32
	c := NewCapturer(func() (Browser, error) { launches.Add(1); return fb, nil }, Options{IdleClose: 50 * time.Millisecond})
	defer c.Close()
	if launches.Load() != 0 {
		t.Fatal("browser launched before first capture")
	}
	shot, err := c.Capture(context.Background(), "http://10.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	if shot.Width != FullWidth || len(shot.Thumb) == 0 || shot.Title == "" || len(shot.PHash) != 16 || shot.CapturedAt.IsZero() {
		t.Fatalf("bad screenshot %+v", shot)
	}
	if _, err := c.Capture(context.Background(), "http://10.0.0.2/"); err == nil {
		t.Fatal("unreachable page must fail")
	}
	if launches.Load() != 1 {
		t.Fatalf("launches = %d, want 1 (browser reused)", launches.Load())
	}
	// Idle: the browser is closed and relaunched on demand.
	deadline := time.Now().Add(2 * time.Second)
	for !fb.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !fb.closed.Load() {
		t.Fatal("idle browser not closed")
	}
	fb.closed.Store(false)
	if _, err := c.Capture(context.Background(), "http://10.0.0.1/"); err != nil {
		t.Fatal(err)
	}
	if launches.Load() != 2 {
		t.Fatalf("launches = %d, want 2", launches.Load())
	}
}

func TestCapturerTimeoutAndLaunchFailure(t *testing.T) {
	fb := &fakeBrowser{pages: map[string][]byte{"http://slow/": page(t, 0)}, delay: time.Second}
	c := NewCapturer(func() (Browser, error) { return fb, nil }, Options{Timeout: 50 * time.Millisecond})
	defer c.Close()
	start := time.Now()
	if _, err := c.Capture(context.Background(), "http://slow/"); err == nil {
		t.Fatal("slow page must time out")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("timeout not enforced")
	}

	var launches atomic.Int32
	bad := NewCapturer(func() (Browser, error) { launches.Add(1); return nil, errors.New("no sandbox") }, Options{})
	defer bad.Close()
	for i := 0; i < 3; i++ {
		if _, err := bad.Capture(context.Background(), "http://x/"); err == nil {
			t.Fatal("expected launch error")
		}
	}
	if launches.Load() != 1 {
		t.Fatalf("failed launch retried %d times, want 1 (backoff)", launches.Load())
	}
	if !strings.Contains(bad.LastError(), "no sandbox") {
		t.Fatalf("LastError = %q", bad.LastError())
	}
}

func TestSharedIsNilUnderGoTest(t *testing.T) {
	if Shared() != nil {
		t.Fatal("unit tests must never start a real browser")
	}
}

func testVault(t *testing.T) *crypto.Vault {
	t.Helper()
	v, err := crypto.NewVault(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func shotOf(t *testing.T, variant int, at time.Time) *domain.Screenshot {
	t.Helper()
	p, err := Process(page(t, variant))
	if err != nil {
		t.Fatal(err)
	}
	return &domain.Screenshot{Image: p.Full, Thumb: p.Thumb, Width: p.Width, Height: p.Height,
		PHash: FormatHash(p.PHash), URL: "http://10.0.0.1/", Title: "Admin", CapturedAt: at}
}

func TestStoreDedupKeepAndEncryption(t *testing.T) {
	dir := t.TempDir()
	v := testVault(t)
	st, err := OpenStore(dir, v, 2)
	if err != nil {
		t.Fatal(err)
	}
	k := Key{IP: "10.0.0.1", Port: 8080, Protocol: "tcp"}
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

	r1, err := st.Put(k, shotOf(t, 0, t0), "run1")
	if err != nil || !r1.New || r1.Previous != nil || r1.Changed {
		t.Fatalf("first put: %+v %v", r1, err)
	}
	// Identical picture: deduplicated, only the timestamp moves.
	r2, err := st.Put(k, shotOf(t, 0, t0.Add(time.Hour)), "run2")
	if err != nil || r2.New || r2.Changed {
		t.Fatalf("dup put: %+v %v", r2, err)
	}
	if h := st.History(k); len(h) != 1 || !h[0].CapturedAt.Equal(t0.Add(time.Hour)) || !h[0].FirstSeen.Equal(t0) {
		t.Fatalf("history after dup: %+v", h)
	}
	// Different page: a change.
	r3, err := st.Put(k, shotOf(t, 1, t0.Add(2*time.Hour)), "run3")
	if err != nil || !r3.New || !r3.Changed || r3.Previous == nil || r3.Previous.ID != r1.Entry.ID {
		t.Fatalf("changed put: %+v %v", r3, err)
	}

	// Nothing on disk is a readable JPEG or contains the IP.
	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}) || bytes.Contains(b, []byte("10.0.0.1")) || bytes.Contains(b, []byte("JFIF")) {
			t.Errorf("%s is not encrypted", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	img, err := st.Read(r3.Entry.ID)
	if err != nil || !bytes.HasPrefix(img, []byte{0xFF, 0xD8}) {
		t.Fatalf("read back: %v", err)
	}
	if !st.Owns(r3.Entry.Thumb) || st.Owns(strings.Repeat("0", 64)) {
		t.Fatal("Owns")
	}
	if _, err := st.Read("../../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Fatal("path traversal id must be rejected")
	}

	// Third distinct picture with keep=2 prunes the oldest and deletes its blobs.
	var third *domain.Screenshot
	{
		img := image.NewRGBA(image.Rect(0, 0, 640, 400))
		for i := range img.Pix {
			img.Pix[i] = uint8(i * 7)
		}
		var buf bytes.Buffer
		_ = png.Encode(&buf, img)
		p, err := Process(buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		third = &domain.Screenshot{Image: p.Full, Thumb: p.Thumb, PHash: FormatHash(p.PHash), CapturedAt: t0.Add(3 * time.Hour)}
	}
	if _, err := st.Put(k, third, "run4"); err != nil {
		t.Fatal(err)
	}
	if h := st.History(k); len(h) != 2 || h[1].ID != r3.Entry.ID {
		t.Fatalf("keep=2 history: %d entries", len(h))
	}
	if _, err := st.Read(r1.Entry.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned blob still readable: %v", err)
	}

	// Reopen: the sealed index survives; a wrong key cannot open it.
	st2, err := OpenStore(dir, v, 2)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Count() != 1 || len(st2.ForIP("10.0.0.1")) != 1 || len(st2.Latest()) != 1 {
		t.Fatal("index not persisted")
	}
	other, _ := crypto.NewVault(strings.Repeat("cd", 32))
	if _, err := OpenStore(dir, other, 2); err == nil {
		t.Fatal("wrong master key must fail")
	}
}

func TestStoreRejectsBadUploads(t *testing.T) {
	st, err := OpenStore(t.TempDir(), testVault(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	k := Key{IP: "10.0.0.9", Port: 80}
	if _, err := st.Put(k, &domain.Screenshot{Image: []byte("<script>"), Thumb: []byte("x")}, ""); err == nil {
		t.Fatal("non-JPEG accepted")
	}
	if _, err := st.Put(Key{IP: "10.0.0.9", Port: 0}, shotOf(t, 0, time.Now()), ""); err == nil {
		t.Fatal("bad key accepted")
	}
	if st.Count() != 0 {
		t.Fatal("rejected upload stored")
	}
}

func TestSinkStoresAndRecordsChange(t *testing.T) {
	st, err := OpenStore(t.TempDir(), testVault(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	var events []domain.LiveEvent
	sink := &Sink{Store: st, Emit: func(e domain.LiveEvent) { events = append(events, e) }}
	obs := []domain.ObservedHost{{IP: "10.0.0.5", Services: []domain.ObservedService{
		{Port: 443, Protocol: "tcp", Screenshot: shotOf(t, 0, time.Now())},
		{Port: 22, Protocol: "tcp"},
	}}}
	sink.StoreScreenshots(context.Background(), "run1", obs)
	if st.Count() != 1 || len(events) != 1 {
		t.Fatalf("count=%d events=%d", st.Count(), len(events))
	}
}
