package screenshot

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	_ "image/png" // Chromium may return PNG
	"math/bits"
	"strconv"
)

// Output geometry. The browser renders a 1280x800 viewport; we keep a 960x600 picture
// (readable text, about 40 to 80 KB as JPEG) and a 320x200 thumbnail for the gallery grid.
const (
	ViewportWidth  = 1280
	ViewportHeight = 800
	FullWidth      = 960
	FullHeight     = 600
	ThumbWidth     = 320
	ThumbHeight    = 200

	fullQuality  = 72
	thumbQuality = 70
	// fullBudget: above this the full image is re-encoded at a lower quality.
	fullBudget = 90 << 10
	// maxRawBytes bounds what we accept from the browser or an agent upload.
	maxRawBytes = 8 << 20
)

// Processed is a captured page turned into stored artefacts.
type Processed struct {
	Full   []byte
	Thumb  []byte
	Width  int
	Height int
	PHash  uint64
}

// Process decodes a raw PNG/JPEG screenshot, downscales it to the stored size, makes a
// thumbnail and computes the perceptual hash.
func Process(raw []byte) (*Processed, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty screenshot")
	}
	if len(raw) > maxRawBytes {
		return nil, fmt.Errorf("screenshot too large (%d bytes)", len(raw))
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode screenshot: %w", err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 8192 || cfg.Height > 8192 {
		return nil, fmt.Errorf("screenshot has odd size %dx%d", cfg.Width, cfg.Height)
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode screenshot: %w", err)
	}
	rgba := toRGBA(src)
	fw, fh := fit(rgba.Bounds().Dx(), rgba.Bounds().Dy(), FullWidth, FullHeight)
	full := resize(rgba, fw, fh)
	fullJPEG, err := encodeJPEG(full, fullQuality)
	if err != nil {
		return nil, err
	}
	if len(fullJPEG) > fullBudget {
		if smaller, err := encodeJPEG(full, 55); err == nil {
			fullJPEG = smaller
		}
	}
	tw, th := fit(fw, fh, ThumbWidth, ThumbHeight)
	thumbJPEG, err := encodeJPEG(resize(full, tw, th), thumbQuality)
	if err != nil {
		return nil, err
	}
	return &Processed{Full: fullJPEG, Thumb: thumbJPEG, Width: fw, Height: fh, PHash: DHash(full)}, nil
}

// Validate checks that an uploaded screenshot (from an agent) is a sane JPEG pair before it
// is stored. It returns the decoded size of the full image.
func Validate(full, thumb []byte) (int, int, error) {
	if len(full) == 0 || len(thumb) == 0 {
		return 0, 0, errors.New("missing image")
	}
	if len(full) > 2<<20 || len(thumb) > 512<<10 {
		return 0, 0, errors.New("image too large")
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(full))
	if err != nil || format != "jpeg" {
		return 0, 0, errors.New("full image is not a JPEG")
	}
	if cfg.Width > 2*FullWidth || cfg.Height > 2*FullHeight || cfg.Width <= 0 || cfg.Height <= 0 {
		return 0, 0, errors.New("full image has odd size")
	}
	tcfg, tformat, err := image.DecodeConfig(bytes.NewReader(thumb))
	if err != nil || tformat != "jpeg" || tcfg.Width > 2*ThumbWidth || tcfg.Height > 2*ThumbHeight {
		return 0, 0, errors.New("thumbnail is not a small JPEG")
	}
	return cfg.Width, cfg.Height, nil
}

func encodeJPEG(img image.Image, q int) ([]byte, error) {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
		return nil, fmt.Errorf("encode jpeg: %w", err)
	}
	return buf.Bytes(), nil
}

// fit scales (w, h) down to fit (maxW, maxH), keeping the aspect ratio. Never upscales.
func fit(w, h, maxW, maxH int) (int, int) {
	if w <= maxW && h <= maxH {
		return w, h
	}
	nw, nh := maxW, h*maxW/w
	if nh > maxH {
		nw, nh = w*maxH/h, maxH
	}
	if nw < 1 {
		nw = 1
	}
	if nh < 1 {
		nh = 1
	}
	return nw, nh
}

func toRGBA(src image.Image) *image.RGBA {
	if r, ok := src.(*image.RGBA); ok && r.Bounds().Min == (image.Point{}) {
		return r
	}
	b := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(dst, dst.Bounds(), src, b.Min, draw.Src)
	return dst
}

// resize downscales with an area average (box filter): every source pixel contributes to
// exactly one destination pixel. Good enough for text-heavy pages and cheap.
func resize(src *image.RGBA, w, h int) *image.RGBA {
	sw, sh := src.Bounds().Dx(), src.Bounds().Dy()
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	if sw == w && sh == h {
		copy(dst.Pix, src.Pix)
		return dst
	}
	for y := 0; y < h; y++ {
		y0, y1 := y*sh/h, (y+1)*sh/h
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < w; x++ {
			x0, x1 := x*sw/w, (x+1)*sw/w
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, b, a, n uint32
			for sy := y0; sy < y1 && sy < sh; sy++ {
				off := sy*src.Stride + x0*4
				for sx := x0; sx < x1 && sx < sw; sx++ {
					r += uint32(src.Pix[off])
					g += uint32(src.Pix[off+1])
					b += uint32(src.Pix[off+2])
					a += uint32(src.Pix[off+3])
					off += 4
					n++
				}
			}
			if n == 0 {
				continue
			}
			d := y*dst.Stride + x*4
			dst.Pix[d] = uint8(r / n)
			dst.Pix[d+1] = uint8(g / n)
			dst.Pix[d+2] = uint8(b / n)
			dst.Pix[d+3] = uint8(a / n)
		}
	}
	return dst
}

// DHash is the 64-bit difference hash of an image: shrink to 9x8 grey, then one bit per
// horizontal neighbour pair (left brighter than right). Similar pages give hashes a few bits
// apart; a different page differs in many bits.
func DHash(img *image.RGBA) uint64 {
	small := resize(img, 9, 8)
	var h uint64
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			if grey(small, x, y) > grey(small, x+1, y) {
				h |= 1 << uint(y*8+x)
			}
		}
	}
	return h
}

func grey(img *image.RGBA, x, y int) uint32 {
	o := y*img.Stride + x*4
	return (299*uint32(img.Pix[o]) + 587*uint32(img.Pix[o+1]) + 114*uint32(img.Pix[o+2])) / 1000
}

// FormatHash renders a perceptual hash as 16 hex chars.
func FormatHash(h uint64) string {
	s := strconv.FormatUint(h, 16)
	for len(s) < 16 {
		s = "0" + s
	}
	return s
}

// ParseHash is the inverse of FormatHash.
func ParseHash(s string) (uint64, bool) {
	if len(s) != 16 {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 64)
	return v, err == nil
}

// Distance is the Hamming distance between two perceptual hashes (0 = same picture).
func Distance(a, b uint64) int { return bits.OnesCount64(a ^ b) }
