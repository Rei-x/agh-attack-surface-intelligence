package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"strconv"
)

// MurmurHash3_32 computes the signed 32-bit x86 MurmurHash3 (compatible with Python mmh3.hash).
func MurmurHash3_32(data []byte, seed uint32) int32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)

	h1 := seed
	n := len(data)
	nblocks := n / 4

	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4 : i*4+4])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(n)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}

// ShodanBase64 encodes raw bytes identically to Python's codecs.encode(raw, "base64")
// (RFC 2045 standard base64 wrapped with '\n' every 76 chars plus a trailing '\n').
func ShodanBase64(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	var buf bytes.Buffer
	buf.Grow(len(encoded) + len(encoded)/76 + 1)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// FaviconMMH3 returns the Shodan-compatible MurmurHash3 decimal string for raw favicon bytes.
func FaviconMMH3(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	b64 := ShodanBase64(raw)
	return strconv.FormatInt(int64(MurmurHash3_32(b64, 0)), 10)
}

// FaviconSHA256 returns the lowercase hex SHA-256 digest of raw favicon bytes.
func FaviconSHA256(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
