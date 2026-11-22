package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBlobInPlaceMatchesSealAndOpen(t *testing.T) {
	v, err := NewVault(hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	const aad = "test:blob:v1"
	plain := bytes.Repeat([]byte("dzieciol store payload "), 1000)
	prefix := []byte("MAGIC123")

	for _, spare := range []int{BlobTagSize, 0} { // enough capacity, and the copying path
		buf := make([]byte, 0, len(prefix)+BlobNonceSize+len(plain)+spare)
		buf = append(buf, prefix...)
		buf = append(buf, make([]byte, BlobNonceSize)...)
		buf = append(buf, plain...)
		out, err := v.SealBlobInPlace(buf, len(prefix), aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out[:len(prefix)], prefix) || len(out) != len(prefix)+BlobNonceSize+len(plain)+BlobTagSize {
			t.Fatalf("spare=%d: unexpected layout (len %d)", spare, len(out))
		}
		got, err := v.OpenBlob(out[len(prefix):], aad)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("spare=%d: OpenBlob of an in-place seal: %v", spare, err)
		}
		if _, err := v.OpenBlob(out[len(prefix):], "other:aad"); err == nil {
			t.Fatal("wrong AAD must fail")
		}
	}

	sealed, err := v.SealBlob(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.OpenBlobInPlace(sealed, aad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("OpenBlobInPlace of SealBlob output: %v", err)
	}
	sealed, _ = v.SealBlob(plain, aad)
	sealed[len(sealed)/2] ^= 1
	if _, err := v.OpenBlobInPlace(sealed, aad); err == nil {
		t.Fatal("tampered blob must fail")
	}
	if _, err := v.OpenBlobInPlace([]byte("short"), aad); err == nil {
		t.Fatal("short blob must fail")
	}
}
