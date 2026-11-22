package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// blobKeyLabel derives a dedicated 256-bit key (HMAC-SHA256 of the KEK) used to seal whole
// files such as the local encrypted store snapshot. It is independent from the per-row DEKs
// so the snapshot can carry the wrapped DEKs inside its own encrypted envelope.
// KDF label predates the Dzięcioł rename; kept so existing encrypted data stays readable.
const blobKeyLabel = "aegis-asi:file-blob:v1"

// Blob layout: nonce(BlobNonceSize) | ciphertext | tag(BlobTagSize).
const (
	BlobNonceSize = 12
	BlobTagSize   = 16
)

// SealBlob encrypts an arbitrary byte payload with AES-256-GCM under a KEK-derived key.
// Output layout: nonce(12) | ciphertext | tag(16). aad binds the blob to its purpose/format.
func (v *Vault) SealBlob(plaintext []byte, aad string) ([]byte, error) {
	return aesGCMEncrypt(deriveSubkey(v.kek, blobKeyLabel), plaintext, []byte(aad))
}

// OpenBlob decrypts a payload produced by SealBlob. A wrong master key or any tampering
// fails AEAD authentication.
func (v *Vault) OpenBlob(payload []byte, aad string) ([]byte, error) {
	plain, err := aesGCMDecrypt(deriveSubkey(v.kek, blobKeyLabel), payload, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("decrypt blob (wrong DZIECIOL_MASTER_KEY / master.key?): %w", err)
	}
	return plain, nil
}

func (v *Vault) blobAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveSubkey(v.kek, blobKeyLabel))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealBlobInPlace is SealBlob without a second copy of a large payload. buf[off:] holds
// BlobNonceSize bytes of room followed by the plaintext: a fresh nonce is written into the
// room and the plaintext is encrypted where it lies. The returned slice is buf extended by
// the BlobTagSize tag; give buf that much spare capacity, otherwise it is copied once. The
// returned bytes from off on are exactly what SealBlob(plaintext, aad) returns.
func (v *Vault) SealBlobInPlace(buf []byte, off int, aad string) ([]byte, error) {
	if off < 0 || len(buf) < off+BlobNonceSize {
		return nil, errors.New("seal blob: buffer too short")
	}
	gcm, err := v.blobAEAD()
	if err != nil {
		return nil, err
	}
	if cap(buf)-len(buf) < gcm.Overhead() {
		grown := make([]byte, len(buf), len(buf)+gcm.Overhead())
		copy(grown, buf)
		buf = grown
	}
	nonce := buf[off : off+BlobNonceSize]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	plain := buf[off+BlobNonceSize:]
	sealed := gcm.Seal(plain[:0], nonce, plain, []byte(aad))
	return buf[:off+BlobNonceSize+len(sealed)], nil
}

// OpenBlobInPlace is OpenBlob decrypting into the payload's own storage, so opening a large
// file needs no second buffer. payload is overwritten and the plaintext aliases it.
func (v *Vault) OpenBlobInPlace(payload []byte, aad string) ([]byte, error) {
	gcm, err := v.blobAEAD()
	if err != nil {
		return nil, err
	}
	if len(payload) < BlobNonceSize+gcm.Overhead() {
		return nil, errors.New("decrypt blob: ciphertext too short")
	}
	nonce, ct := payload[:BlobNonceSize], payload[BlobNonceSize:]
	plain, err := gcm.Open(ct[:0], nonce, ct, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("decrypt blob (wrong DZIECIOL_MASTER_KEY / master.key?): aead authentication failed: %w", err)
	}
	return plain, nil
}

// GenerateMasterKey returns a fresh random 256-bit master key encoded as 64 hex chars,
// suitable for DZIECIOL_MASTER_KEY or a 0600 master.key file.
func GenerateMasterKey() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate master key: %w", err)
	}
	return hex.EncodeToString(b), nil
}
