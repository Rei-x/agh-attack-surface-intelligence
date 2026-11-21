package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// blobKeyLabel derives a dedicated 256-bit key (HMAC-SHA256 of the KEK) used to seal whole
// files such as the local encrypted store snapshot. It is independent from the per-row DEKs
// so the snapshot can carry the wrapped DEKs inside its own encrypted envelope.
const blobKeyLabel = "aegis-asi:file-blob:v1"

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
		return nil, fmt.Errorf("decrypt blob (wrong ASI_MASTER_KEY / master.key?): %w", err)
	}
	return plain, nil
}

// GenerateMasterKey returns a fresh random 256-bit master key encoded as 64 hex chars,
// suitable for ASI_MASTER_KEY or a 0600 master.key file.
func GenerateMasterKey() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate master key: %w", err)
	}
	return hex.EncodeToString(b), nil
}
