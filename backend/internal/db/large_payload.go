package db

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
)

// Large encrypted payloads (per-run inventory snapshots, merged raw nmap XML) are gzipped
// before the per-row AES-256-GCM envelope. Ciphertext does not compress, so without this the
// file store's outer gzip cannot shrink them at all, while their plaintext (repetitive JSON
// keys, XML tags) compresses 5 to 10 times. Payloads written before this change are plain
// JSON or XML; they never start with the gzip magic, so both forms decrypt.

func isGzip(b []byte) bool { return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b }

// encryptLarge compresses plain and seals it with the active DEK (empty stays empty).
func encryptLarge(v *crypto.Vault, plain []byte, aad string) (string, error) {
	if len(plain) == 0 {
		return "", nil
	}
	var buf bytes.Buffer
	buf.Grow(len(plain) / 4)
	zw, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(plain); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return v.EncryptBytes(buf.Bytes(), aad)
}

func encryptLargeString(v *crypto.Vault, plain, aad string) (string, error) {
	return encryptLarge(v, []byte(plain), aad)
}

func encryptLargeJSON(v *crypto.Vault, val any, aad string) (string, error) {
	raw, err := json.Marshal(val)
	if err != nil {
		return "", fmt.Errorf("marshal json for encryption: %w", err)
	}
	if string(raw) == "null" {
		return "", nil
	}
	return encryptLarge(v, raw, aad)
}

// decryptLarge opens a payload written by encryptLarge or by a plain vault.Encrypt.
func decryptLarge(v *crypto.Vault, ciphertext, aad string) ([]byte, error) {
	raw, err := v.DecryptBytes(ciphertext, aad)
	if err != nil || !isGzip(raw) {
		return raw, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decompress payload: %w", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("decompress payload: %w", err)
	}
	return out, nil
}

func decryptLargeString(v *crypto.Vault, ciphertext, aad string) (string, error) {
	raw, err := decryptLarge(v, ciphertext, aad)
	return string(raw), err
}

func decryptLargeJSON(v *crypto.Vault, ciphertext, aad string, dst any) error {
	raw, err := decryptLarge(v, ciphertext, aad)
	if err != nil || len(raw) == 0 {
		return err
	}
	return json.Unmarshal(raw, dst)
}
