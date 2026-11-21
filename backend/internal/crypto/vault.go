package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
)

const (
	encPrefix  = "enc:v1:"
	wrapPrefix = "wrap:v1:"
)

// Status contains safe encryption metadata suitable for admin telemetry and proof views.
// It NEVER exposes KEK, DEK, or HMAC key material.
type Status struct {
	Active           bool   `json:"active"`
	Algorithm        string `json:"algorithm"`
	BlindIndexAlgo   string `json:"blind_index_algo"`
	Format           string `json:"format"`
	ActiveKeyVersion string `json:"active_key_version"`
	KeyCount         int    `json:"key_count"`
	DevKeyGenerated  bool   `json:"dev_key_generated"`
}

// Vault provides Envelope Encryption (AES-256-GCM AEAD with AAD),
// HMAC-SHA256 blind indexing, and versioned DEK rotation.
type Vault struct {
	kek             []byte
	hmacKey         []byte
	jwtKey          []byte
	devKeyGenerated bool

	mu          sync.RWMutex
	activeKID   string
	nextVersion int
	deks        map[string][]byte
	wrappedDEKs map[string]string
}

// NewVault initializes a Vault from masterKey (64-char hex or base64 32-byte key).
// If masterKey is empty, a cryptographically random ephemeral dev key is generated with a warning.
func NewVault(masterKey string) (*Vault, error) {
	kek, devGen, err := parseMasterKey(masterKey)
	if err != nil {
		return nil, err
	}

	// The "aegis-asi:" KDF labels predate the Dzięcioł rename and are kept on purpose:
	// changing them would make every existing blind index, JWT and store unreadable.
	v := &Vault{
		kek:             kek,
		hmacKey:         deriveSubkey(kek, "aegis-asi:blind-index:v1"),
		jwtKey:          deriveSubkey(kek, "aegis-asi:jwt-signing:v1"),
		devKeyGenerated: devGen,
		deks:            make(map[string][]byte),
		wrappedDEKs:     make(map[string]string),
		nextVersion:     1,
	}

	if _, _, err := v.generateAndActivateDEKLocked(); err != nil {
		return nil, err
	}
	return v, nil
}

func parseMasterKey(raw string) ([]byte, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, false, fmt.Errorf("generate dev master key: %w", err)
		}
		log.Printf("[WARN] DZIECIOL_MASTER_KEY is unset; generated ephemeral 256-bit dev master key (set DZIECIOL_MASTER_KEY in production)")
		return b, true, nil
	}

	// 1. Hex encoded 32 bytes (64 hex chars)
	if len(raw) == 64 {
		if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
			return decoded, false, nil
		}
	}

	// 2. Base64 encoded 32 bytes (standard or raw)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(raw); err == nil && len(decoded) == 32 {
			return decoded, false, nil
		}
	}

	// 3. Fallback: derive 32-byte key via SHA-256 from passphrase
	log.Printf("[WARN] DZIECIOL_MASTER_KEY is not raw 32-byte hex/base64; deriving 256-bit KEK via SHA-256")
	sum := sha256.Sum256([]byte(raw))
	return sum[:], false, nil
}

func deriveSubkey(kek []byte, label string) []byte {
	mac := hmac.New(sha256.New, kek)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

func (v *Vault) generateAndActivateDEKLocked() (string, string, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return "", "", fmt.Errorf("generate dek: %w", err)
	}
	kid := fmt.Sprintf("dek-v%d", v.nextVersion)
	v.nextVersion++

	wrapped, err := wrapWithKEK(v.kek, kid, dek)
	if err != nil {
		return "", "", err
	}
	v.deks[kid] = dek
	v.wrappedDEKs[kid] = wrapped
	v.activeKID = kid
	return kid, wrapped, nil
}

func wrapWithKEK(kek []byte, kid string, dek []byte) (string, error) {
	ct, err := aesGCMEncrypt(kek, dek, []byte("dek:"+kid))
	if err != nil {
		return "", fmt.Errorf("wrap dek %s: %w", kid, err)
	}
	return wrapPrefix + kid + ":" + base64.StdEncoding.EncodeToString(ct), nil
}

func unwrapWithKEK(kek []byte, wrapped string) (string, []byte, error) {
	if !strings.HasPrefix(wrapped, wrapPrefix) {
		return "", nil, errors.New("invalid wrapped DEK format")
	}
	rest := strings.TrimPrefix(wrapped, wrapPrefix)
	idx := strings.IndexByte(rest, ':')
	if idx <= 0 {
		return "", nil, errors.New("malformed wrapped DEK header")
	}
	kid := rest[:idx]
	payload, err := base64.StdEncoding.DecodeString(rest[idx+1:])
	if err != nil {
		return "", nil, fmt.Errorf("decode wrapped DEK: %w", err)
	}
	dek, err := aesGCMDecrypt(kek, payload, []byte("dek:"+kid))
	if err != nil {
		return "", nil, fmt.Errorf("unwrap dek %s (wrong DZIECIOL_MASTER_KEY?): %w", kid, err)
	}
	if len(dek) != 32 {
		return "", nil, errors.New("unwrapped DEK has invalid length")
	}
	return kid, dek, nil
}

// LoadWrappedDEKs restores persisted wrapped DEKs from storage and sets the active KID.
func (v *Vault) LoadWrappedDEKs(wrapped map[string]string, activeKID string) error {
	if len(wrapped) == 0 {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	loadedDEKs := make(map[string][]byte, len(wrapped))
	loadedWrapped := make(map[string]string, len(wrapped))
	maxVer := 0

	for kid, w := range wrapped {
		parsedKID, dek, err := unwrapWithKEK(v.kek, w)
		if err != nil {
			return err
		}
		if parsedKID != kid {
			return fmt.Errorf("wrapped DEK kid mismatch: expected %s got %s", kid, parsedKID)
		}
		loadedDEKs[kid] = dek
		loadedWrapped[kid] = w
		if ver := parseVersionNum(kid); ver > maxVer {
			maxVer = ver
		}
	}

	if activeKID == "" || loadedDEKs[activeKID] == nil {
		return fmt.Errorf("active KID %q not found in loaded keys", activeKID)
	}

	v.deks = loadedDEKs
	v.wrappedDEKs = loadedWrapped
	v.activeKID = activeKID
	v.nextVersion = maxVer + 1
	return nil
}

func parseVersionNum(kid string) int {
	if strings.HasPrefix(kid, "dek-v") {
		n, err := strconv.Atoi(strings.TrimPrefix(kid, "dek-v"))
		if err == nil && n > 0 {
			return n
		}
	}
	return 1
}

// ExportWrappedDEKs returns a copy of all wrapped DEKs and the currently active KID.
func (v *Vault) ExportWrappedDEKs() (map[string]string, string) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make(map[string]string, len(v.wrappedDEKs))
	for k, val := range v.wrappedDEKs {
		out[k] = val
	}
	return out, v.activeKID
}

// ActiveKID returns the identifier of the currently active Data Encryption Key.
func (v *Vault) ActiveKID() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.activeKID
}

// JWTSecret returns the JWT HMAC signing secret (using override if provided, otherwise derived from KEK).
func (v *Vault) JWTSecret(override string) []byte {
	if strings.TrimSpace(override) != "" {
		sum := sha256.Sum256([]byte(strings.TrimSpace(override)))
		return sum[:]
	}
	out := make([]byte, len(v.jwtKey))
	copy(out, v.jwtKey)
	return out
}

// Status returns safe metadata about encryption state.
func (v *Vault) Status() Status {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return Status{
		Active:           true,
		Algorithm:        "AES-256-GCM (Envelope AEAD)",
		BlindIndexAlgo:   "HMAC-SHA256",
		Format:           "enc:v1:<kid>:<base64(nonce|ct|tag)>",
		ActiveKeyVersion: v.activeKID,
		KeyCount:         len(v.deks),
		DevKeyGenerated:  v.devKeyGenerated,
	}
}

// RotateDEK generates a new versioned 256-bit DEK, wraps it with the KEK,
// activates it for new writes, and keeps prior DEKs for decrypting existing rows.
func (v *Vault) RotateDEK() (string, string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.generateAndActivateDEKLocked()
}

// Encrypt encrypts plaintext using AES-256-GCM with the active DEK and AAD (table:record_id:column).
// Empty strings remain empty so optional columns stay distinguishable.
func (v *Vault) Encrypt(plaintext, aad string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	return v.EncryptBytes([]byte(plaintext), aad)
}

// EncryptBytes encrypts raw bytes with AES-256-GCM and AAD.
func (v *Vault) EncryptBytes(plaintext []byte, aad string) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}
	v.mu.RLock()
	kid := v.activeKID
	dek := v.deks[kid]
	v.mu.RUnlock()

	if len(dek) != 32 {
		return "", errors.New("active DEK unavailable")
	}

	payload, err := aesGCMEncrypt(dek, plaintext, []byte(aad))
	if err != nil {
		return "", err
	}
	return encPrefix + kid + ":" + base64.StdEncoding.EncodeToString(payload), nil
}

// Decrypt decrypts an `enc:v1:<kid>:<base64>` string verifying AAD = table:record_id:column.
func (v *Vault) Decrypt(ciphertext, aad string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	raw, err := v.DecryptBytes(ciphertext, aad)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// DecryptBytes decrypts an envelope ciphertext and verifies its AAD tag.
func (v *Vault) DecryptBytes(ciphertext, aad string) ([]byte, error) {
	if ciphertext == "" {
		return nil, nil
	}
	kid, payload, err := parseEnvelope(ciphertext)
	if err != nil {
		return nil, err
	}

	v.mu.RLock()
	dek := v.deks[kid]
	v.mu.RUnlock()

	if len(dek) != 32 {
		return nil, fmt.Errorf("unknown DEK version %q", kid)
	}
	return aesGCMDecrypt(dek, payload, []byte(aad))
}

// EncryptJSON marshals v to JSON and encrypts it with AAD.
func (v *Vault) EncryptJSON(val any, aad string) (string, error) {
	if val == nil {
		return "", nil
	}
	b, err := json.Marshal(val)
	if err != nil {
		return "", fmt.Errorf("marshal json for encryption: %w", err)
	}
	if string(b) == "null" {
		return "", nil
	}
	return v.EncryptBytes(b, aad)
}

// DecryptJSON decrypts ciphertext and unmarshals JSON into dst.
func (v *Vault) DecryptJSON(ciphertext, aad string, dst any) error {
	if ciphertext == "" {
		return nil
	}
	b, err := v.DecryptBytes(ciphertext, aad)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, dst)
}

// ReEncrypt decrypts ciphertext under its old DEK and re-encrypts it under the currently active DEK.
// Returns changed=false if ciphertext is empty or already encrypted with the active DEK.
func (v *Vault) ReEncrypt(ciphertext, aad string) (string, bool, error) {
	if ciphertext == "" {
		return "", false, nil
	}
	kid, _, err := parseEnvelope(ciphertext)
	if err != nil {
		return "", false, err
	}
	if kid == v.ActiveKID() {
		return ciphertext, false, nil
	}
	plain, err := v.DecryptBytes(ciphertext, aad)
	if err != nil {
		return "", false, err
	}
	reEnc, err := v.EncryptBytes(plain, aad)
	if err != nil {
		return "", false, err
	}
	return reEnc, true, nil
}

// BlindIndex computes a deterministic HMAC-SHA256 index for exact equality lookup
// and deduplication of encrypted fields (IPs, hostnames) without exposing plaintext.
func (v *Vault) BlindIndex(value string) string {
	norm := strings.ToLower(strings.TrimSpace(value))
	mac := hmac.New(sha256.New, v.hmacKey)
	mac.Write([]byte(norm))
	return hex.EncodeToString(mac.Sum(nil))
}

func parseEnvelope(ciphertext string) (string, []byte, error) {
	if !strings.HasPrefix(ciphertext, encPrefix) {
		return "", nil, errors.New("ciphertext missing enc:v1: prefix")
	}
	rest := strings.TrimPrefix(ciphertext, encPrefix)
	idx := strings.IndexByte(rest, ':')
	if idx <= 0 {
		return "", nil, errors.New("malformed ciphertext header")
	}
	kid := rest[:idx]
	payload, err := base64.StdEncoding.DecodeString(rest[idx+1:])
	if err != nil {
		return "", nil, fmt.Errorf("decode ciphertext base64: %w", err)
	}
	return kid, payload, nil
}

func aesGCMEncrypt(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func aesGCMDecrypt(key, payload, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(payload) < ns+gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := payload[:ns], payload[ns:]
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("aead authentication failed: %w", err)
	}
	return plain, nil
}
