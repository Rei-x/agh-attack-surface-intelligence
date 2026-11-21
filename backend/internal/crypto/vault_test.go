package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestVaultEncryptDecryptAndAADTamping(t *testing.T) {
	keyHex := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	v, err := NewVault(keyHex)
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if v.Status().DevKeyGenerated {
		t.Fatalf("expected DevKeyGenerated=false for valid 32-byte hex key")
	}

	aad := "hosts:host-123:ip"
	plain := "172.28.0.10"
	ct, err := v.Encrypt(plain, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(ct, "enc:v1:dek-v1:") {
		t.Fatalf("unexpected ciphertext prefix: %s", ct)
	}
	if strings.Contains(ct, plain) {
		t.Fatalf("plaintext leaked inside ciphertext: %s", ct)
	}

	// Valid decrypt
	got, err := v.Decrypt(ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("got %q want %q", got, plain)
	}

	// AAD row-swap rejection (different record ID)
	if _, err := v.Decrypt(ct, "hosts:host-999:ip"); err == nil {
		t.Fatalf("expected error on swapped record AAD, got nil")
	}
	// AAD column-swap rejection
	if _, err := v.Decrypt(ct, "hosts:host-123:hostname"); err == nil {
		t.Fatalf("expected error on swapped column AAD, got nil")
	}
	// Ciphertext bit-flip tamper rejection
	tampered := ct[:len(ct)-2] + "AA"
	if tampered == ct {
		tampered = ct[:len(ct)-2] + "BB"
	}
	if _, err := v.Decrypt(tampered, aad); err == nil {
		t.Fatalf("expected error on tampered ciphertext, got nil")
	}
}

func TestVaultBlindIndexAndRotation(t *testing.T) {
	keyHex := hex.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	v, err := NewVault(keyHex)
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}

	idx1 := v.BlindIndex("172.28.0.10")
	idx2 := v.BlindIndex("  172.28.0.10 ")
	if idx1 != idx2 || len(idx1) != 64 {
		t.Fatalf("blind index mismatch or bad length: %q vs %q", idx1, idx2)
	}
	if v.BlindIndex("Host.AGH.EDU.PL") != v.BlindIndex("host.agh.edu.pl") {
		t.Fatalf("blind index should normalize case")
	}

	aad := "services:svc-1:banner"
	ct1, err := v.Encrypt("Apache/2.4.58", aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	newKID, wrapped, err := v.RotateDEK()
	if err != nil {
		t.Fatalf("RotateDEK: %v", err)
	}
	if newKID != "dek-v2" || !strings.HasPrefix(wrapped, "wrap:v1:dek-v2:") {
		t.Fatalf("unexpected rotated key: kid=%s wrapped=%s", newKID, wrapped)
	}

	// Old ciphertext still decrypts after rotation
	plain, err := v.Decrypt(ct1, aad)
	if err != nil || plain != "Apache/2.4.58" {
		t.Fatalf("decrypt old ciphertext after rotation failed: plain=%q err=%v", plain, err)
	}

	// ReEncrypt upgrades ciphertext to dek-v2
	ct2, changed, err := v.ReEncrypt(ct1, aad)
	if err != nil || !changed || !strings.HasPrefix(ct2, "enc:v1:dek-v2:") {
		t.Fatalf("ReEncrypt failed: ct2=%s changed=%v err=%v", ct2, changed, err)
	}

	// Simulate server restart: new Vault with same KEK restores wrapped DEKs
	wrappedMap, active := v.ExportWrappedDEKs()
	v2, err := NewVault(keyHex)
	if err != nil {
		t.Fatalf("NewVault restart: %v", err)
	}
	if err := v2.LoadWrappedDEKs(wrappedMap, active); err != nil {
		t.Fatalf("LoadWrappedDEKs: %v", err)
	}
	got2, err := v2.Decrypt(ct2, aad)
	if err != nil || got2 != "Apache/2.4.58" {
		t.Fatalf("decrypt after restart failed: got=%q err=%v", got2, err)
	}
	if v2.BlindIndex("172.28.0.10") != idx1 {
		t.Fatalf("blind index changed across restart/rotation")
	}
}

func TestPasswordArgon2id(t *testing.T) {
	hash, err := HashPassword("Admin123!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("expected argon2id PHC string, got %s", hash)
	}
	if !VerifyPassword("Admin123!", hash) {
		t.Fatalf("expected VerifyPassword to succeed")
	}
	if VerifyPassword("WrongPass!", hash) {
		t.Fatalf("expected VerifyPassword to reject wrong password")
	}
}
