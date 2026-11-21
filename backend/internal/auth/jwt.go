package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Claims represents the signed JWT payload.
type Claims struct {
	Sub      string `json:"sub"`
	Username string `json:"username"`
	RoleID   string `json:"role_id"`
	RoleSlug string `json:"role_slug"`
	RoleName string `json:"role_name"`
	IAT      int64  `json:"iat"`
	EXP      int64  `json:"exp"`
}

var jwtHeaderB64 = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// SignToken creates an HS256 JWT for the given user.
func SignToken(secret []byte, user *domain.User, ttl time.Duration) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("empty jwt secret")
	}
	now := time.Now().UTC()
	claims := Claims{
		Sub:      user.ID,
		Username: user.Username,
		RoleID:   user.RoleID,
		RoleSlug: user.RoleSlug,
		RoleName: user.RoleName,
		IAT:      now.Unix(),
		EXP:      now.Add(ttl).Unix(),
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := jwtHeaderB64 + "." + payloadB64

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sigB64, nil
}

// VerifyToken validates the HS256 signature and expiration of a JWT.
func VerifyToken(secret []byte, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed jwt")
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid jwt header encoding")
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr.Alg != "HS256" {
		return nil, errors.New("unsupported jwt algorithm")
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(expectedSig, gotSig) {
		return nil, errors.New("invalid jwt signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid jwt payload encoding")
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New("invalid jwt claims")
	}
	if time.Now().UTC().Unix() > claims.EXP {
		return nil, errors.New("jwt expired")
	}
	return &claims, nil
}
