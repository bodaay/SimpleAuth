package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	kid        string
}

type Claims struct {
	jwt.RegisteredClaims
	GUID           string   `json:"guid,omitempty"`
	Name           string   `json:"name,omitempty"`
	Email          string   `json:"email,omitempty"`
	Department     string   `json:"department,omitempty"`
	Company        string   `json:"company,omitempty"`
	JobTitle       string   `json:"job_title,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	Impersonated   bool     `json:"impersonated,omitempty"`
	ImpersonatedBy string   `json:"impersonated_by,omitempty"`
	FamilyID       string   `json:"family_id,omitempty"`

	// OIDC / Keycloak-compatible claims
	PreferredUsername string                     `json:"preferred_username,omitempty"`
	RealmAccess       *RealmAccess               `json:"realm_access,omitempty"`
	ResourceAccess    map[string]*ResourceAccess `json:"resource_access,omitempty"`
	Scope             string                     `json:"scope,omitempty"`
	Nonce             string                     `json:"nonce,omitempty"`
	AtHash            string                     `json:"at_hash,omitempty"`
	Typ               string                     `json:"typ,omitempty"`
	Azp               string                     `json:"azp,omitempty"`
	SessionState      string                     `json:"session_state,omitempty"`
}

type RealmAccess struct {
	Roles []string `json:"roles"`
}

type ResourceAccess struct {
	Roles []string `json:"roles"`
}

func NewJWTManager(dataDir, issuer string) (*JWTManager, error) {
	privPath := filepath.Join(dataDir, "private.pem")
	pubPath := filepath.Join(dataDir, "public.pem")

	m := &JWTManager{issuer: issuer, kid: uuid.New().String()[:8]}

	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		if err := m.generateKeys(privPath, pubPath); err != nil {
			return nil, fmt.Errorf("generate rsa keys: %w", err)
		}
	} else {
		if err := m.loadKeys(privPath, pubPath); err != nil {
			return nil, fmt.Errorf("load rsa keys: %w", err)
		}
	}
	return m, nil
}

func (m *JWTManager) generateKeys(privPath, pubPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	m.privateKey = key
	m.publicKey = &key.PublicKey

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return os.WriteFile(pubPath, pubPEM, 0644)
}

func (m *JWTManager) loadKeys(privPath, pubPath string) error {
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(privData)
	if block == nil {
		return fmt.Errorf("no PEM block found in private key")
	}
	m.privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	m.publicKey = &m.privateKey.PublicKey
	return nil
}

func (m *JWTManager) IssueAccessToken(c Claims, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	c.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    m.issuer,
		Subject:   c.Subject,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		ID:        uuid.New().String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = m.kid
	return token.SignedString(m.privateKey)
}

func (m *JWTManager) IssueRefreshToken(userGUID, familyID string, ttl time.Duration) (string, string, error) {
	tokenID := uuid.New().String()
	if familyID == "" {
		familyID = uuid.New().String()
	}
	now := time.Now().UTC()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userGUID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        tokenID,
		},
		FamilyID: familyID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid
	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", "", err
	}
	return signed, tokenID, nil
}

func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (m *JWTManager) JWKS() JWKSResponse {
	return JWKSResponse{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: m.kid,
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(m.publicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.publicKey.E)).Bytes()),
			},
		},
	}
}

func (m *JWTManager) JWKSHandler() []byte {
	data, _ := json.Marshal(m.JWKS())
	return data
}

// Issuer returns the configured JWT issuer.
func (m *JWTManager) Issuer() string {
	return m.issuer
}

// Kid returns the key ID.
func (m *JWTManager) Kid() string {
	return m.kid
}

// IssueAccessTokenWithIssuer issues an access token with a custom issuer (for OIDC).
func (m *JWTManager) IssueAccessTokenWithIssuer(c Claims, ttl time.Duration, issuer string) (string, error) {
	now := time.Now().UTC()
	c.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   c.Subject,
		Audience:  c.Audience,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		ID:        uuid.New().String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = m.kid
	return token.SignedString(m.privateKey)
}

// IssueIDToken issues an OIDC ID token.
func (m *JWTManager) IssueIDToken(c Claims, ttl time.Duration, issuer string) (string, error) {
	now := time.Now().UTC()
	c.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   c.Subject,
		Audience:  c.Audience,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		ID:        uuid.New().String(),
	}
	c.Typ = "ID"
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = m.kid
	return token.SignedString(m.privateKey)
}

// ComputeAtHash computes the at_hash value for an OIDC ID token (RS256 = SHA-256).
func ComputeAtHash(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:16]) // left half
}
