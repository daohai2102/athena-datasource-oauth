// =========================================================================
// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
// This package is downstream-specific for OAuth Passthrough (Web Identity)
// authentication with AWS Athena and AWS STS.
// All OAuth token extraction, session name templating, JWT validation, and
// credentials caching are isolated in this package to minimize changes to
// upstream files and avoid merge conflicts during upstream sync.
// =========================================================================

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

type contextKey string

const (
	oauthTokenKey contextKey = "oauthToken"
	oauthUserKey  contextKey = "oauthUser"

	DefaultSessionName = "grafana-athena-session"
)

// ExtractToken extracts an OAuth/OIDC token from HTTP headers.
// As prioritized, it checks X-Id-Token first, then falls back to Authorization Bearer token.
func ExtractToken(headers http.Header) string {
	if headers == nil {
		return ""
	}

	// 1. Check X-Id-Token header
	if idToken := headers.Get(backend.OAuthIdentityIDTokenHeaderName); strings.TrimSpace(idToken) != "" {
		return strings.TrimSpace(idToken)
	}

	// 2. Check Authorization header
	if auth := headers.Get(backend.OAuthIdentityTokenHeaderName); auth != "" {
		trimmed := strings.TrimSpace(auth)
		if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
			return strings.TrimSpace(trimmed[7:])
		}
		// In case raw token was forwarded in Authorization
		if trimmed != "" {
			return trimmed
		}
	}

	return ""
}

// ExtractTokenFromMap extracts an OAuth/OIDC token from a map of string headers (case-insensitive).
func ExtractTokenFromMap(headers map[string]string) string {
	if headers == nil {
		return ""
	}

	// 1. Check X-Id-Token (case-insensitive)
	for k, v := range headers {
		if strings.EqualFold(k, backend.OAuthIdentityIDTokenHeaderName) && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}

	// 2. Check Authorization (case-insensitive)
	for k, v := range headers {
		if strings.EqualFold(k, backend.OAuthIdentityTokenHeaderName) && strings.TrimSpace(v) != "" {
			trimmed := strings.TrimSpace(v)
			if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
				return strings.TrimSpace(trimmed[7:])
			}
			return trimmed
		}
	}

	return ""
}

// ExtractTokenFromPluginRequest extracts the token from backend.QueryDataRequest or backend.CheckHealthRequest headers
func ExtractTokenFromPluginRequest(headers map[string]string) string {
	return ExtractTokenFromMap(headers)
}

// TokenClaims represents standard OpenID Connect / JWT claims used for pre-flight validation.
type TokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	ExpiresAt *int64 `json:"exp"`
	NotBefore *int64 `json:"nbf"`
	IssuedAt  *int64 `json:"iat"`
}

// ParseAndValidateToken performs local pre-flight checks on the token before sending to AWS STS:
// 1. Checks that the token is non-empty.
// 2. Checks that the token has 3 dot-separated segments (RFC 7519 JWT structure).
// 3. Verifies that the payload is valid base64url and valid JSON.
// 4. Verifies that the token has not expired and is active (with 1-minute clock skew tolerance).
func ParseAndValidateToken(token string) (*TokenClaims, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return nil, errors.New("token is empty")
	}

	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		if strings.HasPrefix(trimmed, "glsa_") {
			return nil, errors.New("token appears to be a Grafana service account token, not an OpenID Connect ID token")
		}
		return nil, errors.New("token is not a valid OpenID Connect JWT (expected 3 dot-separated base64url segments)")
	}

	// Decode payload (segment 2)
	payloadSegment := parts[1]
	decoded, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		// Fallback to padded decoding if unpadded fails
		decoded, err = base64.URLEncoding.DecodeString(payloadSegment)
		if err != nil {
			return nil, fmt.Errorf("failed to decode JWT payload base64url: %w", err)
		}
	}

	var claims TokenClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload JSON: %w", err)
	}

	now := time.Now()
	clockSkew := 1 * time.Minute

	if claims.ExpiresAt != nil {
		exp := time.Unix(*claims.ExpiresAt, 0)
		if now.After(exp.Add(clockSkew)) {
			return nil, fmt.Errorf("token expired at %s", exp.UTC().Format(time.RFC3339))
		}
	}

	if claims.NotBefore != nil {
		nbf := time.Unix(*claims.NotBefore, 0)
		if now.Before(nbf.Add(-clockSkew)) {
			return nil, fmt.Errorf("token is not valid before %s", nbf.UTC().Format(time.RFC3339))
		}
	}

	return &claims, nil
}

// ValidateToken performs pre-flight validation on the token and returns an error if invalid.
func ValidateToken(token string) error {
	_, err := ParseAndValidateToken(token)
	return err
}

// CreateTestJWT is a helper function to create a valid 3-part base64url JWT for testing.
func CreateTestJWT(sub string, exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	expUnix := exp.Unix()
	claims := TokenClaims{
		Subject:   sub,
		Issuer:    "https://auth.example.com",
		ExpiresAt: &expUnix,
	}
	claimsBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signature := base64.RawURLEncoding.EncodeToString([]byte("mock-signature"))
	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

// Context helpers
func WithOAuthToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, oauthTokenKey, token)
}

func OAuthTokenFromContext(ctx context.Context) string {
	val, ok := ctx.Value(oauthTokenKey).(string)
	if !ok {
		return ""
	}
	return val
}

func WithOAuthUser(ctx context.Context, user *backend.User) context.Context {
	return context.WithValue(ctx, oauthUserKey, user)
}

func OAuthUserFromContext(ctx context.Context) *backend.User {
	val, ok := ctx.Value(oauthUserKey).(*backend.User)
	if !ok {
		return nil
	}
	return val
}

// TokenHash returns a SHA-256 hex string (truncated to 16 characters) for cache keys
func TokenHash(token string) string {
	if token == "" {
		return ""
	}
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])[:16]
}

var invalidSessionNameChars = regexp.MustCompile(`[^\w+=,.@-]+`)

// SanitizeRoleSessionName ensures the session name conforms to AWS STS requirements:
// [\w+=,.@-]{2,64}
func SanitizeRoleSessionName(name string) string {
	cleaned := invalidSessionNameChars.ReplaceAllString(name, "-")
	cleaned = strings.Trim(cleaned, "-")

	if len(cleaned) < 2 {
		return DefaultSessionName
	}

	if len(cleaned) > 64 {
		return cleaned[:64]
	}

	return cleaned
}

// GenerateSessionName generates an appropriate AWS STS RoleSessionName
// based on user info or a configured template/prefix.
// Supported placeholders: ${USER}, ${USERNAME}, ${EMAIL}.
// If customName does not contain any placeholder and user info is present,
// customName is treated as a prefix: "<customName>-<username>".
func GenerateSessionName(customName string, user *backend.User) string {
	custom := strings.TrimSpace(customName)

	var userName string
	var userEmail string
	if user != nil {
		userName = strings.TrimSpace(user.Login)
		userEmail = strings.TrimSpace(user.Email)
	}

	// Determine best identifier for user
	userIdent := userName
	if userIdent == "" {
		userIdent = userEmail
	}

	if custom != "" {
		hasUserPlaceholder := strings.Contains(custom, "${USER}") || strings.Contains(custom, "${USERNAME}")
		hasEmailPlaceholder := strings.Contains(custom, "${EMAIL}")

		if hasUserPlaceholder || hasEmailPlaceholder {
			resolved := custom
			if userIdent != "" {
				resolved = strings.ReplaceAll(resolved, "${USER}", userIdent)
				resolved = strings.ReplaceAll(resolved, "${USERNAME}", userIdent)
			} else {
				resolved = strings.ReplaceAll(resolved, "${USER}", "user")
				resolved = strings.ReplaceAll(resolved, "${USERNAME}", "user")
			}

			if userEmail != "" {
				resolved = strings.ReplaceAll(resolved, "${EMAIL}", userEmail)
			} else if userIdent != "" {
				resolved = strings.ReplaceAll(resolved, "${EMAIL}", userIdent)
			} else {
				resolved = strings.ReplaceAll(resolved, "${EMAIL}", "user")
			}
			return SanitizeRoleSessionName(resolved)
		}

		// If no placeholder, treat customName as prefix when user identity is available
		if userIdent != "" {
			return SanitizeRoleSessionName(fmt.Sprintf("%s-%s", custom, userIdent))
		}
		return SanitizeRoleSessionName(custom)
	}

	if userIdent != "" {
		return SanitizeRoleSessionName(fmt.Sprintf("grafana-%s", userIdent))
	}

	return DefaultSessionName
}

type CachedCredentials struct {
	Credentials *types.Credentials
	ExpiresAt   time.Time
}

// CredentialsCache provides thread-safe in-memory caching of STS credentials
type CredentialsCache struct {
	cache sync.Map
}

var defaultCredentialsCache = &CredentialsCache{}

func GetDefaultCredentialsCache() *CredentialsCache {
	return defaultCredentialsCache
}

func (c *CredentialsCache) Get(key string) (*types.Credentials, bool) {
	val, ok := c.cache.Load(key)
	if !ok {
		return nil, false
	}

	cached, ok := val.(*CachedCredentials)
	if !ok || cached == nil {
		return nil, false
	}

	// Buffer 2 minutes before expiry to ensure valid execution
	if time.Now().Add(2 * time.Minute).After(cached.ExpiresAt) {
		c.cache.Delete(key)
		return nil, false
	}

	return cached.Credentials, true
}

func (c *CredentialsCache) Set(key string, creds *types.Credentials) {
	if creds == nil || creds.Expiration == nil {
		return
	}
	c.cache.Store(key, &CachedCredentials{
		Credentials: creds,
		ExpiresAt:   *creds.Expiration,
	})
}
