// =========================================================================
// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
// Unit tests for downstream OAuth authentication utilities, token extraction,
// session name generation, credentials cache, and pre-flight JWT validation.
// =========================================================================

package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractToken(t *testing.T) {
	t.Run("returns empty string when headers are nil or empty", func(t *testing.T) {
		assert.Equal(t, "", ExtractToken(nil))
		assert.Equal(t, "", ExtractToken(http.Header{}))
	})

	t.Run("extracts X-Id-Token with highest priority", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("X-Id-Token", "id-token-123")
		headers.Set("Authorization", "Bearer access-token-456")

		token := ExtractToken(headers)
		assert.Equal(t, "id-token-123", token)
	})

	t.Run("falls back to Authorization Bearer token when X-Id-Token is absent", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer access-token-456")

		token := ExtractToken(headers)
		assert.Equal(t, "access-token-456", token)
	})

	t.Run("handles Authorization with lowercase bearer prefix", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "bearer my-test-token")

		token := ExtractToken(headers)
		assert.Equal(t, "my-test-token", token)
	})

	t.Run("handles raw Authorization token without bearer prefix", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "raw-test-token")

		token := ExtractToken(headers)
		assert.Equal(t, "raw-test-token", token)
	})
}

func TestExtractTokenFromMap(t *testing.T) {
	t.Run("extracts X-Id-Token case-insensitively", func(t *testing.T) {
		m := map[string]string{
			"x-id-token":    "id-token-from-map",
			"authorization": "Bearer other-token",
		}
		assert.Equal(t, "id-token-from-map", ExtractTokenFromMap(m))
	})

	t.Run("falls back to Authorization in map", func(t *testing.T) {
		m := map[string]string{
			"Authorization": "Bearer auth-token-from-map",
		}
		assert.Equal(t, "auth-token-from-map", ExtractTokenFromMap(m))
	})
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()

	assert.Equal(t, "", OAuthTokenFromContext(ctx))
	assert.Nil(t, OAuthUserFromContext(ctx))

	ctx = WithOAuthToken(ctx, "sample-token")
	assert.Equal(t, "sample-token", OAuthTokenFromContext(ctx))

	user := &backend.User{Login: "user-1", Email: "test@example.com"}
	ctx = WithOAuthUser(ctx, user)
	assert.Equal(t, user, OAuthUserFromContext(ctx))
}

func TestTokenHash(t *testing.T) {
	assert.Equal(t, "", TokenHash(""))
	h1 := TokenHash("token-1")
	h2 := TokenHash("token-2")
	h1Again := TokenHash("token-1")

	assert.Len(t, h1, 16)
	assert.Equal(t, h1, h1Again)
	assert.NotEqual(t, h1, h2)
}

func TestGenerateSessionName(t *testing.T) {
	t.Run("uses custom name when provided without user", func(t *testing.T) {
		assert.Equal(t, "custom-session", GenerateSessionName("custom-session", nil))
	})

	t.Run("sanitizes custom name with illegal chars", func(t *testing.T) {
		assert.Equal(t, "custom-session-1", GenerateSessionName("custom session #1", nil))
	})

	t.Run("treats custom name as prefix when user is present without template", func(t *testing.T) {
		user := &backend.User{Login: "alice"}
		assert.Equal(t, "my-prefix-alice", GenerateSessionName("my-prefix", user))
	})

	t.Run("resolves ${USER} template", func(t *testing.T) {
		user := &backend.User{Login: "bob", Email: "bob@example.com"}
		assert.Equal(t, "corp-bob-session", GenerateSessionName("corp-${USER}-session", user))
	})

	t.Run("resolves ${EMAIL} template", func(t *testing.T) {
		user := &backend.User{Login: "bob", Email: "bob@example.com"}
		assert.Equal(t, "audit-bob@example.com", GenerateSessionName("audit-${EMAIL}", user))
	})

	t.Run("uses user login when custom name is empty", func(t *testing.T) {
		user := &backend.User{Login: "john.doe", Email: "john.doe@example.com"}
		assert.Equal(t, "grafana-john.doe", GenerateSessionName("", user))
	})

	t.Run("uses user email when login is empty", func(t *testing.T) {
		user := &backend.User{Email: "alice@example.com"}
		assert.Equal(t, "grafana-alice@example.com", GenerateSessionName("", user))
	})

	t.Run("falls back to default when both custom name and user are missing", func(t *testing.T) {
		assert.Equal(t, DefaultSessionName, GenerateSessionName("", nil))
	})
}

func TestCredentialsCache(t *testing.T) {
	cache := &CredentialsCache{}
	now := time.Now()

	// Not found
	creds, found := cache.Get("key1")
	assert.False(t, found)
	assert.Nil(t, creds)

	// Valid credentials
	validExp := now.Add(30 * time.Minute)
	testCreds := &types.Credentials{
		AccessKeyId:     aws.String("test-access-key"),
		SecretAccessKey: aws.String("test-secret-key"),
		SessionToken:    aws.String("test-session-token"),
		Expiration:      &validExp,
	}
	cache.Set("key1", testCreds)

	creds, found = cache.Get("key1")
	require.True(t, found)
	assert.Equal(t, "test-access-key", *creds.AccessKeyId)

	// Expired credentials (or within 2 min buffer)
	almostExpired := now.Add(1 * time.Minute)
	expiredCreds := &types.Credentials{
		AccessKeyId:     aws.String("expired-access-key"),
		SecretAccessKey: aws.String("expired-secret-key"),
		SessionToken:    aws.String("expired-session-token"),
		Expiration:      &almostExpired,
	}
	cache.Set("key2", expiredCreds)

	creds, found = cache.Get("key2")
	assert.False(t, found)
	assert.Nil(t, creds)
}

func TestValidateToken(t *testing.T) {
	t.Run("returns error when token is empty", func(t *testing.T) {
		err := ValidateToken("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is empty")

		err = ValidateToken("   ")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is empty")
	})

	t.Run("detects and rejects Grafana service account token", func(t *testing.T) {
		err := ValidateToken("glsa_1234567890abcdef")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Grafana service account token")
	})

	t.Run("returns error when token does not have 3 parts", func(t *testing.T) {
		err := ValidateToken("opaque-access-token-12345")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected 3 dot-separated base64url segments")

		err = ValidateToken("header.payload")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected 3 dot-separated base64url segments")
	})

	t.Run("returns error when payload is not valid base64url", func(t *testing.T) {
		err := ValidateToken("header.invalid!base64.signature")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode JWT payload")
	})

	t.Run("returns error when payload is not valid JSON", func(t *testing.T) {
		notJSON := base64.RawURLEncoding.EncodeToString([]byte("plain text not json"))
		err := ValidateToken(fmt.Sprintf("header.%s.signature", notJSON))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse JWT payload JSON")
	})

	t.Run("returns error when token has expired beyond clock skew", func(t *testing.T) {
		token := CreateTestJWT("user1", time.Now().Add(-5*time.Minute))
		err := ValidateToken(token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token expired at")
	})

	t.Run("returns error when token is not valid yet (nbf)", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
		futureTime := time.Now().Add(10 * time.Minute).Unix()
		claims := TokenClaims{
			Subject:   "user1",
			NotBefore: &futureTime,
		}
		claimsBytes, _ := json.Marshal(claims)
		payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
		token := fmt.Sprintf("%s.%s.sig", header, payload)

		err := ValidateToken(token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is not valid before")
	})

	t.Run("accepts valid unexpired token", func(t *testing.T) {
		token := CreateTestJWT("user1", time.Now().Add(30*time.Minute))
		claims, err := ParseAndValidateToken(token)
		require.NoError(t, err)
		assert.Equal(t, "user1", claims.Subject)
		assert.Equal(t, "https://auth.example.com", claims.Issuer)
	})

	t.Run("tolerates small clock skew within 1 minute", func(t *testing.T) {
		// Expired 30 seconds ago (within 1m leeway)
		token := CreateTestJWT("user1", time.Now().Add(-30*time.Second))
		err := ValidateToken(token)
		assert.NoError(t, err)
	})
}
