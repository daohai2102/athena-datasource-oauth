// =========================================================================
// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
// This file is downstream-specific for OAuth Passthrough (Web Identity)
// AWS configuration. It encapsulates STS AssumeRoleWithWebIdentity calls
// and credentials management so that pkg/athena/api/api.go retains its
// upstream structure with minimal modifications, avoiding merge conflicts
// when syncing from upstream (grafana/athena-datasource).
// =========================================================================

package oauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/grafana/athena-datasource/pkg/athena/models"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

// STSClient is the interface for AWS STS client operations used by OAuth authentication.
type STSClient interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

// defaultSTSClientFactory creates a new STS client using AnonymousCredentials.
var newSTSClient = func(region string, endpoint string, httpClient *http.Client) STSClient {
	opts := sts.Options{
		Region:      region,
		HTTPClient:  httpClient,
		Credentials: aws.AnonymousCredentials{},
	}
	if endpoint != "" {
		opts.BaseEndpoint = aws.String(endpoint)
	}
	return sts.New(opts)
}

// SetSTSClientFactory sets a custom STS client factory (primarily for unit tests).
func SetSTSClientFactory(f func(region string, endpoint string, httpClient *http.Client) STSClient) {
	newSTSClient = f
}

// ResetSTSClientFactory restores the default STS client factory.
func ResetSTSClientFactory() {
	newSTSClient = func(region string, endpoint string, httpClient *http.Client) STSClient {
		opts := sts.Options{
			Region:      region,
			HTTPClient:  httpClient,
			Credentials: aws.AnonymousCredentials{},
		}
		if endpoint != "" {
			opts.BaseEndpoint = aws.String(endpoint)
		}
		return sts.New(opts)
	}
}

// GetAWSConfig attempts to create an aws.Config using OAuth Web Identity authentication.
// Returns:
//   - cfg: the constructed aws.Config if handled
//   - handled: true if OAuth passthrough handled the request (or produced a terminal error),
//     false if the caller should proceed with upstream standard auth config provider.
//   - err: error if validation or STS AssumeRoleWithWebIdentity failed.
func GetAWSConfig(ctx context.Context, athenaSettings *models.AthenaDataSourceSettings, region string, httpClient *http.Client) (aws.Config, bool, error) {
	if athenaSettings == nil || !athenaSettings.OAuthPassThru {
		return aws.Config{}, false, nil
	}

	oauthToken := OAuthTokenFromContext(ctx)

	// If OAuth is enabled and a token is present, assume role with web identity
	if oauthToken != "" {
		if err := ValidateToken(oauthToken); err != nil {
			return aws.Config{}, true, backend.DownstreamErrorf("invalid OAuth identity token: %w", err)
		}

		roleArn := athenaSettings.OAuthRoleArn
		if roleArn == "" {
			roleArn = athenaSettings.AssumeRoleARN
		}
		if roleArn == "" {
			return aws.Config{}, true, backend.DownstreamErrorf("OAuth pass-through is enabled but no Role ARN is configured")
		}

		sessionName := GenerateSessionName(athenaSettings.OAuthRoleSessionName, OAuthUserFromContext(ctx))
		cacheKey := fmt.Sprintf("%s:%s", roleArn, TokenHash(oauthToken))
		cachedCreds, found := GetDefaultCredentialsCache().Get(cacheKey)

		var creds *ststypes.Credentials
		if found && cachedCreds != nil {
			creds = cachedCreds
		} else {
			stsClient := newSTSClient(region, athenaSettings.Endpoint, httpClient)
			input := &sts.AssumeRoleWithWebIdentityInput{
				RoleArn:          aws.String(roleArn),
				RoleSessionName:  aws.String(sessionName),
				WebIdentityToken: aws.String(oauthToken),
			}
			output, err := stsClient.AssumeRoleWithWebIdentity(ctx, input)
			if err != nil {
				return aws.Config{}, true, backend.DownstreamErrorf("failed to assume role with web identity: %w", err)
			}
			creds = output.Credentials
			GetDefaultCredentialsCache().Set(cacheKey, creds)
		}

		cfg := aws.Config{
			Region:     region,
			HTTPClient: httpClient,
			Credentials: credentials.NewStaticCredentialsProvider(
				aws.ToString(creds.AccessKeyId),
				aws.ToString(creds.SecretAccessKey),
				aws.ToString(creds.SessionToken),
			),
		}
		if athenaSettings.Endpoint != "" {
			cfg.BaseEndpoint = aws.String(athenaSettings.Endpoint)
		}
		return cfg, true, nil
	}

	// If OAuth is enabled, no token was provided, and no base auth credentials exist, fail fast
	if athenaSettings.AccessKey == "" && athenaSettings.Profile == "" && athenaSettings.AssumeRoleARN == "" {
		return aws.Config{}, true, backend.DownstreamErrorf("OAuth pass-through is enabled, but no OAuth identity token was provided in the request")
	}

	// No token provided, but base auth credentials exist: fallback to upstream standard config
	return aws.Config{}, false, nil
}
