// =========================================================================
// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
// This file is downstream-specific for wrapping the backend datasource
// instance and connection arguments with OAuth identity awareness.
// Moving these implementations out of pkg/main.go and pkg/athena/datasource.go
// ensures those upstream files remain minimal, avoiding merge conflicts
// when syncing from upstream (grafana/athena-datasource).
// =========================================================================

package oauth

import (
	"context"
	"encoding/json"

	"github.com/grafana/grafana-aws-sdk/pkg/awsds"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/instancemgmt"
	"github.com/grafana/sqlds/v5"
)

// OAuthAthenaDatasource wraps AsyncAWSDatasource to extract per-request OAuth identity
// tokens from incoming query requests and inject the OAuth hash for cache isolation.
type OAuthAthenaDatasource struct {
	*awsds.AsyncAWSDatasource
	settings backend.DataSourceInstanceSettings
}

// WrapDatasource wraps an instancemgmt.Instance in an OAuthAthenaDatasource proxy.
func WrapDatasource(inst instancemgmt.Instance, err error) (instancemgmt.Instance, error) {
	if err != nil {
		return nil, err
	}
	asyncDS, ok := inst.(*awsds.AsyncAWSDatasource)
	if !ok {
		return inst, nil
	}
	return &OAuthAthenaDatasource{
		AsyncAWSDatasource: asyncDS,
	}, nil
}

func (d *OAuthAthenaDatasource) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	if req == nil {
		return d.AsyncAWSDatasource.QueryData(ctx, req)
	}

	token := ExtractToken(req.GetHTTPHeaders())
	if token == "" {
		if idToken := req.GetHTTPHeader(backend.OAuthIdentityIDTokenHeaderName); idToken != "" {
			token = idToken
		} else if auth := req.GetHTTPHeader(backend.OAuthIdentityTokenHeaderName); auth != "" {
			token = ExtractTokenFromMap(map[string]string{backend.OAuthIdentityTokenHeaderName: auth})
		}
	}

	if token != "" {
		ctx = WithOAuthToken(ctx, token)
		if req.PluginContext.User != nil {
			ctx = WithOAuthUser(ctx, req.PluginContext.User)
		}
		hash := TokenHash(token)
		for i := range req.Queries {
			req.Queries[i].JSON = InjectOAuthHashIntoQueryJSON(req.Queries[i].JSON, hash)
		}
	}

	return d.AsyncAWSDatasource.QueryData(ctx, req)
}

func (d *OAuthAthenaDatasource) CheckHealth(ctx context.Context, req *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	if req == nil {
		return d.AsyncAWSDatasource.CheckHealth(ctx, req)
	}

	token := ExtractToken(req.GetHTTPHeaders())
	if token == "" {
		if idToken := req.GetHTTPHeader(backend.OAuthIdentityIDTokenHeaderName); idToken != "" {
			token = idToken
		} else if auth := req.GetHTTPHeader(backend.OAuthIdentityTokenHeaderName); auth != "" {
			token = ExtractTokenFromMap(map[string]string{backend.OAuthIdentityTokenHeaderName: auth})
		}
	}

	if token != "" {
		ctx = WithOAuthToken(ctx, token)
		if req.PluginContext.User != nil {
			ctx = WithOAuthUser(ctx, req.PluginContext.User)
		}
	}

	return d.AsyncAWSDatasource.CheckHealth(ctx, req)
}

func (d *OAuthAthenaDatasource) CallResource(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	if req == nil {
		return d.AsyncAWSDatasource.CallResource(ctx, req, sender)
	}

	token := ExtractToken(req.GetHTTPHeaders())
	if token == "" {
		if idToken := req.GetHTTPHeader(backend.OAuthIdentityIDTokenHeaderName); idToken != "" {
			token = idToken
		} else if auth := req.GetHTTPHeader(backend.OAuthIdentityTokenHeaderName); auth != "" {
			token = ExtractTokenFromMap(map[string]string{backend.OAuthIdentityTokenHeaderName: auth})
		}
	}

	if token != "" {
		ctx = WithOAuthToken(ctx, token)
		if req.PluginContext.User != nil {
			ctx = WithOAuthUser(ctx, req.PluginContext.User)
		}
	}

	return d.AsyncAWSDatasource.CallResource(ctx, req, sender)
}

// InjectOAuthHashIntoQueryJSON injects the OAuth token hash into connectionArgs of a raw query JSON message.
func InjectOAuthHashIntoQueryJSON(raw json.RawMessage, hash string) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	connArgs, ok := m["connectionArgs"].(map[string]any)
	if !ok || connArgs == nil {
		connArgs = make(map[string]any)
	}
	connArgs["__oauth_hash"] = hash
	m["connectionArgs"] = connArgs
	updated, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return updated
}

// InjectOAuthHashToArgs injects __oauth_hash into sqlds.Options if a token exists in context
// and __oauth_hash is not already set.
func InjectOAuthHashToArgs(ctx context.Context, args sqlds.Options) {
	if args["__oauth_hash"] == "" {
		if token := OAuthTokenFromContext(ctx); token != "" {
			args["__oauth_hash"] = TokenHash(token)
		}
	}
}
