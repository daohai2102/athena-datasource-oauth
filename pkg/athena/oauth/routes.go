// =========================================================================
// [DOWNSTREAM: daohai2102/athena-datasource-oauth]
// This file is downstream-specific for wrapping HTTP resource handlers
// to extract and propagate OAuth identity tokens in request context.
// Isolated here to prevent merge conflicts in pkg/athena/routes/routes.go
// during upstream synchronization.
// =========================================================================

package oauth

import (
	"net/http"
)

// WrapRoute wraps an HTTP handler function to extract the OAuth identity token
// from headers and inject it into the request context.
func WrapRoute(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		token := ExtractToken(req.Header)
		if token != "" {
			ctx := WithOAuthToken(req.Context(), token)
			req = req.WithContext(ctx)
		}
		handler(rw, req)
	}
}

// WrapRoutes applies WrapRoute to each handler in the routes map.
func WrapRoutes(routes map[string]func(http.ResponseWriter, *http.Request)) map[string]func(http.ResponseWriter, *http.Request) {
	wrapped := make(map[string]func(http.ResponseWriter, *http.Request), len(routes))
	for k, handler := range routes {
		wrapped[k] = WrapRoute(handler)
	}
	return wrapped
}
