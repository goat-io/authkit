// Package nethttp adapts authkit to the standard net/http server: a middleware
// that authenticates the request and carries the Principal in the context.
package nethttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/goat-io/authkit/identity"
)

type ctxKey struct{}

// BearerToken pulls the token from the Authorization header or a ?token= query.
func BearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return r.URL.Query().Get("token")
}

// Middleware authenticates every request and stores the Principal in the context.
// It does not reject anonymous callers — leave that to handlers/authorization so
// public routes can opt out.
func Middleware(a *identity.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := a.Authenticate(r.Context(), BearerToken(r))
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
		})
	}
}

// Require rejects anonymous callers with 401.
func Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := PrincipalFrom(r.Context()); !ok || !p.Authenticated() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// PrincipalFrom returns the authenticated Principal stored by Middleware.
func PrincipalFrom(ctx context.Context) (identity.Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(identity.Principal)
	return p, ok
}
