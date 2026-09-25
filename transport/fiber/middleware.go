// Package fiber adapts authkit to gofiber/fiber/v2: a middleware that
// authenticates the request and carries the Principal in c.Locals.
package fiber

import (
	"strings"

	"github.com/goat-io/authkit/identity"
	"github.com/gofiber/fiber/v2"
)

const localsKey = "authkit.principal"

// BearerToken pulls the token from the Authorization header or a ?token= query.
func BearerToken(c *fiber.Ctx) string {
	if h := c.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return c.Query("token")
}

// Middleware authenticates every request and stores the Principal in Locals. It
// does not reject anonymous callers — handlers/authorization decide that, so
// public routes can opt out.
func Middleware(a *identity.Authenticator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Locals(localsKey, a.Authenticate(c.UserContext(), BearerToken(c)))
		return c.Next()
	}
}

// Require rejects anonymous callers with 401.
func Require(c *fiber.Ctx) error {
	if p, ok := PrincipalFrom(c); !ok || !p.Authenticated() {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
	}
	return c.Next()
}

// PrincipalFrom returns the authenticated Principal stored by Middleware.
func PrincipalFrom(c *fiber.Ctx) (identity.Principal, bool) {
	p, ok := c.Locals(localsKey).(identity.Principal)
	return p, ok
}
