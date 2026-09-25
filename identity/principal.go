// Package identity is the framework- and storage-agnostic core of authkit: it
// resolves who a caller is (a Principal) from a credential, and mints/exchanges
// the credentials machines use. It depends only on the standard library and the
// ports defined here — frameworks (Fiber, net/http) and stores (Postgres) plug in
// as adapters from the outside (hexagonal architecture).
//
// Reshaped from goatlab/walliverse's internal/auth so it can back any Go service.
package identity

import "time"

// Kind distinguishes the three identity paths.
type Kind int

const (
	KindAnonymous Kind = iota
	KindAdmin          // a shared bootstrap/operator token — full access
	KindUser           // a human (session / passkey) acting in an organization
	KindMachine        // a runner/agent presenting a short-lived JWT
)

func (k Kind) String() string {
	switch k {
	case KindAdmin:
		return "admin"
	case KindUser:
		return "user"
	case KindMachine:
		return "machine"
	default:
		return "anonymous"
	}
}

// Membership is a user's role within one organization.
type Membership struct {
	OrgID string `json:"orgId"`
	Role  string `json:"role"`
}

// Principal is the authenticated caller. Both the user path and the machine path
// resolve to this single shape so authorization code is uniform.
type Principal struct {
	Kind        Kind         `json:"kind"`
	Subject     string       `json:"subject"`            // user id or runner id
	OrgID       string       `json:"orgId,omitempty"`    // the organization being acted in
	Memberships []Membership `json:"memberships,omitempty"`
	Roles       []string     `json:"roles,omitempty"`
	Scopes      []string     `json:"scopes,omitempty"`
	StepUp      bool         `json:"stepUp,omitempty"` // carries a step-up (MFA/passkey) claim
}

func (p Principal) IsAdmin() bool       { return p.Kind == KindAdmin }
func (p Principal) Authenticated() bool { return p.Kind != KindAnonymous }

// HasScope reports whether the principal was granted scope s.
func (p Principal) HasScope(s string) bool {
	for _, x := range p.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

// MemberOf reports whether the principal belongs to org.
func (p Principal) MemberOf(org string) bool {
	if p.OrgID == org {
		return true
	}
	for _, m := range p.Memberships {
		if m.OrgID == org {
			return true
		}
	}
	return false
}

// Claims is the token payload a Signer mints/verifies (machine path; the user
// path can reuse it). Times are concrete so adapters don't depend on a JWT lib.
type Claims struct {
	Subject   string
	OrgID     string
	Roles     []string
	Scopes    []string
	ExpiresAt time.Time
}
