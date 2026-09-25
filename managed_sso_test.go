package authkit

import (
	"testing"

	"github.com/goat-io/authkit/identity"
)

func TestManagedSSORequiresVerifiedEmailInDomain(t *testing.T) {
	for _, tc := range []struct {
		email          string
		verified, want bool
	}{
		{"person@example.com", true, true},
		{"person@EXAMPLE.COM", true, true},
		{"person@example.com", false, false},
		{"person@other.example", true, false},
		{"@example.com", true, false},
	} {
		if got := validSSOEmail(identity.SocialIdentity{Email: tc.email, EmailVerified: tc.verified}, "example.com"); got != tc.want {
			t.Fatalf("%q verified=%t: got %t", tc.email, tc.verified, got)
		}
	}
}
