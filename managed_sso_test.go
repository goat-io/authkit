package authkit

import (
	"regexp"
	"testing"

	"github.com/goat-io/authkit/identity"
)

func TestSSOProviderNameIsStableAndURLSafe(t *testing.T) {
	name := SSOProviderName("org_A-B_C/42")
	if !regexp.MustCompile(`^sso_[a-f0-9]{32}$`).MatchString(name) || name != SSOProviderName("org_A-B_C/42") || name == SSOProviderName("org_other") {
		t.Fatalf("invalid SSO provider name: %q", name)
	}
}

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
