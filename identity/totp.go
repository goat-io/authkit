package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// totp.go — RFC 6238 TOTP, the authenticator-app second factor, on the standard
// library alone (HMAC-SHA1, 30s step, 6 digits — the de-facto Google Authenticator/
// 1Password/Authy profile). No third-party OTP dependency. The shared secret lives
// ONLY server-side; the client ever sends just the 6-digit code.

const (
	totpStep   = 30 * time.Second
	totpDigits = 6
	totpSkew   = 1 // accept the previous/next step too (clock drift), nothing wider
)

// base32NoPad is the encoding authenticator apps expect for the secret (RFC 4648
// base32, uppercase, no '=' padding).
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh 160-bit secret as base32 (the SHA-1 block
// size — the RFC-recommended secret length). It is the value embedded in the
// provisioning URI and stored server-side for verification.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32NoPad.EncodeToString(b), nil
}

// TOTPProvisioningURI builds the otpauth:// URI an authenticator app scans
// (rendered as a QR by the client). issuer + account label the entry; the SHA1 /
// 6-digit / 30s parameters are explicit so apps don't guess.
func TOTPProvisioningURI(secret, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", int(totpStep.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// ValidateTOTP reports whether code is a valid TOTP for secret at time now,
// accepting a ±1 step skew. Comparison is constant-time. A malformed secret or a
// non-6-digit code is rejected (never panics).
func ValidateTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	key, err := base32NoPad.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return false
	}
	counter := uint64(now.Unix() / int64(totpStep.Seconds()))
	for d := -totpSkew; d <= totpSkew; d++ {
		want := hotp(key, uint64(int64(counter)+int64(d)))
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// hotp is RFC 4226 HOTP over HMAC-SHA1: dynamic truncation of the MAC to a
// zero-padded `totpDigits`-digit decimal.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	val := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, val%mod)
}
