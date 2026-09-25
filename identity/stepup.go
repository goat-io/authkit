package identity

import (
	"context"
	"errors"
	"sort"
	"time"
)

// stepup.go — "elevate this session before a sensitive action". A signed-in user
// proves a SECOND factor at the moment of a sensitive operation and receives a
// short-TTL ELEVATED session (a bearer whose Principal.StepUp is true) that the
// gated route accepts. A normal session is never StepUp (session.go Issue), so the
// gate is real.
//
// PLUGGABLE BY DESIGN: each factor is a StepUpMethod registered with the service;
// the service, the gate and the handler are method-agnostic. Ship `totp` and
// `biometric`; adding email-OTP / a device passkey later is just registering
// another StepUpMethod — no change here or at the gate.

var (
	// ErrStepUpRejected → the proof did not verify (wrong code, failed assertion).
	ErrStepUpRejected = errors.New("step-up verification rejected")
	// ErrStepUpMethodUnknown → the requested method id is not registered.
	ErrStepUpMethodUnknown = errors.New("unknown step-up method")
	// ErrStepUpNotSetUp → the method is valid but this subject has not set it up.
	ErrStepUpNotSetUp = errors.New("step-up method not set up")
)

// StepUpProof is the method-specific evidence a user submits to elevate. Code
// carries a knowledge factor (a TOTP / email-OTP code); methods needing richer
// proof (a passkey assertion) read fields added here in future. The biometric
// method uses no Code — its proof is the on-device OS gate.
type StepUpProof struct {
	Code string
}

// StepUpMethod is one pluggable second-factor verifier. Method() is its stable id
// ("totp" | "biometric" | …); Available reports whether the subject can use it now
// (drives the methods list the client offers); Verify checks the proof.
type StepUpMethod interface {
	Method() string
	Available(ctx context.Context, subject string) (bool, error)
	// Verify returns nil on success, ErrStepUpRejected on a bad proof, or
	// ErrStepUpNotSetUp if the subject has not enrolled the method.
	Verify(ctx context.Context, subject string, proof StepUpProof) error
}

// stepUpIssuer mints a short-TTL elevated session for an authenticated subject.
// SessionService satisfies it (IssueStepUp).
type stepUpIssuer interface {
	IssueStepUp(ctx context.Context, userID string, ttl time.Duration) (string, error)
}

// StepUpService dispatches a proof to the registered method and, on success, mints
// a short-TTL elevated session (Principal.StepUp == true) via the SessionService.
type StepUpService struct {
	methods  map[string]StepUpMethod
	sessions stepUpIssuer
	ttl      time.Duration
}

// NewStepUpService wires the service over the session service (for the elevated
// token), an elevation TTL (≤ 0 ⇒ SessionService's IssueStepUp default), and the
// registered methods.
func NewStepUpService(sessions *SessionService, ttl time.Duration, methods ...StepUpMethod) *StepUpService {
	m := make(map[string]StepUpMethod, len(methods))
	for _, x := range methods {
		m[x.Method()] = x
	}
	return &StepUpService{methods: m, sessions: sessions, ttl: ttl}
}

// Methods returns the ids of the factors AVAILABLE to subject (set up + usable),
// sorted for stable output — so the client offers only what the user can complete.
func (s *StepUpService) Methods(ctx context.Context, subject string) ([]string, error) {
	out := make([]string, 0, len(s.methods))
	for id, m := range s.methods {
		ok, err := m.Available(ctx, subject)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Elevate verifies proof for method and, on success, mints + returns a step-up
// session token for subject (plus its ttl). Unknown method → ErrStepUpMethodUnknown;
// bad proof → ErrStepUpRejected; not enrolled → ErrStepUpNotSetUp. No token is
// minted on any failure.
func (s *StepUpService) Elevate(ctx context.Context, subject, method string, proof StepUpProof) (token string, ttl time.Duration, err error) {
	m, ok := s.methods[method]
	if !ok {
		return "", 0, ErrStepUpMethodUnknown
	}
	if err := m.Verify(ctx, subject, proof); err != nil {
		return "", 0, err
	}
	tok, err := s.sessions.IssueStepUp(ctx, subject, s.ttl)
	if err != nil {
		return "", 0, err
	}
	return tok, s.ttl, nil
}

// TOTPMethod is the authenticator-app step-up factor, backed by the MFAService.
// Available iff the subject has ACTIVE MFA; Verify checks the 6-digit code.
type TOTPMethod struct {
	mfa *MFAService
	now func() time.Time
}

// NewTOTPMethod builds the TOTP step-up method over an MFAService. now may be nil
// (defaults to time.Now); pass a fixed clock in tests.
func NewTOTPMethod(mfa *MFAService, now func() time.Time) TOTPMethod {
	if now == nil {
		now = time.Now
	}
	return TOTPMethod{mfa: mfa, now: now}
}

func (TOTPMethod) Method() string { return "totp" }

func (m TOTPMethod) Available(ctx context.Context, subject string) (bool, error) {
	return m.mfa.IsEnrolled(ctx, subject)
}

func (m TOTPMethod) Verify(ctx context.Context, subject string, proof StepUpProof) error {
	err := m.mfa.Verify(ctx, subject, proof.Code, m.now())
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrMFANotEnrolled):
		return ErrStepUpNotSetUp
	default:
		return ErrStepUpRejected
	}
}

var _ StepUpMethod = TOTPMethod{}

// BiometricMethod is the device-asserted-presence factor: the OS biometric gate
// (Face ID / Touch ID) runs ON-DEVICE; a server cannot verify a biometric, so this
// elevates a VALID authenticated session on the strength of that on-device gate +
// possession of the unlocked device. It is the placeholder for a real device-bound
// passkey/WebAuthn method (which would Verify a signed challenge here). Verify
// always succeeds because the caller is already authenticated and the gate happened
// client-side.
type BiometricMethod struct{}

func (BiometricMethod) Method() string { return "biometric" }

// Available: any device can attempt the OS biometric gate, so it is always offered
// (the client still checks the hardware is enrolled before invoking it).
func (BiometricMethod) Available(context.Context, string) (bool, error) { return true, nil }

func (BiometricMethod) Verify(context.Context, string, StepUpProof) error { return nil }

var _ StepUpMethod = BiometricMethod{}
