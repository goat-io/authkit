// Package gowebauthn is authkit's WebAuthn (passkey) adapter over
// github.com/go-webauthn/webauthn. It is framework-agnostic: ceremony responses
// come in as raw bytes (parse them from any HTTP body), and the transient ceremony
// state (the server-anchored challenge) is RETURNED to the caller as an opaque
// blob to store however it likes — a short-lived cookie, a row, anything — so it
// works across stateless pods (walliver pins it in memory; this doesn't have to).
package gowebauthn

import (
	"context"
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/goat-io/authkit/identity"
)

// Config is the relying-party configuration.
type Config struct {
	RPID          string   // e.g. "delphi.app"
	RPDisplayName string   // e.g. "Delphi"
	RPOrigins     []string // e.g. ["https://delphi.app"]
}

// Provider runs passkey registration + login ceremonies.
type Provider struct {
	wa    *webauthn.WebAuthn
	store identity.WebAuthnCredentialStore
}

func New(cfg Config, store identity.WebAuthnCredentialStore) (*Provider, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, err
	}
	return &Provider{wa: wa, store: store}, nil
}

// waUser adapts an authkit User + its stored passkeys to webauthn.User.
type waUser struct {
	u     identity.User
	creds []webauthn.Credential
}

func (w waUser) WebAuthnID() []byte                         { return []byte(w.u.ID) }
func (w waUser) WebAuthnName() string                       { return w.u.Email }
func (w waUser) WebAuthnDisplayName() string                { return displayName(w.u) }
func (w waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func displayName(u identity.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

func (p *Provider) user(ctx context.Context, u identity.User) (waUser, error) {
	stored, err := p.store.ListByUser(ctx, u.ID)
	if err != nil {
		return waUser{}, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		creds = append(creds, toWebAuthnCredential(c))
	}
	return waUser{u: u, creds: creds}, nil
}

// BeginRegistration starts a passkey-enrollment ceremony. It returns the creation
// options (JSON for the browser's navigator.credentials.create) and an opaque
// session blob the caller must hold and pass back to FinishRegistration.
func (p *Provider) BeginRegistration(ctx context.Context, u identity.User) (options []byte, session []byte, err error) {
	wu, err := p.user(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	creation, sess, err := p.wa.BeginRegistration(wu)
	if err != nil {
		return nil, nil, err
	}
	if options, err = json.Marshal(creation); err != nil {
		return nil, nil, err
	}
	if session, err = json.Marshal(sess); err != nil {
		return nil, nil, err
	}
	return options, session, nil
}

// FinishRegistration validates the authenticator's attestation (response = the raw
// navigator.credentials.create() result) and persists the new passkey.
func (p *Provider) FinishRegistration(ctx context.Context, u identity.User, session, response []byte) error {
	wu, err := p.user(ctx, u)
	if err != nil {
		return err
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal(session, &sess); err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return err
	}
	cred, err := p.wa.CreateCredential(wu, sess, parsed)
	if err != nil {
		return err
	}
	return p.store.Add(ctx, fromWebAuthnCredential(cred, u.ID))
}

// BeginLogin starts an authentication ceremony for a known user.
func (p *Provider) BeginLogin(ctx context.Context, u identity.User) (options []byte, session []byte, err error) {
	wu, err := p.user(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	assertion, sess, err := p.wa.BeginLogin(wu)
	if err != nil {
		return nil, nil, err
	}
	if options, err = json.Marshal(assertion); err != nil {
		return nil, nil, err
	}
	if session, err = json.Marshal(sess); err != nil {
		return nil, nil, err
	}
	return options, session, nil
}

// FinishLogin validates the assertion (response = the raw
// navigator.credentials.get() result), updates the passkey's sign counter (clone
// detection), and returns the authenticated user id on success. The caller then
// issues a session (identity.SessionService.Issue).
func (p *Provider) FinishLogin(ctx context.Context, u identity.User, session, response []byte) (string, error) {
	wu, err := p.user(ctx, u)
	if err != nil {
		return "", err
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal(session, &sess); err != nil {
		return "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return "", err
	}
	cred, err := p.wa.ValidateLogin(wu, sess, parsed)
	if err != nil {
		return "", err
	}
	_ = p.store.UpdateSignCount(ctx, cred.ID, cred.Authenticator.SignCount)
	return u.ID, nil
}

func toWebAuthnCredential(c identity.WebAuthnCredential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	wc := webauthn.Credential{
		ID:              c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
	}
	wc.Flags.BackupEligible = c.BackupEligible
	wc.Flags.BackupState = c.BackupState
	wc.Authenticator.AAGUID = c.AAGUID
	wc.Authenticator.SignCount = c.SignCount
	return wc
}

func fromWebAuthnCredential(c *webauthn.Credential, userID string) identity.WebAuthnCredential {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return identity.WebAuthnCredential{
		ID:              c.ID,
		UserID:          userID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		AAGUID:          c.Authenticator.AAGUID,
		SignCount:       c.Authenticator.SignCount,
		Transports:      transports,
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
	}
}
