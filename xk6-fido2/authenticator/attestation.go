package authenticator

import (
	"encoding/base64"
	"fmt"

	"github.com/backbase-rnd/k6-fido2/webauthn"
)

// RegistrationResult contains the result of a credential registration
type RegistrationResult struct {
	ID       string                       `json:"id"`
	RawID    string                       `json:"rawId"`
	Type     string                       `json:"type"`
	Response webauthn.AttestationResponse `json:"response"`
}

// Register creates a new credential and returns the attestation response
func (a *Authenticator) Register(opts webauthn.RegistrationOptions) (*RegistrationResult, error) {
	// Generate new credential
	keyPair, err := a.CreateCredential()
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	// Build clientDataJSON
	clientDataJSON, err := webauthn.BuildClientDataJSON("webauthn.create", opts.Challenge, opts.Origin)
	if err != nil {
		return nil, fmt.Errorf("failed to build clientDataJSON: %w", err)
	}

	// Get COSE public key
	cosePublicKey, err := keyPair.GetCOSEPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to encode COSE public key: %w", err)
	}

	// Build authenticator data with attested credential
	signCount := keyPair.IncrementSignCount()
	authData := webauthn.BuildAuthenticatorData(opts.RpID, keyPair.CredentialID, cosePublicKey, signCount)

	// Encode attestation object
	attestationObject, err := EncodeAttestationObject(authData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode attestation object: %w", err)
	}

	// Encode credential ID
	credentialIDBase64 := base64.RawURLEncoding.EncodeToString(keyPair.CredentialID)

	return &RegistrationResult{
		ID:    credentialIDBase64,
		RawID: credentialIDBase64,
		Type:  "public-key",
		Response: webauthn.AttestationResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			AttestationObject: base64.RawURLEncoding.EncodeToString(attestationObject),
		},
	}, nil
}
