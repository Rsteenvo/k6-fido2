package authenticator

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/backbase-rnd/k6-fido2/webauthn"
)

// AuthenticationResult contains the result of a credential authentication
type AuthenticationResult struct {
	ID       string                     `json:"id"`
	RawID    string                     `json:"rawId"`
	Type     string                     `json:"type"`
	Response webauthn.AssertionResponse `json:"response"`
}

// Authenticate signs a challenge with an existing credential
func (a *Authenticator) Authenticate(opts webauthn.AuthenticationOptions) (*AuthenticationResult, error) {
	// Get the credential
	keyPair, err := a.GetCredential(opts.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	// Build clientDataJSON
	clientDataJSON, err := webauthn.BuildClientDataJSON("webauthn.get", opts.Challenge, opts.Origin)
	if err != nil {
		return nil, fmt.Errorf("failed to build clientDataJSON: %w", err)
	}

	// Increment sign count
	signCount := keyPair.IncrementSignCount()

	// Build authenticator data (without attested credential for assertion)
	authData := webauthn.BuildAuthenticatorDataForAssertion(opts.RpID, signCount)

	// Create signature over authData || clientDataHash
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData := append(authData, clientDataHash[:]...)

	// Hash the signed data for ECDSA signature
	signedDataHash := sha256.Sum256(signedData)

	// Sign with DER format (commonly expected by WebAuthn servers)
	signature, err := keyPair.SignDER(signedDataHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion: %w", err)
	}

	return &AuthenticationResult{
		ID:    opts.CredentialID,
		RawID: opts.CredentialID,
		Type:  "public-key",
		Response: webauthn.AssertionResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
			Signature:         base64.RawURLEncoding.EncodeToString(signature),
			UserHandle:        opts.UserHandle,
		},
	}, nil
}
