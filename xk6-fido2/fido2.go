package fido2

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/rsteenvo/k6-fido2/authenticator"
	"github.com/rsteenvo/k6-fido2/webauthn"

	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/fido2", new(RootModule))
}

// RootModule is the global module instance that will create Fido2 instances for each VU
type RootModule struct{}

// NewModuleInstance creates a new instance for each VU
func (*RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	return &Fido2{
		vu:            vu,
		authenticator: authenticator.NewAuthenticator(),
	}
}

// Fido2 is the type for the K6 extension instance
type Fido2 struct {
	vu            modules.VU
	authenticator *authenticator.Authenticator
}

// Exports returns the exports of the module
func (f *Fido2) Exports() modules.Exports {
	return modules.Exports{
		Default: f,
	}
}

// Register creates a new WebAuthn credential and returns the attestation response
func (f *Fido2) Register(opts map[string]interface{}) (map[string]interface{}, error) {
	regOpts := webauthn.RegistrationOptions{
		Challenge: getStringOption(opts, "challenge", ""),
		RpID:      getStringOption(opts, "rpId", ""),
		RpName:    getStringOption(opts, "rpName", ""),
		UserID:    getStringOption(opts, "userId", ""),
		UserName:  getStringOption(opts, "userName", ""),
		Origin:    getStringOption(opts, "origin", ""),
	}

	result, err := f.authenticator.Register(regOpts)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"id":    result.ID,
		"rawId": result.RawID,
		"type":  result.Type,
		"response": map[string]interface{}{
			"clientDataJSON":    result.Response.ClientDataJSON,
			"attestationObject": result.Response.AttestationObject,
		},
	}, nil
}

// Authenticate signs a challenge with an existing credential
func (f *Fido2) Authenticate(opts map[string]interface{}) (map[string]interface{}, error) {
	authOpts := webauthn.AuthenticationOptions{
		Challenge:    getStringOption(opts, "challenge", ""),
		RpID:         getStringOption(opts, "rpId", ""),
		CredentialID: getStringOption(opts, "credentialId", ""),
		Origin:       getStringOption(opts, "origin", ""),
		UserHandle:   getStringOption(opts, "userHandle", ""),
	}

	result, err := f.authenticator.Authenticate(authOpts)
	if err != nil {
		return nil, err
	}

	response := map[string]interface{}{
		"clientDataJSON":    result.Response.ClientDataJSON,
		"authenticatorData": result.Response.AuthenticatorData,
		"signature":         result.Response.Signature,
	}

	if result.Response.UserHandle != "" {
		response["userHandle"] = result.Response.UserHandle
	}

	return map[string]interface{}{
		"id":       result.ID,
		"rawId":    result.RawID,
		"type":     result.Type,
		"response": response,
	}, nil
}

// GenerateDeviceKey creates a new EC key pair for device registration
// Returns: { alias: string, publicKey: string (base64 X9.62 uncompressed format) }
func (f *Fido2) GenerateDeviceKey() (map[string]interface{}, error) {
	keyPair, err := f.authenticator.CreateCredential()
	if err != nil {
		return nil, err
	}

	alias := base64.RawURLEncoding.EncodeToString(keyPair.CredentialID)

	// Get public key in X9.62 uncompressed format (04 || X || Y)
	pubKeyBytes := keyPair.GetX962PublicKey()

	return map[string]interface{}{
		"alias":     alias,
		"publicKey": base64.StdEncoding.EncodeToString(pubKeyBytes),
	}, nil
}

// SignWithDeviceKey signs data with a stored device key
// Options: { alias: string, data: string }
// Returns: { signature: string (base64 raw r||s format) }
func (f *Fido2) SignWithDeviceKey(opts map[string]interface{}) (map[string]interface{}, error) {
	alias := getStringOption(opts, "alias", "")
	data := getStringOption(opts, "data", "")

	// Hash the data with SHA-256 before signing (standard practice for ECDSA)
	hash := sha256.Sum256([]byte(data))

	// Use raw signature format (r || s) instead of DER
	signature, err := f.authenticator.SignDataRaw(alias, hash[:])
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"signature": base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// ExportCredential exports a credential for storage/persistence
// Options: { credentialId: string }
// Returns: { credentialId: string, privateKeyD: string, signCount: number }
func (f *Fido2) ExportCredential(credentialID string) (map[string]interface{}, error) {
	exported, err := f.authenticator.ExportCredential(credentialID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"credentialId": exported.CredentialID,
		"privateKeyD":  exported.PrivateKeyD,
		"signCount":    exported.SignCount,
	}, nil
}

// ImportCredential imports a previously exported credential
// Options: { credentialId: string, privateKeyD: string, signCount: number }
func (f *Fido2) ImportCredential(opts map[string]interface{}) error {
	exported := &authenticator.ExportedCredential{
		CredentialID: getStringOption(opts, "credentialId", ""),
		PrivateKeyD:  getStringOption(opts, "privateKeyD", ""),
		SignCount:    uint32(getIntOption(opts, "signCount", 0)),
	}

	return f.authenticator.ImportCredential(exported)
}

// ExportAllCredentials exports all stored credentials
// Returns: array of { credentialId: string, privateKeyD: string, signCount: number }
func (f *Fido2) ExportAllCredentials() []map[string]interface{} {
	credentials := f.authenticator.ExportAllCredentials()
	result := make([]map[string]interface{}, len(credentials))

	for i, cred := range credentials {
		result[i] = map[string]interface{}{
			"credentialId": cred.CredentialID,
			"privateKeyD":  cred.PrivateKeyD,
			"signCount":    cred.SignCount,
		}
	}

	return result
}

// getStringOption safely extracts a string option from a map
func getStringOption(opts map[string]interface{}, key, defaultValue string) string {
	if val, ok := opts[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return defaultValue
}

// getIntOption safely extracts an int option from a map
func getIntOption(opts map[string]interface{}, key string, defaultValue int) int {
	if val, ok := opts[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return defaultValue
}
