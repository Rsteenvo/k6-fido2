package fido2

import (
	"github.com/backbase-rnd/k6-fido2/authenticator"
	"github.com/backbase-rnd/k6-fido2/webauthn"

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

// getStringOption safely extracts a string option from a map
func getStringOption(opts map[string]interface{}, key, defaultValue string) string {
	if val, ok := opts[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return defaultValue
}
