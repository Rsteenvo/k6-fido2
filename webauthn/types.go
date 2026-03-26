package webauthn

// RegistrationOptions contains the options for credential creation
type RegistrationOptions struct {
	Challenge string `json:"challenge"`
	RpID      string `json:"rpId"`
	RpName    string `json:"rpName"`
	UserID    string `json:"userId"`
	UserName  string `json:"userName"`
	Origin    string `json:"origin"`
}

// AuthenticationOptions contains the options for credential assertion
type AuthenticationOptions struct {
	Challenge    string                 `json:"challenge"`
	RpID         string                 `json:"rpId"`
	CredentialID string                 `json:"credentialId"`
	Origin       string                 `json:"origin"`
	UserHandle   string                 `json:"userHandle,omitempty"`
	Extensions   map[string]interface{} `json:"extensions,omitempty"`
}

// PublicKeyCredential represents the credential returned by registration or authentication
type PublicKeyCredential struct {
	ID       string      `json:"id"`
	RawID    string      `json:"rawId"`
	Type     string      `json:"type"`
	Response interface{} `json:"response"`
}

// AttestationResponse is the response for registration
type AttestationResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`
}

// AssertionResponse is the response for authentication
type AssertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// ClientData represents the client data JSON structure
type ClientData struct {
	Type        string                 `json:"type"`
	Challenge   string                 `json:"challenge"`
	Origin      string                 `json:"origin"`
	CrossOrigin bool                   `json:"crossOrigin"`
	Rar         map[string]interface{} `json:"rar,omitempty"`
}

// AttestationObject represents the CBOR-encoded attestation object
type AttestationObject struct {
	Fmt      string                 `json:"fmt"`
	AttStmt  map[string]interface{} `json:"attStmt"`
	AuthData []byte                 `json:"authData"`
}
