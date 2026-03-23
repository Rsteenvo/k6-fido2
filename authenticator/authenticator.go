package authenticator

import (
	"encoding/base64"
	"fmt"
	"sync"
)

// Authenticator simulates a WebAuthn platform authenticator
type Authenticator struct {
	credentials map[string]*KeyPair
	mu          sync.RWMutex
}

// NewAuthenticator creates a new authenticator instance
func NewAuthenticator() *Authenticator {
	return &Authenticator{
		credentials: make(map[string]*KeyPair),
	}
}

// CreateCredential generates a new credential and stores it
func (a *Authenticator) CreateCredential() (*KeyPair, error) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	credentialIDBase64 := base64.RawURLEncoding.EncodeToString(keyPair.CredentialID)

	a.mu.Lock()
	a.credentials[credentialIDBase64] = keyPair
	a.mu.Unlock()

	return keyPair, nil
}

// GetCredential retrieves a credential by its ID
func (a *Authenticator) GetCredential(credentialID string) (*KeyPair, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	keyPair, ok := a.credentials[credentialID]
	if !ok {
		return nil, fmt.Errorf("credential not found: %s", credentialID)
	}

	return keyPair, nil
}

// StoreCredential stores a credential with a specific ID
func (a *Authenticator) StoreCredential(credentialID string, keyPair *KeyPair) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.credentials[credentialID] = keyPair
}

// HasCredential checks if a credential exists
func (a *Authenticator) HasCredential(credentialID string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.credentials[credentialID]
	return ok
}

// GetPublicKey returns the base64-encoded public key for a credential
func (a *Authenticator) GetPublicKey(credentialID string) ([]byte, error) {
	keyPair, err := a.GetCredential(credentialID)
	if err != nil {
		return nil, err
	}
	return keyPair.GetCOSEPublicKey()
}

// SignData signs data with a stored credential's private key (DER format)
func (a *Authenticator) SignData(credentialID string, data []byte) ([]byte, error) {
	keyPair, err := a.GetCredential(credentialID)
	if err != nil {
		return nil, err
	}
	return keyPair.SignDER(data)
}

// SignDataRaw signs data with a stored credential's private key (raw r||s format)
func (a *Authenticator) SignDataRaw(credentialID string, data []byte) ([]byte, error) {
	keyPair, err := a.GetCredential(credentialID)
	if err != nil {
		return nil, err
	}
	return keyPair.Sign(data)
}

// ExportCredential exports a credential for persistence
func (a *Authenticator) ExportCredential(credentialID string) (*ExportedCredential, error) {
	keyPair, err := a.GetCredential(credentialID)
	if err != nil {
		return nil, err
	}
	return keyPair.Export(), nil
}

// ImportCredential imports a credential from exported data
func (a *Authenticator) ImportCredential(exported *ExportedCredential) error {
	keyPair, err := ImportKeyPair(exported)
	if err != nil {
		return err
	}
	
	credentialIDBase64 := base64.RawURLEncoding.EncodeToString(keyPair.CredentialID)
	a.StoreCredential(credentialIDBase64, keyPair)
	return nil
}

// ExportAllCredentials exports all stored credentials
func (a *Authenticator) ExportAllCredentials() []*ExportedCredential {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]*ExportedCredential, 0, len(a.credentials))
	for _, kp := range a.credentials {
		result = append(result, kp.Export())
	}
	return result
}
