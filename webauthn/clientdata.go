package webauthn

import (
	"crypto/sha256"
	"encoding/json"
)

// BuildClientDataJSON creates the clientDataJSON for registration or authentication
func BuildClientDataJSON(typ, challenge, origin string) ([]byte, error) {
	clientData := ClientData{
		Type:        typ,
		Challenge:   challenge,
		Origin:      origin,
		CrossOrigin: false,
	}
	return json.Marshal(clientData)
}

// HashClientData returns the SHA-256 hash of the clientDataJSON
func HashClientData(clientDataJSON []byte) []byte {
	hash := sha256.Sum256(clientDataJSON)
	return hash[:]
}
