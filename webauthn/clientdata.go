package webauthn

import (
	"crypto/sha256"
	"encoding/json"
)

// BuildClientDataJSON creates the clientDataJSON for registration or authentication.
// When extensions contain a "rar" key, its value is embedded as the "authorization"
// field in clientDataJSON, which is required for FIDO2 transaction signing.
func BuildClientDataJSON(typ, challenge, origin string, extensions map[string]interface{}) ([]byte, error) {
	clientData := ClientData{
		Type:        typ,
		Challenge:   challenge,
		Origin:      origin,
		CrossOrigin: false,
	}
	if extensions != nil {
		if rar, ok := extensions["rar"]; ok {
			if rarMap, ok := rar.(map[string]interface{}); ok {
				clientData.Rar = rarMap
			}
		}
	}
	return json.Marshal(clientData)
}

// HashClientData returns the SHA-256 hash of the clientDataJSON
func HashClientData(clientDataJSON []byte) []byte {
	hash := sha256.Sum256(clientDataJSON)
	return hash[:]
}
