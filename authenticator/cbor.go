package authenticator

import (
	"github.com/fxamacker/cbor/v2"
)

// AttestationObjectCBOR represents the CBOR-encoded attestation object
type AttestationObjectCBOR struct {
	Fmt      string                 `cbor:"fmt"`
	AttStmt  map[string]interface{} `cbor:"attStmt"`
	AuthData []byte                 `cbor:"authData"`
}

// EncodeAttestationObject encodes the attestation object to CBOR
func EncodeAttestationObject(authData []byte) ([]byte, error) {
	attestObj := AttestationObjectCBOR{
		Fmt:      "none",
		AttStmt:  make(map[string]interface{}),
		AuthData: authData,
	}

	return cbor.Marshal(attestObj)
}
