package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

const (
	// Flags for authenticator data
	FlagUserPresent  byte = 0x01
	FlagUserVerified byte = 0x04
	FlagAttestedCred byte = 0x40
	FlagExtensions   byte = 0x80
)

// BuildAuthenticatorData creates the authenticator data for registration (with attested credential)
func BuildAuthenticatorData(rpID string, credentialID, cosePublicKey []byte, signCount uint32) []byte {
	var buf bytes.Buffer

	// RP ID hash (32 bytes)
	rpIDHash := sha256.Sum256([]byte(rpID))
	buf.Write(rpIDHash[:])

	// Flags (1 byte) - UP + UV + AT (attested credential data present)
	flags := FlagUserPresent | FlagUserVerified | FlagAttestedCred
	buf.WriteByte(flags)

	// Sign count (4 bytes, big endian)
	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, signCount)
	buf.Write(countBytes)

	// Attested credential data
	// AAGUID (16 bytes) - using zeros for testing
	aaguid := make([]byte, 16)
	buf.Write(aaguid)

	// Credential ID length (2 bytes, big endian)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credentialID)))
	buf.Write(credIDLen)

	// Credential ID
	buf.Write(credentialID)

	// COSE public key
	buf.Write(cosePublicKey)

	return buf.Bytes()
}

// BuildAuthenticatorDataForAssertion creates the authenticator data for authentication (without attested credential)
func BuildAuthenticatorDataForAssertion(rpID string, signCount uint32) []byte {
	var buf bytes.Buffer

	// RP ID hash (32 bytes)
	rpIDHash := sha256.Sum256([]byte(rpID))
	buf.Write(rpIDHash[:])

	// Flags (1 byte) - UP + UV (no attested credential data)
	flags := FlagUserPresent | FlagUserVerified
	buf.WriteByte(flags)

	// Sign count (4 bytes, big endian)
	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, signCount)
	buf.Write(countBytes)

	return buf.Bytes()
}
