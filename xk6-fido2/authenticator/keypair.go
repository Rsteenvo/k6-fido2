package authenticator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// COSE key type and algorithm constants
const (
	COSEKeyTypeEC2     = 2   // Elliptic Curve key type
	COSEAlgES256       = -7  // ECDSA w/ SHA-256
	COSEP256CurveID    = 1   // P-256 curve
)

// COSEKey represents a COSE-encoded public key
type COSEKey struct {
	KeyType   int    `cbor:"1,keyasint"`
	Algorithm int    `cbor:"3,keyasint"`
	CurveID   int    `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}

// KeyPair holds an ECDSA key pair with its credential ID
type KeyPair struct {
	CredentialID []byte
	PrivateKey   *ecdsa.PrivateKey
	PublicKey    *ecdsa.PublicKey
	SignCount    uint32
}

// GenerateKeyPair creates a new ECDSA P-256 key pair
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Generate a random credential ID (32 bytes)
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		return nil, fmt.Errorf("failed to generate credential ID: %w", err)
	}

	return &KeyPair{
		CredentialID: credentialID,
		PrivateKey:   privateKey,
		PublicKey:    &privateKey.PublicKey,
		SignCount:    0,
	}, nil
}

// GetCOSEPublicKey returns the public key in COSE format
func (kp *KeyPair) GetCOSEPublicKey() ([]byte, error) {
	// Ensure X and Y coordinates are 32 bytes (P-256)
	xBytes := kp.PublicKey.X.Bytes()
	yBytes := kp.PublicKey.Y.Bytes()

	// Pad to 32 bytes if needed
	xBytes = padTo32Bytes(xBytes)
	yBytes = padTo32Bytes(yBytes)

	coseKey := COSEKey{
		KeyType:   COSEKeyTypeEC2,
		Algorithm: COSEAlgES256,
		CurveID:   COSEP256CurveID,
		X:         xBytes,
		Y:         yBytes,
	}

	return cbor.Marshal(coseKey)
}

// GetX962PublicKey returns the public key in X9.62 uncompressed point format (04 || X || Y)
func (kp *KeyPair) GetX962PublicKey() []byte {
	// Ensure X and Y coordinates are 32 bytes (P-256)
	xBytes := kp.PublicKey.X.Bytes()
	yBytes := kp.PublicKey.Y.Bytes()

	// Pad to 32 bytes if needed
	xBytes = padTo32Bytes(xBytes)
	yBytes = padTo32Bytes(yBytes)

	// X9.62 uncompressed format: 0x04 || X || Y (65 bytes total)
	result := make([]byte, 65)
	result[0] = 0x04 // Uncompressed point indicator
	copy(result[1:33], xBytes)
	copy(result[33:65], yBytes)

	return result
}

// Sign signs the data using the private key and returns the signature in raw format (r||s)
func (kp *KeyPair) Sign(data []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, kp.PrivateKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	// Convert to raw signature format (r || s), each 32 bytes for P-256
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Copy r and s with left padding to 32 bytes
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	return signature, nil
}

// SignDER signs the data and returns the signature in DER format
func (kp *KeyPair) SignDER(data []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, kp.PrivateKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return encodeDERSignature(r, s), nil
}

// IncrementSignCount increments and returns the new sign count
func (kp *KeyPair) IncrementSignCount() uint32 {
	kp.SignCount++
	return kp.SignCount
}

// padTo32Bytes pads a byte slice to 32 bytes with leading zeros
func padTo32Bytes(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// encodeDERSignature encodes r and s values as DER signature
func encodeDERSignature(r, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Add leading zero if high bit is set (to ensure positive integer)
	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0x00}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0x00}, sBytes...)
	}

	// Build DER structure
	totalLen := 2 + len(rBytes) + 2 + len(sBytes)
	der := make([]byte, 0, 2+totalLen)

	// SEQUENCE tag and length
	der = append(der, 0x30)
	der = append(der, byte(totalLen))

	// INTEGER r
	der = append(der, 0x02)
	der = append(der, byte(len(rBytes)))
	der = append(der, rBytes...)

	// INTEGER s
	der = append(der, 0x02)
	der = append(der, byte(len(sBytes)))
	der = append(der, sBytes...)

	return der
}

// ExportedCredential represents a serializable credential for persistence
type ExportedCredential struct {
	CredentialID string `json:"credentialId"`
	PrivateKeyD  string `json:"privateKeyD"`
	SignCount    uint32 `json:"signCount"`
}

// Export serializes the KeyPair for storage
func (kp *KeyPair) Export() *ExportedCredential {
	return &ExportedCredential{
		CredentialID: base64.RawURLEncoding.EncodeToString(kp.CredentialID),
		PrivateKeyD:  base64.RawURLEncoding.EncodeToString(kp.PrivateKey.D.Bytes()),
		SignCount:    kp.SignCount,
	}
}

// ImportKeyPair reconstructs a KeyPair from exported data
func ImportKeyPair(exported *ExportedCredential) (*KeyPair, error) {
	// Decode credential ID
	credentialID, err := base64.RawURLEncoding.DecodeString(exported.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential ID: %w", err)
	}

	// Decode private key D value
	dBytes, err := base64.RawURLEncoding.DecodeString(exported.PrivateKeyD)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Reconstruct the private key
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(dBytes)

	// Compute public key from D
	x, y := curve.ScalarBaseMult(d.Bytes())

	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}

	return &KeyPair{
		CredentialID: credentialID,
		PrivateKey:   privateKey,
		PublicKey:    &privateKey.PublicKey,
		SignCount:    exported.SignCount,
	}, nil
}
