# xk6-fido2

A K6 extension for FIDO2/WebAuthn client simulation, enabling performance testing of WebAuthn servers.

This library simulates a WebAuthn platform authenticator (like TouchID, FaceID, or Windows Hello), allowing you to generate valid WebAuthn registration and authentication responses directly within K6 load tests.

## Features

- Generate WebAuthn registration (attestation) responses
- Generate WebAuthn authentication (assertion) responses  
- ECDSA P-256 key pair management
- COSE-encoded public keys
- In-memory credential storage per VU (virtual user)
- Thread-safe for concurrent K6 virtual users

## Prerequisites

- Go 1.21 or later
- [xk6](https://github.com/grafana/xk6) - K6 extension builder

## Building

```bash
cd xk6-fido2

# Build custom k6 binary with the extension
xk6 build --with github.com/backbase-rnd/k6-fido2=.

# Or for local development
xk6 build --with xk6-fido2=.
```

## Usage

```javascript
import fido2 from 'k6/x/fido2';

export default function() {
  // Registration - create a new credential
  const credential = fido2.register({
    challenge: 'base64url-challenge-from-server',
    rpId: 'example.com',
    rpName: 'Example Corp',
    userId: 'base64url-user-id',
    userName: 'testuser',
    origin: 'https://example.com'
  });

  console.log(`Created credential: ${credential.id}`);

  // Authentication - sign a challenge with the credential
  const assertion = fido2.authenticate({
    challenge: 'new-base64url-challenge-from-server',
    rpId: 'example.com',
    credentialId: credential.id,
    origin: 'https://example.com'
  });

  console.log(`Signed assertion: ${assertion.response.signature}`);
}
```

## API Reference

### fido2.register(options)

Creates a new credential and returns the attestation response.

**Options:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `challenge` | string | Base64URL-encoded challenge from server |
| `rpId` | string | Relying Party ID (domain) |
| `rpName` | string | Relying Party display name |
| `userId` | string | Base64URL-encoded user ID |
| `userName` | string | User display name |
| `origin` | string | Origin URL (e.g., "https://example.com") |

**Returns:** PublicKeyCredential object with attestation response

```javascript
{
  id: "base64url-credential-id",
  rawId: "base64url-credential-id",
  type: "public-key",
  response: {
    clientDataJSON: "base64url-encoded-json",
    attestationObject: "base64url-encoded-cbor"
  }
}
```

### fido2.authenticate(options)

Signs an authentication challenge with an existing credential.

**Options:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `challenge` | string | Base64URL-encoded challenge from server |
| `rpId` | string | Relying Party ID (domain) |
| `credentialId` | string | Base64URL-encoded credential ID |
| `origin` | string | Origin URL |
| `userHandle` | string (optional) | Base64URL-encoded user handle |

**Returns:** PublicKeyCredential object with assertion response

```javascript
{
  id: "base64url-credential-id",
  rawId: "base64url-credential-id", 
  type: "public-key",
  response: {
    clientDataJSON: "base64url-encoded-json",
    authenticatorData: "base64url-encoded-data",
    signature: "base64url-encoded-signature",
    userHandle: "optional-user-handle"
  }
}
```

## Examples

See the `xk6-fido2/examples/` directory for complete examples:

- `simple.js` - Basic credential creation and authentication
- `test.js` - Full WebAuthn flow with a server

## Running Examples

```bash
cd xk6-fido2

# Build the k6 binary
xk6 build --with xk6-fido2=.

# Run the simple example
./k6 run examples/simple.js

# Run with a WebAuthn server
./k6 run -e BASE_URL=http://localhost:8080 examples/test.js
```

## Project Structure

```
xk6-fido2/
├── go.mod                  # Go module definition
├── fido2.go                # K6 module entry point
├── authenticator/
│   ├── authenticator.go    # Core authenticator with credential storage
│   ├── keypair.go          # ECDSA P-256 key generation
│   ├── attestation.go      # Registration response builder
│   ├── assertion.go        # Authentication response builder
│   └── cbor.go             # CBOR encoding helpers
├── webauthn/
│   ├── types.go            # WebAuthn data structures
│   ├── clientdata.go       # ClientDataJSON builder
│   └── authdata.go         # AuthenticatorData builder
└── examples/
    ├── simple.js           # Basic usage example
    └── test.js             # Full WebAuthn flow example
```

## Technical Details

- **Curve**: ECDSA P-256 (secp256r1)
- **Signature Format**: DER-encoded ECDSA
- **Attestation Format**: "none" (standard for software authenticators)
- **AAGUID**: All zeros (acceptable for testing)
- **Sign Counter**: Increments per-credential for replay protection
