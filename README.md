# xk6-fido2

A K6 extension for FIDO2/WebAuthn client simulation, enabling performance testing of WebAuthn servers.

## Features

- Generate WebAuthn registration (attestation) responses
- Generate WebAuthn authentication (assertion) responses
- ECDSA P-256 key pair management
- In-memory credential storage per VU

## Building

```bash
xk6 build --with github.com/rsteenvo/k6-fido2=.
```

## Usage

```javascript
import fido2 from 'k6/x/fido2';

export default function() {
  // Registration
  const credential = fido2.register({
    challenge: 'base64url-challenge-from-server',
    rpId: 'example.com',
    rpName: 'Example Corp',
    userId: 'base64url-user-id',
    userName: 'testuser',
    origin: 'https://example.com'
  });
  
  // Authentication
  const assertion = fido2.authenticate({
    challenge: 'base64url-challenge-from-server',
    rpId: 'example.com',
    credentialId: credential.id,
    origin: 'https://example.com'
  });
}
```

## API

### fido2.register(options)

Creates a new credential and returns the attestation response.

**Options:**
- `challenge` (string): Base64URL-encoded challenge from server
- `rpId` (string): Relying Party ID (domain)
- `rpName` (string): Relying Party display name
- `userId` (string): Base64URL-encoded user ID
- `userName` (string): User display name
- `origin` (string): Origin URL (e.g., "https://example.com")

**Returns:** PublicKeyCredential object with attestation response

### fido2.authenticate(options)

Signs an authentication challenge with an existing credential.

**Options:**
- `challenge` (string): Base64URL-encoded challenge from server
- `rpId` (string): Relying Party ID (domain)
- `credentialId` (string): Base64URL-encoded credential ID
- `origin` (string): Origin URL
- `userHandle` (string, optional): Base64URL-encoded user handle

**Returns:** PublicKeyCredential object with assertion response
