import fido2 from 'k6/x/fido2';
import { check } from 'k6';
import encoding from 'k6/encoding';

export const options = {
  vus: 1,
  iterations: 1,
};

export default function () {
  // Generate a random challenge (simulating what a server would provide)
  const challenge = encoding.b64encode(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))), 'rawurl');

  // Create a new credential
  console.log('Creating new FIDO2 credential...');
  const credential = fido2.register({
    challenge: challenge,
    rpId: 'example.com',
    rpName: 'Example Corp',
    userId: encoding.b64encode('user123', 'rawurl'),
    userName: 'testuser@example.com',
    origin: 'https://example.com',
  });

  check(credential, {
    'credential has id': (c) => c.id !== '',
    'credential has type public-key': (c) => c.type === 'public-key',
    'credential has clientDataJSON': (c) => c.response.clientDataJSON !== '',
    'credential has attestationObject': (c) => c.response.attestationObject !== '',
  });

  console.log(`Credential ID: ${credential.id}`);
  console.log(`Credential Type: ${credential.type}`);

  // Authenticate with the credential
  console.log('\nAuthenticating with credential...');
  const newChallenge = encoding.b64encode(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))), 'rawurl');

  const assertion = fido2.authenticate({
    challenge: newChallenge,
    rpId: 'example.com',
    credentialId: credential.id,
    origin: 'https://example.com',
  });

  check(assertion, {
    'assertion has id': (a) => a.id === credential.id,
    'assertion has type public-key': (a) => a.type === 'public-key',
    'assertion has clientDataJSON': (a) => a.response.clientDataJSON !== '',
    'assertion has authenticatorData': (a) => a.response.authenticatorData !== '',
    'assertion has signature': (a) => a.response.signature !== '',
  });

  console.log(`Assertion ID: ${assertion.id}`);
  console.log(`Signature: ${assertion.response.signature.substring(0, 50)}...`);

  console.log('\nFIDO2 credential creation and authentication successful!');
}
