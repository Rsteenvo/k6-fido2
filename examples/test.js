import http from 'k6/http';
import { check, sleep } from 'k6';
import fido2 from 'k6/x/fido2';

export const options = {
  vus: 1,
  iterations: 1,
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const RP_ID = __ENV.RP_ID || 'localhost';
const ORIGIN = __ENV.ORIGIN || 'http://localhost:8080';

export default function () {
  // Step 1: Start registration - get challenge from server
  console.log('Starting WebAuthn registration flow...');
  
  const regStartRes = http.post(`${BASE_URL}/webauthn/register/start`, JSON.stringify({
    username: `testuser_${__VU}_${__ITER}`,
    displayName: 'Test User',
  }), {
    headers: { 'Content-Type': 'application/json' },
  });

  check(regStartRes, {
    'registration start successful': (r) => r.status === 200,
  });

  const regOptions = JSON.parse(regStartRes.body);
  console.log('Received registration options from server');

  // Step 2: Create credential using FIDO2 authenticator
  const credential = fido2.register({
    challenge: regOptions.publicKey.challenge,
    rpId: regOptions.publicKey.rp.id || RP_ID,
    rpName: regOptions.publicKey.rp.name || 'Test RP',
    userId: regOptions.publicKey.user.id,
    userName: regOptions.publicKey.user.name,
    origin: ORIGIN,
  });

  console.log(`Created credential with ID: ${credential.id}`);

  // Step 3: Complete registration - send attestation to server
  const regFinishRes = http.post(`${BASE_URL}/webauthn/register/finish`, JSON.stringify({
    id: credential.id,
    rawId: credential.rawId,
    type: credential.type,
    response: {
      clientDataJSON: credential.response.clientDataJSON,
      attestationObject: credential.response.attestationObject,
    },
  }), {
    headers: { 'Content-Type': 'application/json' },
  });

  check(regFinishRes, {
    'registration finish successful': (r) => r.status === 200 || r.status === 201,
  });

  console.log('Registration completed successfully');

  sleep(1);

  // Step 4: Start authentication - get challenge from server
  console.log('Starting WebAuthn authentication flow...');

  const authStartRes = http.post(`${BASE_URL}/webauthn/login/start`, JSON.stringify({
    username: `testuser_${__VU}_${__ITER}`,
  }), {
    headers: { 'Content-Type': 'application/json' },
  });

  check(authStartRes, {
    'authentication start successful': (r) => r.status === 200,
  });

  const authOptions = JSON.parse(authStartRes.body);
  console.log('Received authentication options from server');

  // Step 5: Sign challenge using FIDO2 authenticator
  const assertion = fido2.authenticate({
    challenge: authOptions.publicKey.challenge,
    rpId: authOptions.publicKey.rpId || RP_ID,
    credentialId: credential.id,
    origin: ORIGIN,
    userHandle: authOptions.publicKey.userHandle || '',
  });

  console.log('Created assertion signature');

  // Step 6: Complete authentication - send assertion to server
  const authFinishRes = http.post(`${BASE_URL}/webauthn/login/finish`, JSON.stringify({
    id: assertion.id,
    rawId: assertion.rawId,
    type: assertion.type,
    response: {
      clientDataJSON: assertion.response.clientDataJSON,
      authenticatorData: assertion.response.authenticatorData,
      signature: assertion.response.signature,
      userHandle: assertion.response.userHandle || null,
    },
  }), {
    headers: { 'Content-Type': 'application/json' },
  });

  check(authFinishRes, {
    'authentication finish successful': (r) => r.status === 200,
  });

  console.log('Authentication completed successfully');
}
