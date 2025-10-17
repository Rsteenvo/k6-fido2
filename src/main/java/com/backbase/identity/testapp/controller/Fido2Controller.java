package com.backbase.identity.testapp.controller;

import com.backbase.identity.fido2testharness.dto.Base64Bytes;
import com.backbase.identity.fido2testharness.util.PublicKeyAuthenticationRequestBuilder;
import com.backbase.identity.fido2testharness.util.PublicKeyRegistrationRequestBuilder;
import com.backbase.identity.fido2testharness.webdto.PublicKeyAuthenticationRequest;
import com.backbase.identity.fido2testharness.webdto.PublicKeyRegistrationRequest;
import com.backbase.identity.testapp.model.fido2.AssertionEnvelope;
import com.backbase.identity.testapp.model.fido2.AttestationEnvelope;
import java.security.KeyPair;
import java.util.Map;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/webauthn")
@AllArgsConstructor
public class Fido2Controller {

    private final Map<String, KeyPair> fido2KeyPairs;

    @PostMapping(path = "/register", consumes = "application/json", produces = "application/json")
    public PublicKeyRegistrationRequest handleAttestation(@RequestBody AttestationEnvelope envelope) {
        // Simulate platform authenticator logic here
        PublicKeyRegistrationRequestBuilder builder = new PublicKeyRegistrationRequestBuilder(
            fido2KeyPairs, envelope.getOptions());
        // Add custom request values if provided
        if (StringUtils.isNotBlank(envelope.getLabel())) {
            builder.withLabel(envelope.getLabel());
        } else {
            builder.withLabel("Test Key " + System.currentTimeMillis());
        }
        return builder.build();
    }

    @PostMapping(path = "/authenticate", consumes = "application/json", produces = "application/json")
    public PublicKeyAuthenticationRequest handleAssertion(@RequestBody AssertionEnvelope envelope) {
        // Simulate platform authenticator logic here
        PublicKeyAuthenticationRequestBuilder builder = new PublicKeyAuthenticationRequestBuilder(fido2KeyPairs,
            envelope.getOptions());

        if (StringUtils.isNotBlank(envelope.getCredentialId())) {
            builder.withCredentialId(new Base64Bytes(envelope.getCredentialId()));
        } else {
            // Use the first allowed credential if no specific credentialId is provided
            if (envelope.getOptions().getAllowCredentials() != null && !envelope.getOptions().getAllowCredentials()
                .isEmpty()) {
                builder.withCredentialId(envelope.getOptions().getAllowCredentials().get(0).getId());
            } else {
                throw new IllegalArgumentException("No allowed credentials available to use for authentication.");
            }
        }
        return builder.build();
    }
}

