package com.backbase.identity.testapp.model.fido2;

import com.backbase.identity.fido2testharness.dto.CredentialAssertionOptions;
import lombok.Data;

/**
 * Envelope for FIDO2 assertion options, additional fields can be added if needed to simulate more complex cases.
 */
@Data
public class AssertionEnvelope {
    private CredentialAssertionOptions options;
    private String credentialId;
}
