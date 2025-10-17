package com.backbase.identity.testapp.model.fido2;

import com.backbase.identity.fido2testharness.dto.CredentialCreationOptions;
import lombok.Data;

/**
 * Envelope for FIDO2 creation options, additional fields can be added if needed to simulate more complex cases.
 */
@Data
public class AttestationEnvelope {
    private CredentialCreationOptions options;
    private String label;
}
