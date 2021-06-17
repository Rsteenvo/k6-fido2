package com.backbase.identity.testapp.model.fido.uaf.authentication;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class CreateFidoUafAuthenticationResponseRequestBody {

    private String aaId;

    private String keyPairAlias;

    private String uafRequest;

    private String signatureAlgorithm;

    private String trustedFacetId;

    private String username;

    private Integer authenticationMode;

    private String signatureKeyPairAlias;

    private String overridenSignature;

    private String signatureSignData;

    private Boolean authFlowSupportsKeyRotation;

}
