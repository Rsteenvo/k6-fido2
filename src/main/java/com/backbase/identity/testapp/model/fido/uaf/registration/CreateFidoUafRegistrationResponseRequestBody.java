package com.backbase.identity.testapp.model.fido.uaf.registration;

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
public class CreateFidoUafRegistrationResponseRequestBody {

    private String aaId;

    private String keyPairAlias;

    private String publicKeyAlgorithm;

    private String uafRequest;

    private String signatureAlgorithm;

    private String trustedFacetId;


}
