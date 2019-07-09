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
public class CreateFidoUafRegistrationResponseResponseBody {

    private String sendUafResponse;

    private String publicKeyAlgorithm;

    private String signatureAlgorithm;

}
