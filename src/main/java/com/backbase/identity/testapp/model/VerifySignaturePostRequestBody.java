package com.backbase.identity.testapp.model;

import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class VerifySignaturePostRequestBody {

    @NotNull
    private Integer id;

    @NotNull
    private String signature;

    @NotNull
    private String signatureAlgorithm;

    @NotNull
    private String publicKey;

    @NotNull
    private String publicKeyAlgorithm;

}
