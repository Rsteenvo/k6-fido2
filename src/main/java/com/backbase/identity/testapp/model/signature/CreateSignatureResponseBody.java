package com.backbase.identity.testapp.model.signature;

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
public class CreateSignatureResponseBody {

    private String keyPairAlias;

    private String signature;

    private String signatureAlgorithm;
}
