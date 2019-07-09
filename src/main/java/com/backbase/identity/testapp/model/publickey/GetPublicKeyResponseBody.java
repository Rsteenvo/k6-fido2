package com.backbase.identity.testapp.model.publickey;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class GetPublicKeyResponseBody {

    private String publicKey;

    private String publicKeyAlgorithm;
}
