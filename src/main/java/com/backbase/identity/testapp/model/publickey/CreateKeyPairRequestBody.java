package com.backbase.identity.testapp.model.publickey;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.jetbrains.annotations.NotNull;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class CreateKeyPairRequestBody {

    private String keyPairAlias;

    @NotNull
    private String publicKeyAlgorithm;
}
