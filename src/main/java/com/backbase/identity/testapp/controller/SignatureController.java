package com.backbase.identity.testapp.controller;

import com.backbase.identity.device.common.signature.AuthenticationAlgorithm;
import com.backbase.identity.fidotestharness.FidoUafRegistry;
import com.backbase.identity.fidotestharness.utils.BBPKIUtils;
import com.backbase.identity.testapp.model.signature.CreateSignatureRequestBody;
import com.backbase.identity.testapp.model.signature.CreateSignatureResponseBody;
import com.backbase.identity.testapp.validation.ValidationUtils;
import java.security.Signature;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/signatures")
public class SignatureController {

    private BBPKIUtils bbpkiUtils = BBPKIUtils.getInstance();

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public CreateSignatureResponseBody createKeyPair(@RequestBody CreateSignatureRequestBody requestBody) {
        String keyPairAlias = requestBody.getKeyPairAlias();
        if (!bbpkiUtils.hasKeyPair(keyPairAlias)) {
            throw new RuntimeException("Key pair does not exist with alias : " + keyPairAlias);
        }

        ValidationUtils.validateSignatureAlgorithm(requestBody.getSignatureAlgorithm());

        Signature signatureObject = bbpkiUtils.getSignatureObject(keyPairAlias);
        return CreateSignatureResponseBody.builder()
            .keyPairAlias(keyPairAlias)
            .signature(Base64.encodeBase64String(
                bbpkiUtils.signData(
                    signatureObject,
                    keyPairAlias,
                    requestBody.getSignatureAlgorithm().equals(AuthenticationAlgorithm.ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW.name())
                        ? FidoUafRegistry.ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
                        : FidoUafRegistry.ALG_SIGN_SECP256R1_ECDSA_SHA256_DER,
                    requestBody.getData().getBytes())
                )
            )
            .signatureAlgorithm(requestBody.getSignatureAlgorithm())
            .build();

    }

}
