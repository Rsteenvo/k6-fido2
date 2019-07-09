package com.backbase.identity.testapp.controller;

import com.backbase.identity.device.common.publickey.PublicKeyAlgorithm;
import com.backbase.identity.fidotestharness.FidoUafRegistry;
import com.backbase.identity.fidotestharness.utils.BBPKIUtils;
import com.backbase.identity.testapp.model.publickey.CreateKeyPairRequestBody;
import com.backbase.identity.testapp.model.publickey.CreateKeyPairResponseBody;
import com.backbase.identity.testapp.model.publickey.GetPublicKeyResponseBody;
import com.backbase.identity.testapp.validation.ValidationUtils;
import java.util.UUID;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public-keys")
public class PublicKeyController {

    private BBPKIUtils bbpkiUtils = BBPKIUtils.getInstance();

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public CreateKeyPairResponseBody createKeyPair(@RequestBody CreateKeyPairRequestBody requestBody) {
        ValidationUtils.validatePublicKeyAlgorithm(requestBody.getPublicKeyAlgorithm());

        String alias = (StringUtils.isNotEmpty(requestBody.getKeyPairAlias())
            ? requestBody.getKeyPairAlias()
            : UUID.randomUUID().toString());
        bbpkiUtils.generateKeyPair(alias);

        String publicKeyAlgorithm = PublicKeyAlgorithm.valueOf(requestBody.getPublicKeyAlgorithm()).name();
        byte[] publicKeyBytes = bbpkiUtils.getPublicKey(
            alias,
            publicKeyAlgorithm.equals(PublicKeyAlgorithm.ALG_KEY_ECC_X962_RAW.name())
                ? FidoUafRegistry.ALG_KEY_ECC_X962_RAW
                : FidoUafRegistry.ALG_KEY_ECC_X962_DER);

        return CreateKeyPairResponseBody.builder()
            .keyPairAlias(alias)
            .publicKey(Base64.encodeBase64String(publicKeyBytes))
            .publicKeyAlgorithm(publicKeyAlgorithm)
            .build();
    }

    @GetMapping("/{keyPairAlias}")
    @ResponseStatus(HttpStatus.OK)
    public GetPublicKeyResponseBody getKeyPair(
        @PathVariable String keyPairAlias, @PathVariable String publicKeyAlgorithm) {
        if (!bbpkiUtils.hasKeyPair(keyPairAlias)) {
            throw new RuntimeException("Key pair does not exist with alias : " + keyPairAlias);
        }

        ValidationUtils.validatePublicKeyAlgorithm(publicKeyAlgorithm);

        return GetPublicKeyResponseBody.builder()
            .publicKey(Base64.encodeBase64String(bbpkiUtils.getPublicKey(
                keyPairAlias,
                publicKeyAlgorithm.equals(PublicKeyAlgorithm.ALG_KEY_ECC_X962_RAW.name())
                    ? FidoUafRegistry.ALG_KEY_ECC_X962_RAW
                    : FidoUafRegistry.ALG_KEY_ECC_X962_DER)))
            .publicKeyAlgorithm(publicKeyAlgorithm)
            .build();
    }





}
