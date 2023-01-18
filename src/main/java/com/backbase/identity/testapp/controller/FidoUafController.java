package com.backbase.identity.testapp.controller;

import com.backbase.identity.device.common.publickey.PublicKeyAlgorithm;
import com.backbase.identity.device.common.signature.AuthenticationAlgorithm;
import com.backbase.identity.device.model.fido.Operation;
import com.backbase.identity.device.model.fido.ReturnUafRequest;
import com.backbase.identity.device.model.fido.SendUafResponse;
import com.backbase.identity.device.model.fido.Transaction;
import com.backbase.identity.device.model.fido.UafStatusCode;
import com.backbase.identity.fidotestharness.FidoUafRegistry;
import com.backbase.identity.fidotestharness.assertions.AssertionBuilder;
import com.backbase.identity.fidotestharness.assertions.AuthenticationAssertionBuilder;
import com.backbase.identity.fidotestharness.assertions.RegistrationAssertionBuilder;
import com.backbase.identity.fidotestharness.dto.RegRequestEntry;
import com.backbase.identity.fidotestharness.response.FidoUafAuthenticationResponseBuilder;
import com.backbase.identity.fidotestharness.response.FidoUafRegistrationResponseBuilder;
import com.backbase.identity.fidotestharness.response.FidoUafResponseBuilder.DefaultFCPBase64Encoder;
import com.backbase.identity.fidotestharness.response.FidoUafResponseBuilder.DefaultFCPHasher;
import com.backbase.identity.fidotestharness.response.FidoUafResponseBuilder.DefaultTTHasher;
import com.backbase.identity.fidotestharness.utils.BBPKIUtils;
import com.backbase.identity.testapp.model.fido.uaf.authentication.CreateFidoUafAuthenticationResponseRequestBody;
import com.backbase.identity.testapp.model.fido.uaf.authentication.CreateFidoUafAuthenticationResponseResponseBody;
import com.backbase.identity.testapp.model.fido.uaf.registration.CreateFidoUafRegistrationResponseRequestBody;
import com.backbase.identity.testapp.model.fido.uaf.registration.CreateFidoUafRegistrationResponseResponseBody;
import com.backbase.identity.testapp.validation.ValidationUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import java.security.Signature;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/fido-uaf")
public class FidoUafController {

    private BBPKIUtils bbpkiUtils = BBPKIUtils.getInstance();

    private ObjectMapper objectMapper = new ObjectMapper();
    private static final int AUTH_MODE_USER_VERIFIED = 1;
    private static final int AUTH_MODE_TXN_CONTENT_VERIFIED = 2;

    @PostMapping("/registration-response")
    @ResponseStatus(HttpStatus.CREATED)
    public CreateFidoUafRegistrationResponseResponseBody createFidoUafRegistrationResponse(
        @RequestBody CreateFidoUafRegistrationResponseRequestBody requestBody) throws Exception {
        ValidationUtils.validatePublicKeyAlgorithm(requestBody.getPublicKeyAlgorithm());
        ValidationUtils.validateSignatureAlgorithm(requestBody.getSignatureAlgorithm());

        String keyPairAlias = requestBody.getKeyPairAlias();

        String signatureKeyPairAlias = requestBody.getSignatureKeyPairAlias();
        if (signatureKeyPairAlias == null) {
            signatureKeyPairAlias = keyPairAlias;
        }

        if (!bbpkiUtils.hasKeyPair(signatureKeyPairAlias)) {
            throw new RuntimeException("Key pair does not exist with alias : " + keyPairAlias);
        }

        Signature signatureObject = bbpkiUtils.getSignatureObject(signatureKeyPairAlias);

        SendUafResponse sendUafResponse = new FidoUafRegistrationResponseBuilder()
            .withFacetId(requestBody.getTrustedFacetId())
            .withRegistrationRequest(ReturnUafRequest.builder()
                .uafRequest(requestBody.getUafRequest())
                .op(Operation.Reg)
                .statusCode(UafStatusCode.OK)
                .lifetimeMillis(300000L)
                .build())
            .withFinalChallengeParamsHasher(new DefaultFCPHasher())
            .withFinalChallengeParamsBase64Encoder(new DefaultFCPBase64Encoder())
            .withAssertionBuilders(
                new RegistrationAssertionBuilder()
                    .withAaid(requestBody.getAaId())
                    .withAuthenticatorVersion((short)1)
                    .withKeyAlias(keyPairAlias)
                    .withSignCounter(0)
                    .withRegistrationCounter(0)
                    .withAuthenticationMode((byte)AUTH_MODE_USER_VERIFIED)
                    .withSignatureAlgAndEncoding(requestBody.getSignatureAlgorithm().equals(AuthenticationAlgorithm.ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW.name())
                        ? FidoUafRegistry.ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
                        : FidoUafRegistry.ALG_SIGN_SECP256R1_ECDSA_SHA256_DER)
                    .withPublicKeyAlgAndEncoding(requestBody.getPublicKeyAlgorithm().equals(PublicKeyAlgorithm.ALG_KEY_ECC_X962_RAW.name())
                        ? FidoUafRegistry.ALG_KEY_ECC_X962_RAW
                        : FidoUafRegistry.ALG_KEY_ECC_X962_DER)
                    .withPublicKey(bbpkiUtils.getPublicKey(
                        keyPairAlias,
                        requestBody.getPublicKeyAlgorithm().equals(PublicKeyAlgorithm.ALG_KEY_ECC_X962_RAW.name())
                            ? FidoUafRegistry.ALG_KEY_ECC_X962_RAW
                            : FidoUafRegistry.ALG_KEY_ECC_X962_DER))
                    .withSignature(signatureObject)
                    .withOverridenSignature(requestBody.getOverridenSignature())
                    .withSignatureSignData(requestBody.getSignatureSignData()))
            .build();

        return CreateFidoUafRegistrationResponseResponseBody.builder()
            .publicKeyAlgorithm(requestBody.getPublicKeyAlgorithm())
            .sendUafResponse(objectMapper.writeValueAsString(sendUafResponse))
            .signatureAlgorithm(requestBody.getSignatureAlgorithm())
            .build();
    }

    @PostMapping("/authentication-response")
    @ResponseStatus(HttpStatus.CREATED)
    public CreateFidoUafAuthenticationResponseResponseBody createFidoUafAuthenticationResponse(
        @RequestBody CreateFidoUafAuthenticationResponseRequestBody requestBody) throws Exception {
        ValidationUtils.validateSignatureAlgorithm(requestBody.getSignatureAlgorithm());

        String keyPairAlias = requestBody.getKeyPairAlias();

        String signatureKeyPairAlias = requestBody.getSignatureKeyPairAlias();
        if (signatureKeyPairAlias == null) {
            signatureKeyPairAlias = keyPairAlias;
        }

        if (!bbpkiUtils.hasKeyPair(signatureKeyPairAlias)) {
            throw new RuntimeException("Key pair does not exist with alias : " + keyPairAlias);
        }

        Signature signatureObject = bbpkiUtils.getSignatureObject(signatureKeyPairAlias);

        SendUafResponse sendUafResponse = new FidoUafAuthenticationResponseBuilder()
            .withUsername(requestBody.getUsername())
            .withUserId(requestBody.getUserId())
            .withDeviceId(requestBody.getDeviceId())
            .withFacetId(requestBody.getTrustedFacetId())
            .withAuthFlowSupportsKeyRotation(requestBody.getAuthFlowSupportsKeyRotation())
            .withAuthenticationRequest(ReturnUafRequest.builder()
                .uafRequest(requestBody.getUafRequest())
                .op(Operation.Auth)
                .statusCode(UafStatusCode.OK)
                .lifetimeMillis(300000L)
                .build())
            .withFinalChallengeParamsHasher(new DefaultFCPHasher())
            .withFinalChallengeParamsBase64Encoder(new DefaultFCPBase64Encoder())
            .withTransactionTextHasher(new DefaultTTHasher())
            .withAssertionBuilders(
                getAssertionBuilder(requestBody, keyPairAlias, signatureObject))
            .build();

        return CreateFidoUafAuthenticationResponseResponseBody.builder()
            .sendUafResponse(objectMapper.writeValueAsString(sendUafResponse))
            .signatureAlgorithm(requestBody.getSignatureAlgorithm())
            .build();
    }

    private AssertionBuilder getAssertionBuilder(
        @RequestBody CreateFidoUafAuthenticationResponseRequestBody requestBody,
        String keyPairAlias, Signature signatureObject) {
        Integer authenticationMode = requestBody.getAuthenticationMode();
        if (authenticationMode == null) {
            RegRequestEntry[] regRequestEntries = new Gson()
                .fromJson(requestBody.getUafRequest(), RegRequestEntry[].class);
            Transaction[] transactions = regRequestEntries[0].getTransaction();
            authenticationMode = transactions == null || transactions.length == 0
                ? AUTH_MODE_USER_VERIFIED : AUTH_MODE_TXN_CONTENT_VERIFIED;
        }

        return new AuthenticationAssertionBuilder()
            .withAaid(requestBody.getAaId())
            .withAuthenticatorVersion((short)1)
            .withKeyAlias(keyPairAlias)
            .withSignCounter(0)
            .withSignatureAlgAndEncoding(requestBody.getSignatureAlgorithm().equals(AuthenticationAlgorithm.ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW.name())
                ? FidoUafRegistry.ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
                : FidoUafRegistry.ALG_SIGN_SECP256R1_ECDSA_SHA256_DER)
            .withSignature(signatureObject)
            .withAuthenticationMode(authenticationMode.byteValue())
            .withOverridenSignature(requestBody.getOverridenSignature())
            .withSignatureSignData(requestBody.getSignatureSignData());
    }


}
