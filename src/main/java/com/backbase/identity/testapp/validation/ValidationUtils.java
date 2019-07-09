package com.backbase.identity.testapp.validation;

import com.backbase.identity.device.common.publickey.PublicKeyAlgorithm;
import com.backbase.identity.device.common.signature.AuthenticationAlgorithm;
import java.util.Arrays;

public class ValidationUtils {

    public static void validatePublicKeyAlgorithm(String publicKeyAlgorithm) {
        if (Arrays.stream(
            PublicKeyAlgorithm.values())
            .noneMatch(alg -> alg.name().equals(publicKeyAlgorithm))) {
            throw new RuntimeException("Public key algorithm not recognised or supported");
        }
    }

    public static void validateSignatureAlgorithm(String signatureAlgorithm) {
        if (Arrays.stream(
            AuthenticationAlgorithm.values())
            .noneMatch(alg -> alg.name().equals(signatureAlgorithm))) {
            throw new RuntimeException("Signature algorithm not recognised or supported");
        }
    }



}
