package com.backbase.identity.testapp.controller;

import com.backbase.identity.fidotestharness.dto.VerificationRequest;
import com.backbase.identity.fidotestharness.utils.DeviceAssertionSigner;
import com.backbase.identity.testapp.model.deviceassertion.DeviceAssertionResponseBody;
import com.backbase.identity.testapp.model.deviceassertion.VerificationRequestBody;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/deviceassertion")
public class DeviceAssertionController {

    private DeviceAssertionSigner deviceAssertionSigner;

    public DeviceAssertionController()
        throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, IOException {
        this.deviceAssertionSigner = new DeviceAssertionSigner();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.OK)
    public DeviceAssertionResponseBody signDeviceAssertion(@RequestBody VerificationRequestBody requestBody)
        throws GeneralSecurityException, IOException {
        VerificationRequest verificationRequest = requestBody.mapToVerificationRequest();

        String assertion = deviceAssertionSigner.signDeviceAssertion(verificationRequest);

        return DeviceAssertionResponseBody.builder()
            .deviceAttestation(assertion)
            .build();
    }

}
