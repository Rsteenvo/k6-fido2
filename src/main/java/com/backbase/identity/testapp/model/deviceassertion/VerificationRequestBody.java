package com.backbase.identity.testapp.model.deviceassertion;

import com.backbase.identity.fidotestharness.dto.VerificationRequest;
import com.google.api.client.util.Base64;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
public class VerificationRequestBody {

    private String nonce;
    private Long timestampMs;
    private String apkPackageName;
    private String[] apkCertificateDigestSha256;
    private Boolean ctsProfileMatch;
    private Boolean basicIntegrity;
    private String evaluationType;

    public VerificationRequest mapToVerificationRequest() throws NoSuchAlgorithmException {
        if (nonce == null) {
            throw new IllegalArgumentException("nonce cannot be null");
        }

        VerificationRequest verificationRequest = new VerificationRequest();
        verificationRequest.set("timestampMs", timestampMs != null ? timestampMs : System.currentTimeMillis());
        verificationRequest.set("nonce", Base64.encodeBase64String(nonce.getBytes()));
        verificationRequest.set("apkPackageName", apkPackageName != null
            ? apkPackageName : "com.package.name.of.requesting.app");
        verificationRequest.set("apkCertificateDigestSha256", apkCertificateDigestSha256 != null
            ? apkCertificateDigestSha256 : new String[] {new String(MessageDigest.getInstance("SHA-256").digest())});
        verificationRequest.set("ctsProfileMatch", ctsProfileMatch != null ? ctsProfileMatch : true);
        verificationRequest.set("basicIntegrity", basicIntegrity != null ? basicIntegrity : true);
        verificationRequest.set("evaluationType", evaluationType != null ? evaluationType : "BASIC");

        return verificationRequest;
    }

}
