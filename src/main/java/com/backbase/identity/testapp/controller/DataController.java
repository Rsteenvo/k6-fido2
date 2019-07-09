package com.backbase.identity.testapp.controller;

import com.backbase.identity.device.common.publickey.PublicKeyAlgorithm;
import com.backbase.identity.device.common.publickey.PublicKeyUtils;
import com.backbase.identity.device.common.signature.AuthenticationAlgorithm;
import com.backbase.identity.device.common.signature.SignatureUtils;
import com.backbase.identity.testapp.entity.DataEntity;
import com.backbase.identity.testapp.model.GetDataResponseBody;
import com.backbase.identity.testapp.model.PostResponseBody;
import com.backbase.identity.testapp.model.VerifyHashPostRequestBody;
import com.backbase.identity.testapp.model.VerifySignaturePostRequestBody;
import com.backbase.identity.testapp.repository.DataRepository;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.RandomUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/data"})
public class DataController {

    private static final Logger log = LoggerFactory.getLogger(DataController.class);

    private DataRepository dataRepository;

    public DataController(DataRepository dataRepository) {
        this.dataRepository = dataRepository;
    }

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public @ResponseBody GetDataResponseBody getData() {
        log.info("GET request received");
        DataEntity dataEntity = new DataEntity();
        dataEntity.setData(Base64.encodeBase64URLSafeString(RandomUtils.nextBytes(200)));
        dataRepository.save(dataEntity);

        GetDataResponseBody responseBody = new GetDataResponseBody(dataEntity.getId(), dataEntity.getData());
        log.info("Generating new signature: {}", responseBody);
        return responseBody;
    }

    @RequestMapping(
        method = {RequestMethod.POST},
        path = {"/hash"},
        produces = {"application/json"}
    )
    @ResponseStatus(HttpStatus.OK)
    public @ResponseBody PostResponseBody verifyHash(@RequestBody VerifyHashPostRequestBody requestBody)
        throws IOException {
        log.info("Hashing request received {}", requestBody);

        byte[] clientHash = Base64.decodeBase64(requestBody.getHash());
        Files.write(Paths.get("/tmp/client.sha256.bin"), clientHash);

        String originalData = getOriginalData(requestBody.getId());
        byte[] b64decodedOriginalData = Base64.decodeBase64(originalData);
        Files.write(Paths.get("/tmp/client.signature.bin"), b64decodedOriginalData);
        byte[] expectedHash = hashData(b64decodedOriginalData);
        Files.write(Paths.get("/tmp/server.sha256.bin"), expectedHash);

        PostResponseBody responseBody;
        if (Arrays.equals(clientHash, expectedHash)) {
            responseBody = new PostResponseBody("Hash matches");
        } else {
            responseBody = new PostResponseBody("Hash doesn't match");
        }
        log.info("Returning response body {}", responseBody);
        return responseBody;
    }

    @RequestMapping(
        method = {RequestMethod.POST},
        path = {"/signature"},
        produces = {"application/json"}
    )
    @ResponseStatus(HttpStatus.OK)
    public @ResponseBody PostResponseBody verifySignature(@RequestBody VerifySignaturePostRequestBody requestBody) {
        log.info("Signature request received {}", requestBody);

        if (Arrays.stream(
            PublicKeyAlgorithm.values())
            .noneMatch(alg -> alg.name().equals(requestBody.getPublicKeyAlgorithm()))) {
            throw new RuntimeException("Public key algorithm not recognised or supported");
        }

        PublicKey publicKey;

        try {
            publicKey = PublicKeyUtils.decodePublicKey(
                PublicKeyAlgorithm.valueOf(requestBody.getPublicKeyAlgorithm()),
                Base64.decodeBase64(requestBody.getPublicKey()));
        } catch (Exception e) {
            throw new RuntimeException("Public key decoding failed");
        }

        byte[] clientSignature = Base64.decodeBase64(requestBody.getSignature());

        if (Arrays.stream(
            AuthenticationAlgorithm.values())
                .noneMatch(alg -> alg.name().equals(requestBody.getSignatureAlgorithm()))) {
            throw new RuntimeException("Signature algorithm not recognised or supported");
        }

        String originalData = getOriginalData(requestBody.getId());
        byte[] b64decodedOriginalData = Base64.decodeBase64(originalData);

        boolean signatureVerified;
        try {
            signatureVerified = SignatureUtils.verifySignature(
                AuthenticationAlgorithm.valueOf(requestBody.getSignatureAlgorithm()),
                publicKey,
                b64decodedOriginalData,
                clientSignature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        PostResponseBody responseBody;
        if (signatureVerified) {
            responseBody = new PostResponseBody("Signature matches");
        } else {
            responseBody = new PostResponseBody("Signature doesn't match");
        }
        log.info("Returning response body {}", responseBody);
        return responseBody;
    }

    private String getOriginalData(int id) {
        Optional<DataEntity> optionalDataEntity = dataRepository.findById(id);
        if (optionalDataEntity.isPresent()) {
           return optionalDataEntity.get().getData();
        } else {
            throw new RuntimeException("id not recognised");
        }
    }

    private byte[] hashData(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
            byte[] hash = md.digest(data);
            Files.write(Paths.get("/tmp/server.sha256.bin"), hash);
            return hash;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
