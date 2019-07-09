package com.backbase.identity.testapp;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;

public class BinaryHash {

    public static void main(String[] args) throws Exception{

        byte[] bArray = Files.readAllBytes(Paths.get("/Users/gavin/Desktop/text.bin"));

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bArray);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Files.write(Paths.get("/Users/gavin/Desktop/text.sha"), bArray);

    }


}
