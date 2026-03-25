package com.example.auth.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

@Service
public class HmacProofService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public String computeBase64(String key, String message) {
        return Base64.getEncoder().encodeToString(computeBytes(key, message));
    }

    public boolean matchesBase64(String providedBase64, String key, String message) {
        if (providedBase64 == null || providedBase64.isBlank()) {
            return false;
        }

        byte[] provided;
        try {
            provided = Base64.getDecoder().decode(providedBase64);
        } catch (IllegalArgumentException ex) {
            return false;
        }

        byte[] expected = computeBytes(key, message);
        return MessageDigest.isEqual(expected, provided);
    }

    private byte[] computeBytes(String key, String message) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
            mac.init(secretKeySpec);
            return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Impossible de calculer la preuve HMAC", ex);
        }
    }
}

