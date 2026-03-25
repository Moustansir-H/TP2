package com.example.auth.service;

import com.example.auth.exception.InvalidInputException;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class PasswordCipherService {

    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_SIZE_BYTES = 12;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecretKeySpec secretKey;

    public PasswordCipherService(AuthSecurityProperties securityProperties) {
        this.secretKey = new SecretKeySpec(buildKeyBytes(securityProperties.getServerMasterKey()), "AES");
    }

    public String encrypt(String plainPassword) {
        if (plainPassword == null || plainPassword.isBlank()) {
            throw new InvalidInputException("Mot de passe obligatoire");
        }

        try {
            byte[] iv = new byte[IV_SIZE_BYTES];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(plainPassword.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Impossible de chiffrer le mot de passe", ex);
        }
    }

    public String decrypt(String encryptedPassword) {
        if (encryptedPassword == null || encryptedPassword.isBlank()) {
            throw new InvalidInputException("Mot de passe chiffré invalide");
        }

        String[] parts = encryptedPassword.split(":", 2);
        if (parts.length != 2) {
            throw new InvalidInputException("Format de mot de passe chiffré invalide");
        }

        try {
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encrypted = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] plain = cipher.doFinal(encrypted);

            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new InvalidInputException("Impossible de déchiffrer le secret utilisateur");
        }
    }

    private byte[] buildKeyBytes(String serverMasterKey) {
        try {
            return MessageDigest
                    .getInstance("SHA-256")
                    .digest(serverMasterKey.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Impossible d'initialiser la clé serveur", ex);
        }
    }
}
