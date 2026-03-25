package com.example.auth.service;

import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import com.example.auth.exception.AccountLockedException;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(1);
    private static final String GENERIC_LOGIN_ERROR = "Email ou mot de passe incorrect";

    private final UserRepository userRepository;
    private final AuthNonceRepository authNonceRepository;
    private final PasswordCipherService passwordCipherService;
    private final HmacProofService hmacProofService;
    private final TokenService tokenService;
    private final AuthSecurityProperties securityProperties;

    public User register(String email, String password) {

        if (email == null || email.isBlank()) {
            throw new InvalidInputException("Email obligatoire");
        }

        if (!email.contains("@")) {
            throw new InvalidInputException("Email invalide");
        }

        if (!PasswordPolicyValidator.isValid(password)) {
            throw new InvalidInputException("Mot de passe invalide: 12+ caractères, majuscule, minuscule, chiffre, caractère spécial requis");
        }

        if (userRepository.findByEmail(email).isPresent()) {
            throw new ResourceConflictException("Email déjà utilisé");
        }

        User user = new User(email, passwordCipherService.encrypt(password));
        User saved = userRepository.save(user);
        log.info("Inscription réussie pour {}", email);
        return saved;

    }

    public LoginResult loginWithProof(String email, String nonce, Long timestamp, String hmac) {
        if (email == null || email.isBlank() || nonce == null || nonce.isBlank() || timestamp == null || hmac == null || hmac.isBlank()) {
            throw new InvalidInputException("Email, nonce, timestamp et hmac obligatoires");
        }

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            log.warn("Connexion échouée pour {}", email);
            throw new AuthenticationFailedException(GENERIC_LOGIN_ERROR);
        }

        LocalDateTime now = LocalDateTime.now();
        authNonceRepository.deleteByExpiresAtBefore(now);

        if (user.isLocked(now)) {
            log.warn("Connexion bloquée (compte verrouillé) pour {}", email);
            throw new AccountLockedException("Compte temporairement verrouillé. Réessayez plus tard.");
        }

        if (user.getLockUntil() != null && !user.isLocked(now)) {
            user.clearLockState();
        }

        if (!isTimestampInWindow(timestamp, Instant.now().getEpochSecond())) {
            throw new AuthenticationFailedException(GENERIC_LOGIN_ERROR);
        }

        if (authNonceRepository.existsByUserIdAndNonceValue(user.getId(), nonce)) {
            throw new AuthenticationFailedException(GENERIC_LOGIN_ERROR);
        }

        AuthNonce authNonce = authNonceRepository.save(
                new AuthNonce(user, nonce, now.plusSeconds(securityProperties.getNonceTtlSeconds()))
        );

        String message = buildMessage(email, nonce, timestamp);
        String plainSecret = passwordCipherService.decrypt(user.getPasswordEncrypted());
        boolean validProof = hmacProofService.matchesBase64(hmac, plainSecret, message);

        authNonce.markConsumed();
        authNonceRepository.save(authNonce);

        if (validProof) {
            user.clearLockState();
            userRepository.save(user);
            log.info("Connexion réussie pour {}", email);
            return tokenService.issueToken(user);
        }

        user.recordFailedAttempt(now, MAX_FAILED_ATTEMPTS, LOCK_DURATION);
        userRepository.save(user);

        if (user.isLocked(now)) {
            log.warn("Connexion échouée puis verrouillage activé pour {}", email);
            throw new AccountLockedException("Compte temporairement verrouillé. Réessayez plus tard.");
        }

        log.warn("Connexion échouée (preuve invalide) pour {}", email);
        throw new AuthenticationFailedException(GENERIC_LOGIN_ERROR);
    }

    public User getUserFromToken(String tokenValue) {
        return tokenService.authenticate(tokenValue);
    }

    private boolean isTimestampInWindow(long timestamp, long nowEpochSeconds) {
        long skew = Math.abs(nowEpochSeconds - timestamp);
        return skew <= securityProperties.getTimestampWindowSeconds();
    }

    private String buildMessage(String email, String nonce, long timestamp) {
        return email + ":" + nonce + ":" + timestamp;
    }
}