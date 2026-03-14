package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AccountLockedException;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(2);
    private static final String GENERIC_LOGIN_ERROR = "Email ou mot de passe incorrect";

    private final UserRepository userRepository;

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

        User user = new User(email, PasswordHasher.hash(password));
        User saved = userRepository.save(user);
        log.info("Inscription réussie pour {}", email);
        return saved;

    }

    public void login(String email, String password) {
        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            throw new InvalidInputException("Email et mot de passe obligatoires");
        }

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            log.warn("Connexion échouée pour {}", email);
            throw new AuthenticationFailedException(GENERIC_LOGIN_ERROR);
        }

        LocalDateTime now = LocalDateTime.now();

        if (user.isLocked(now)) {
            log.warn("Connexion bloquée (compte verrouillé) pour {}", email);
            throw new AccountLockedException("Compte temporairement verrouillé. Réessayez plus tard.");
        }

        // Si le verrouillage a expiré, on repart proprement.
        if (user.getLockUntil() != null && !user.isLocked(now)) {
            user.clearLockState();
        }

        if (PasswordHasher.verify(password, user.getPasswordHash())) {
            user.clearLockState();
            userRepository.save(user);
            log.info("Connexion réussie pour {}", email);
            return;
        }

        user.recordFailedAttempt(now, MAX_FAILED_ATTEMPTS, LOCK_DURATION);
        userRepository.save(user);

        if (user.isLocked(now)) {
            log.warn("Connexion échouée puis verrouillage activé pour {}", email);
            throw new AccountLockedException("Compte temporairement verrouillé. Réessayez plus tard.");
        }

        log.warn("Connexion échouée pour {}", email);
        throw new AuthenticationFailedException(GENERIC_LOGIN_ERROR);

    }
}