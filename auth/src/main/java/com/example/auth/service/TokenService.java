package com.example.auth.service;

import com.example.auth.entity.AuthToken;
import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.repository.AuthTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {

    private static final String INVALID_TOKEN_MESSAGE = "Token invalide ou expiré";

    private final AuthTokenRepository authTokenRepository;
    private final AuthSecurityProperties securityProperties;

    public LoginResult issueToken(User user) {
        LocalDateTime now = LocalDateTime.now();
        authTokenRepository.deleteByExpiresAtBefore(now);

        LocalDateTime expiresAt = now.plusSeconds(securityProperties.getTokenTtlSeconds());
        String tokenValue = UUID.randomUUID().toString();

        authTokenRepository.save(new AuthToken(user, tokenValue, expiresAt));
        return new LoginResult(tokenValue, expiresAt, user.getEmail());
    }

    public User authenticate(String tokenValue) {
        LocalDateTime now = LocalDateTime.now();
        authTokenRepository.deleteByExpiresAtBefore(now);

        AuthToken token = authTokenRepository.findByTokenValue(tokenValue)
                .orElseThrow(() -> new AuthenticationFailedException(INVALID_TOKEN_MESSAGE));

        if (token.isExpired(now)) {
            throw new AuthenticationFailedException(INVALID_TOKEN_MESSAGE);
        }

        return token.getUser();
    }
}

