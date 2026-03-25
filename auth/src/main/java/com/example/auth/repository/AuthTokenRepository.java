package com.example.auth.repository;

import com.example.auth.entity.AuthToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.Optional;

public interface AuthTokenRepository extends JpaRepository<AuthToken, Long> {

    Optional<AuthToken> findByTokenValue(String tokenValue);

    void deleteByExpiresAtBefore(LocalDateTime now);
}

