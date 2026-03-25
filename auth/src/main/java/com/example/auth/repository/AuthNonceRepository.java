package com.example.auth.repository;

import com.example.auth.entity.AuthNonce;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;

public interface AuthNonceRepository extends JpaRepository<AuthNonce, Long> {

    boolean existsByUserIdAndNonceValue(Long userId, String nonceValue);

    void deleteByExpiresAtBefore(LocalDateTime now);
}

