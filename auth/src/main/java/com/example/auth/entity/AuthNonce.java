package com.example.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "auth_nonce",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "nonce_value"})
)
public class AuthNonce {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "nonce_value", nullable = false, length = 128)
    private String nonceValue;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private boolean consumed;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    public AuthNonce() {
    }

    public AuthNonce(User user, String nonceValue, LocalDateTime expiresAt) {
        this.user = user;
        this.nonceValue = nonceValue;
        this.expiresAt = expiresAt;
        this.consumed = false;
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public String getNonceValue() {
        return nonceValue;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public boolean isConsumed() {
        return consumed;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void markConsumed() {
        this.consumed = true;
    }
}

