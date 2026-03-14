package com.example.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.Duration;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private int failedAttempts;

    private LocalDateTime lockUntil;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    public User() {}

    public User(String email, String passwordHash) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.failedAttempts = 0;
        this.createdAt = LocalDateTime.now();
    }

    public boolean isLocked(LocalDateTime now) {
        return lockUntil != null && lockUntil.isAfter(now);
    }

    public void recordFailedAttempt(LocalDateTime now, int maxAttempts, Duration lockDuration) {
        this.failedAttempts++;
        if (this.failedAttempts >= maxAttempts) {
            this.lockUntil = now.plus(lockDuration);
        }
    }

    public void clearLockState() {
        this.failedAttempts = 0;
        this.lockUntil = null;
    }

    // Utilisé seulement dans les tests pour simuler l'expiration d'un lockout.
    public void setLockUntil(LocalDateTime lockUntil) {
        this.lockUntil = lockUntil;
    }

    // Utilisé seulement dans les tests pour préparer un état d'échec.
    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }
}
