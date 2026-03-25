package com.example.auth.service;

import java.time.LocalDateTime;

public record LoginResult(String accessToken, LocalDateTime expiresAt, String email) {
}

