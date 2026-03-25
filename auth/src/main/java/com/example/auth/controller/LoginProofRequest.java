package com.example.auth.controller;

public record LoginProofRequest(String email, String nonce, Long timestamp, String hmac) {
}

