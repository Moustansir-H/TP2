package com.example.auth.model;

public record ApiResult(boolean success, int statusCode, String message, String rawBody) {
}

