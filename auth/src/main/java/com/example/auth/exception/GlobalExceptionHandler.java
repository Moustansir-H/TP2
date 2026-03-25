package com.example.auth.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.converter.HttpMessageNotReadableException;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Gestion globale des exceptions.
 * Cette implémentation est volontairement dangereuse et ne doit jamais être utilisée en production.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidInput(
            InvalidInputException ex,
            HttpServletRequest request) {

        return buildResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }

    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<Map<String, Object>> handleAuthFailed(
            AuthenticationFailedException ex,
            HttpServletRequest request) {

        return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            AccountLockedException ex,
            HttpServletRequest request) {

        return buildResponse(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage(), request);
    }

    @ExceptionHandler(ResourceConflictException.class)
    public ResponseEntity<Map<String, Object>> handleConflict(
            ResourceConflictException ex,
            HttpServletRequest request) {

        return buildResponse(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadableBody(
            HttpServletRequest request) {

        return buildResponse(HttpStatus.BAD_REQUEST, "Payload JSON invalide", request);
    }

    private ResponseEntity<Map<String, Object>> buildResponse(
            HttpStatus status,
            String message,
            HttpServletRequest request) {

        Map<String, Object> body = new HashMap<>();

        body.put("timestamp", LocalDateTime.now());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", request.getRequestURI());

        return new ResponseEntity<>(body, status);
    }
}