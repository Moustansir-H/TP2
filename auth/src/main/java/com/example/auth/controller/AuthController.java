package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import com.example.auth.service.LoginResult;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final String EMAIL_KEY = "email";
    private static final String PASSWORD_KEY = "password";
    private static final String MESSAGE_KEY = "message";
    private static final String TOKEN_KEY = "accessToken";
    private static final String EXPIRES_AT_KEY = "expiresAt";

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, String> request) {
        String email = request.get(EMAIL_KEY);
        String password = request.get(PASSWORD_KEY);

        User user = authService.register(email, password);
        return new ResponseEntity<>(Map.of(
                "id", user.getId(),
                EMAIL_KEY, user.getEmail(),
                "createdAt", user.getCreatedAt()
        ), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginProofRequest request) {
        LoginResult login = authService.loginWithProof(
                request.email(),
                request.nonce(),
                request.timestamp(),
                request.hmac()
        );

        return ResponseEntity.ok(Map.of(
                MESSAGE_KEY, "Connexion réussie",
                EMAIL_KEY, login.email(),
                TOKEN_KEY, login.accessToken(),
                EXPIRES_AT_KEY, login.expiresAt()
        ));
    }
}
