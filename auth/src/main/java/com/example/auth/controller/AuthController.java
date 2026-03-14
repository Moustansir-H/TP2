package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String password = request.get("password");

        User user = authService.register(email, password);
        return new ResponseEntity<>(Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "createdAt", user.getCreatedAt()
        ), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String password = request.get("password");

        authService.login(email, password);

        return ResponseEntity.ok(Map.of(
                "message", "Connexion réussie",
                "email", email
        ));
    }
}
