package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    public User register(String email, String password) {

        if (email == null || email.isBlank()) {
            throw new InvalidInputException("Email obligatoire");
        }

        if (!email.contains("@")) {
            throw new InvalidInputException("Email invalide");
        }

        if (password == null || password.length() < 4) {
            throw new InvalidInputException("Mot de passe minimum 4 caractères");
        }

        if (userRepository.findByEmail(email).isPresent()) {
            throw new ResourceConflictException("Email déjà utilisé");
        }

        User user = new User(email, password);
              return userRepository.save(user);

    }
    public boolean login(String email, String password) {
        return userRepository.findByEmail(email)
                .map(user -> user.getPassword().equals(password))
                .orElse(false);

    }
}