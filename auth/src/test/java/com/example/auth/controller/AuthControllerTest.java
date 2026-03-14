package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.PasswordHasher;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void testRegisterSuccess() throws Exception {
        Map<String, String> request = Map.of(
                "email", "test@example.com",
                "password", "Password@123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.createdAt").exists())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void testRegisterWithInvalidEmail() throws Exception {
        Map<String, String> request = Map.of(
                "email", "invalid-email",
                "password", "Password@123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Email invalide"));
    }

    @Test
    void testRegisterWithWeakPassword() throws Exception {
        Map<String, String> request = Map.of(
                "email", "test@example.com",
                "password", "password123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Mot de passe invalide: 12+ caractères, majuscule, minuscule, chiffre, caractère spécial requis"));
    }

    @Test
    void testRegisterDuplicateEmail() throws Exception {
        User user = new User("test@example.com", PasswordHasher.hash("Password@123"));
        userRepository.save(user);

        Map<String, String> request = Map.of(
                "email", "test@example.com",
                "password", "Password@999"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email déjà utilisé"));
    }

    @Test
    void testLoginSuccess() throws Exception {
        User user = new User("test@example.com", PasswordHasher.hash("Password@123"));
        userRepository.save(user);

        Map<String, String> request = Map.of(
                "email", "test@example.com",
                "password", "Password@123"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Connexion réussie"))
                .andExpect(jsonPath("$.email").value("test@example.com"));
    }

    @Test
    void testLoginWithWrongPassword() throws Exception {
        User user = new User("test@example.com", PasswordHasher.hash("Password@123"));
        userRepository.save(user);

        Map<String, String> request = Map.of(
                "email", "test@example.com",
                "password", "WrongPassword@123"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Email ou mot de passe incorrect"));
    }

    @Test
    void testLoginWithNonExistentUser() throws Exception {
        Map<String, String> request = Map.of(
                "email", "nonexistent@example.com",
                "password", "Password@123"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Email ou mot de passe incorrect"));
    }

    @Test
    void testLockoutAfterFiveFailedAttempts() throws Exception {
        User user = new User("test@example.com", PasswordHasher.hash("Password@123"));
        userRepository.save(user);

        Map<String, String> wrongPassword = Map.of(
                "email", "test@example.com",
                "password", "WrongPassword@123"
        );

        for (int i = 0; i < 4; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(wrongPassword)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message").value("Email ou mot de passe incorrect"));
        }

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(wrongPassword)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.message").value("Compte temporairement verrouillé. Réessayez plus tard."));
    }

    @Test
    void testLockedUserCannotLoginEvenWithCorrectPassword() throws Exception {
        User user = new User("test@example.com", PasswordHasher.hash("Password@123"));
        user.setFailedAttempts(5);
        user.setLockUntil(LocalDateTime.now().plusMinutes(1));
        userRepository.save(user);

        Map<String, String> request = Map.of(
                "email", "test@example.com",
                "password", "Password@123"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.message").value("Compte temporairement verrouillé. Réessayez plus tard."));
    }

    @Test
    void testLoginSucceedsAfterLockExpired() throws Exception {
        User user = new User("test@example.com", PasswordHasher.hash("Password@123"));
        user.setFailedAttempts(5);
        user.setLockUntil(LocalDateTime.now().minusSeconds(1));
        userRepository.save(user);

        Map<String, String> request = Map.of(
                "email", "test@example.com",
                "password", "Password@123"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Connexion réussie"));

        User refreshed = userRepository.findByEmail("test@example.com").orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(0, refreshed.getFailedAttempts());
        org.junit.jupiter.api.Assertions.assertNull(refreshed.getLockUntil());
    }
}
