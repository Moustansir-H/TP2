package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.HmacProofService;
import com.example.auth.service.PasswordCipherService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    private static final String REGISTER_URL = "/api/auth/register";
    private static final String LOGIN_URL = "/api/auth/login";
    private static final String ME_URL = "/api/me";

    private static final String EMAIL_KEY = "email";
    private static final String PASSWORD_KEY = "password";
    private static final String NONCE_KEY = "nonce";
    private static final String TIMESTAMP_KEY = "timestamp";
    private static final String HMAC_KEY = "hmac";

    private static final String JSON_EMAIL = "$.email";
    private static final String JSON_MESSAGE = "$.message";
    private static final String JSON_ACCESS_TOKEN = "$.accessToken";

    private static final String TEST_EMAIL = "test@example.com";
    private static final String SECOND_EMAIL = "other@example.com";
    private static final String INVALID_EMAIL = "invalid-email";

    private static final String VALID_PASSWORD = "Password@123";
    private static final String OTHER_VALID_PASSWORD = "Password@999";
    private static final String WEAK_PASSWORD = "password123";

    private static final String LOGIN_SUCCESS_MESSAGE = "Connexion réussie";
    private static final String INVALID_EMAIL_MESSAGE = "Email invalide";
    private static final String DUPLICATE_EMAIL_MESSAGE = "Email déjà utilisé";
    private static final String INVALID_CREDENTIALS_MESSAGE = "Email ou mot de passe incorrect";
    private static final String LOCKED_MESSAGE = "Compte temporairement verrouillé. Réessayez plus tard.";
    private static final String WEAK_PASSWORD_MESSAGE = "Mot de passe invalide: 12+ caractères, majuscule, minuscule, chiffre, caractère spécial requis";
    private static final String INVALID_TOKEN_MESSAGE = "Token invalide ou expiré";

    private final MockMvc mockMvc;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;
    private final PasswordCipherService passwordCipherService;
    private final HmacProofService hmacProofService;

    @Autowired
    AuthControllerTest(
            MockMvc mockMvc,
            UserRepository userRepository,
            ObjectMapper objectMapper,
            PasswordCipherService passwordCipherService,
            HmacProofService hmacProofService
    ) {
        this.mockMvc = mockMvc;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
        this.passwordCipherService = passwordCipherService;
        this.hmacProofService = hmacProofService;
    }

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void testRegisterSuccess() throws Exception {
        mockMvc.perform(postJson(REGISTER_URL, registerRequest(TEST_EMAIL, VALID_PASSWORD)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath(JSON_EMAIL).value(TEST_EMAIL))
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.createdAt").exists())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void testRegisterWithInvalidEmail() throws Exception {
        mockMvc.perform(postJson(REGISTER_URL, registerRequest(INVALID_EMAIL, VALID_PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath(JSON_MESSAGE).value(INVALID_EMAIL_MESSAGE));
    }

    @Test
    void testRegisterWithWeakPassword() throws Exception {
        mockMvc.perform(postJson(REGISTER_URL, registerRequest(TEST_EMAIL, WEAK_PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath(JSON_MESSAGE).value(WEAK_PASSWORD_MESSAGE));
    }

    @Test
    void testRegisterDuplicateEmail() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        mockMvc.perform(postJson(REGISTER_URL, registerRequest(TEST_EMAIL, OTHER_VALID_PASSWORD)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath(JSON_MESSAGE).value(DUPLICATE_EMAIL_MESSAGE));
    }

    @Test
    void testLoginOkWithValidHmac() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        long timestamp = nowEpochSeconds();
        String nonce = randomNonce();
        Map<String, Object> request = loginRequest(TEST_EMAIL, VALID_PASSWORD, nonce, timestamp);

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isOk())
                .andExpect(jsonPath(JSON_MESSAGE).value(LOGIN_SUCCESS_MESSAGE))
                .andExpect(jsonPath(JSON_EMAIL).value(TEST_EMAIL))
                .andExpect(jsonPath(JSON_ACCESS_TOKEN).exists())
                .andExpect(jsonPath("$.expiresAt").exists());
    }

    @Test
    void testLoginKoWhenHmacInvalid() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        long timestamp = nowEpochSeconds();
        String nonce = randomNonce();
        Map<String, Object> request = Map.of(
                EMAIL_KEY, TEST_EMAIL,
                NONCE_KEY, nonce,
                TIMESTAMP_KEY, timestamp,
                HMAC_KEY, "invalid-base64=="
        );

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath(JSON_MESSAGE).value(INVALID_CREDENTIALS_MESSAGE));
    }

    @Test
    void testLoginKoWhenUserUnknown() throws Exception {
        long timestamp = nowEpochSeconds();
        String nonce = randomNonce();
        Map<String, Object> request = loginRequest(SECOND_EMAIL, VALID_PASSWORD, nonce, timestamp);

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath(JSON_MESSAGE).value(INVALID_CREDENTIALS_MESSAGE));
    }

    @Test
    void testLoginKoWhenTimestampExpired() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        long oldTimestamp = nowEpochSeconds() - 120;
        Map<String, Object> request = loginRequest(TEST_EMAIL, VALID_PASSWORD, randomNonce(), oldTimestamp);

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath(JSON_MESSAGE).value(INVALID_CREDENTIALS_MESSAGE));
    }

    @Test
    void testLoginKoWhenTimestampTooFuture() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        long futureTimestamp = nowEpochSeconds() + 120;
        Map<String, Object> request = loginRequest(TEST_EMAIL, VALID_PASSWORD, randomNonce(), futureTimestamp);

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath(JSON_MESSAGE).value(INVALID_CREDENTIALS_MESSAGE));
    }

    @Test
    void testLoginKoWhenNonceReused() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        long timestamp = nowEpochSeconds();
        String nonce = randomNonce();
        Map<String, Object> request = loginRequest(TEST_EMAIL, VALID_PASSWORD, nonce, timestamp);

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isOk());

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath(JSON_MESSAGE).value(INVALID_CREDENTIALS_MESSAGE));
    }

    @Test
    void testTokenIssuedAndMeAccessOk() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        long timestamp = nowEpochSeconds();
        Map<String, Object> request = loginRequest(TEST_EMAIL, VALID_PASSWORD, randomNonce(), timestamp);

        MvcResult loginResult = mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isOk())
                .andReturn();

        String token = objectMapper.readTree(loginResult.getResponse().getContentAsString()).get("accessToken").asText();

        mockMvc.perform(get(ME_URL).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath(JSON_EMAIL).value(TEST_EMAIL));
    }

    @Test
    void testMeAccessKoWithoutToken() throws Exception {
        mockMvc.perform(get(ME_URL))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath(JSON_MESSAGE).value(INVALID_TOKEN_MESSAGE));
    }

    @Test
    void testMeAccessKoWithInvalidToken() throws Exception {
        mockMvc.perform(get(ME_URL).header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath(JSON_MESSAGE).value(INVALID_TOKEN_MESSAGE));
    }

    @Test
    void testLockoutAfterFiveInvalidProofs() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        for (int i = 0; i < 4; i++) {
            mockMvc.perform(postJson(LOGIN_URL, invalidHmacRequest(TEST_EMAIL)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath(JSON_MESSAGE).value(INVALID_CREDENTIALS_MESSAGE));
        }

        mockMvc.perform(postJson(LOGIN_URL, invalidHmacRequest(TEST_EMAIL)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath(JSON_MESSAGE).value(LOCKED_MESSAGE));
    }

    @Test
    void testLockedUserCannotLoginWithValidProof() throws Exception {
        User user = createUser(TEST_EMAIL, VALID_PASSWORD);
        user.setFailedAttempts(5);
        user.setLockUntil(LocalDateTime.now().plusMinutes(1));
        userRepository.save(user);

        Map<String, Object> request = loginRequest(TEST_EMAIL, VALID_PASSWORD, randomNonce(), nowEpochSeconds());

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath(JSON_MESSAGE).value(LOCKED_MESSAGE));
    }

    @Test
    void testLoginSucceedsAfterLockExpired() throws Exception {
        User user = createUser(TEST_EMAIL, VALID_PASSWORD);
        user.setFailedAttempts(5);
        user.setLockUntil(LocalDateTime.now().minusSeconds(1));
        userRepository.save(user);

        Map<String, Object> request = loginRequest(TEST_EMAIL, VALID_PASSWORD, randomNonce(), nowEpochSeconds());

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isOk())
                .andExpect(jsonPath(JSON_MESSAGE).value(LOGIN_SUCCESS_MESSAGE));

        User refreshed = userRepository.findByEmail(TEST_EMAIL).orElseThrow();
        Assertions.assertEquals(0, refreshed.getFailedAttempts());
        Assertions.assertNull(refreshed.getLockUntil());
    }

    @Test
    void testLoginKoWhenNonceMissing() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        Map<String, Object> request = Map.of(
                EMAIL_KEY, TEST_EMAIL,
                TIMESTAMP_KEY, nowEpochSeconds(),
                HMAC_KEY, "abc"
        );

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath(JSON_MESSAGE).value("Email, nonce, timestamp et hmac obligatoires"));
    }

    @Test
    void testLoginKoWhenTimestampMissing() throws Exception {
        userRepository.save(createUser(TEST_EMAIL, VALID_PASSWORD));

        Map<String, Object> request = Map.of(
                EMAIL_KEY, TEST_EMAIL,
                NONCE_KEY, randomNonce(),
                HMAC_KEY, "abc"
        );

        mockMvc.perform(postJson(LOGIN_URL, request))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath(JSON_MESSAGE).value("Email, nonce, timestamp et hmac obligatoires"));
    }

    private Map<String, String> registerRequest(String email, String password) {
        return Map.of(
                EMAIL_KEY, email,
                PASSWORD_KEY, password
        );
    }

    private Map<String, Object> loginRequest(String email, String password, String nonce, long timestamp) {
        String message = email + ":" + nonce + ":" + timestamp;
        String hmac = hmacProofService.computeBase64(password, message);

        return Map.of(
                EMAIL_KEY, email,
                NONCE_KEY, nonce,
                TIMESTAMP_KEY, timestamp,
                HMAC_KEY, hmac
        );
    }

    private Map<String, Object> invalidHmacRequest(String email) {
        return Map.of(
                EMAIL_KEY, email,
                NONCE_KEY, randomNonce(),
                TIMESTAMP_KEY, nowEpochSeconds(),
                HMAC_KEY, "invalid-base64=="
        );
    }

    private MockHttpServletRequestBuilder postJson(String url, Map<String, ?> payload) throws Exception {
        return post(url)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(payload));
    }

    private User createUser(String email, String rawPassword) {
        return new User(email, passwordCipherService.encrypt(rawPassword));
    }

    private long nowEpochSeconds() {
        return System.currentTimeMillis() / 1000;
    }

    private String randomNonce() {
        return UUID.randomUUID().toString();
    }
}
