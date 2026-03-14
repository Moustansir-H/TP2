package com.example.auth.service;

import com.example.auth.model.ApiResult;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AuthApiClient {

    private static final Pattern MESSAGE_PATTERN = Pattern.compile("\\\"message\\\"\\s*:\\s*\\\"(.*?)\\\"");

    private final HttpClient httpClient;
    private final String baseUrl;

    public AuthApiClient(String baseUrl) {
        this.baseUrl = normalizeBaseUrl(baseUrl);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public ApiResult register(String email, String password) {
        String body = "{"
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"password\":\"" + escapeJson(password) + "\""
                + "}";
        return post("/api/auth/register", body);
    }

    public ApiResult login(String email, String password) {
        String body = "{"
                + "\"email\":\"" + escapeJson(email) + "\","
                + "\"password\":\"" + escapeJson(password) + "\""
                + "}";
        return post("/api/auth/login", body);
    }

    private ApiResult post(String path, String jsonBody) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(8))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            String body = response.body() == null ? "" : response.body();

            if (status >= 200 && status < 300) {
                String successMessage = status == 201 ? "Inscription réussie" : "Connexion réussie";
                return new ApiResult(true, status, successMessage, body);
            }

            String backendMessage = extractMessage(body);
            if (backendMessage == null || backendMessage.isBlank()) {
                backendMessage = "Erreur serveur (" + status + ")";
            }
            return new ApiResult(false, status, backendMessage, body);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return new ApiResult(false, 0, "Requête interrompue", ex.getMessage());
        } catch (IOException ex) {
            return new ApiResult(false, 0, "Impossible de contacter le serveur backend. Vérifie qu'il tourne sur " + baseUrl, ex.getMessage());
        }
    }

    private static String normalizeBaseUrl(String url) {
        if (url == null || url.isBlank()) {
            return "http://localhost:8080";
        }
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String extractMessage(String jsonBody) {
        Matcher matcher = MESSAGE_PATTERN.matcher(jsonBody);
        if (matcher.find()) {
            return matcher.group(1)
                    .replace("\\\"", "\"")
                    .replace("\\n", "\n")
                    .replace("\\r", "\r")
                    .replace("\\t", "\t");
        }
        return null;
    }
}
