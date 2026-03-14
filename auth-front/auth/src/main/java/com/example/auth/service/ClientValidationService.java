package com.example.auth.service;

public final class ClientValidationService {

    public enum StrengthLevel {
        RED,
        ORANGE,
        GREEN
    }

    private ClientValidationService() {}

    public static boolean isEmailValid(String email) {
        return email != null
                && !email.isBlank()
                && email.contains("@")
                && email.indexOf('@') > 0
                && email.lastIndexOf('.') > email.indexOf('@') + 1;
    }

    // Même règle métier que TP2 côté serveur.
    public static boolean isPasswordPolicyValid(String password) {
        if (password == null || password.length() < 12) {
            return false;
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else {
                hasSpecial = true;
            }
        }

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    public static StrengthLevel getStrengthLevel(String password) {
        if (password == null || password.isBlank()) {
            return StrengthLevel.RED;
        }

        int score = 0;
        if (password.length() >= 12) {
            score++;
        }
        if (password.length() >= 16) {
            score++;
        }
        if (containsUpper(password)) {
            score++;
        }
        if (containsLower(password)) {
            score++;
        }
        if (containsDigit(password)) {
            score++;
        }
        if (containsSpecial(password)) {
            score++;
        }

        if (!isPasswordPolicyValid(password)) {
            return StrengthLevel.RED;
        }

        // Conforme mais encore "moyen".
        if (score <= 5) {
            return StrengthLevel.ORANGE;
        }

        return StrengthLevel.GREEN;
    }

    public static String strengthLabel(StrengthLevel level) {
        return switch (level) {
            case RED -> "Rouge - non conforme";
            case ORANGE -> "Orange - conforme mais faible";
            case GREEN -> "Vert - conforme et robuste";
        };
    }

    private static boolean containsUpper(String value) {
        return value.chars().anyMatch(Character::isUpperCase);
    }

    private static boolean containsLower(String value) {
        return value.chars().anyMatch(Character::isLowerCase);
    }

    private static boolean containsDigit(String value) {
        return value.chars().anyMatch(Character::isDigit);
    }

    private static boolean containsSpecial(String value) {
        return value.chars().anyMatch(c -> !Character.isLetterOrDigit(c));
    }
}

