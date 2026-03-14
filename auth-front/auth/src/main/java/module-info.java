module com.example.auth {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.net.http;

    opens com.example.auth to javafx.fxml;
    opens com.example.auth.controller to javafx.fxml;

    exports com.example.auth;
    exports com.example.auth.controller;
    exports com.example.auth.service;
    exports com.example.auth.model;
}