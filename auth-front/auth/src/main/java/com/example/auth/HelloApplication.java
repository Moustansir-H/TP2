package com.example.auth;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class HelloApplication extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("auth-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 700, 520);
        stage.setTitle("TP2 - Client Auth");
        stage.setScene(scene);
        stage.show();
    }
}
