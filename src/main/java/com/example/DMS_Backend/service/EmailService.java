package com.example.DMS_Backend.service;

public interface EmailService {
    void sendCredentialsEmail(String to, String firstName, String username, String password, String accountType);
}
