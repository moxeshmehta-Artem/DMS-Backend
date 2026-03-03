package com.example.DMS_Backend.service.impl;

import com.example.DMS_Backend.service.EmailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EmailServiceImpl implements EmailService {

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private JavaMailSender mailSender;

    @Override
    public void sendCredentialsEmail(String to, String firstName, String username, String password) {
        String subject = "Your Dietitian Credentials - DMS";
        String content = String.format(
                "Hello %s,\n\n" +
                        "Your dietitian account has been created successfully.\n\n" +
                        "Email ID: %s\n" +
                        "Username: %s\n" +
                        "Password: %s\n\n",
                firstName, to, username, password);

        try {
            if (mailSender == null) {
                throw new IllegalStateException("JavaMailSender is not configured. Falling back to mock logging.");
            }
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject(subject);
            message.setText(content);
            mailSender.send(message);

            log.info("Credentials email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send email to: {}. Error: {}", to, e.getMessage());
            // In development, we log the credentials if email fails
            log.warn("MOCK EMAIL [DEVELOPMENT]:\nTo: {}\nSubject: {}\nContent: \n{}", to, subject, content);
        }
    }
}
