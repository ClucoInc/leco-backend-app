package com.leco.usermanagement.mail;

public interface EmailService {
    void sendVerificationEmail(String to, String token);
    void sendResetEmail(String to, String token);
}
