package com.leco.usermanagement.service;

import com.leco.usermanagement.dto.AuthResponse;
import com.leco.usermanagement.dto.LoginRequest;
import com.leco.usermanagement.dto.RegisterRequest;

public interface UserService {
    AuthResponse register(RegisterRequest req);
    AuthResponse login(LoginRequest req);
    void requestPasswordReset(String email);
    void resetPassword(String token, String newPassword);
    boolean verifyEmail(String token);
    boolean verifyCaptcha(String captchaToken);
}
