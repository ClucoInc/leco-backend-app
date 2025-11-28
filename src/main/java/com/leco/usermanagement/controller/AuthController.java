package com.leco.usermanagement.controller;

import com.leco.usermanagement.dto.AuthResponse;
import com.leco.usermanagement.dto.LoginRequest;
import com.leco.usermanagement.dto.RegisterRequest;
import com.leco.usermanagement.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest req) {
        AuthResponse res = userService.register(req);
        return ResponseEntity.ok(res);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req) {
        AuthResponse res = userService.login(req);
        return ResponseEntity.ok(res);
    }

    @PostMapping("/request-reset")
    public ResponseEntity<Void> requestReset(@RequestParam String email) {
        userService.requestPasswordReset(email);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/verify-email")
    public ResponseEntity<Void> verifyEmail(@RequestParam String token) {
        boolean ok = userService.verifyEmail(token);
        return ok ? ResponseEntity.ok().build() : ResponseEntity.badRequest().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
        try {
            userService.resetPassword(token, newPassword);
            return ResponseEntity.ok().build();
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/verify-captcha")
    public ResponseEntity<Void> verifyCaptcha(@RequestParam(required = false) String captchaToken) {
        boolean ok = userService.verifyCaptcha(captchaToken);
        return ok ? ResponseEntity.ok().build() : ResponseEntity.status(422).build();
    }
}
