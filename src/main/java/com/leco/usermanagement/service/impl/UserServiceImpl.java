package com.leco.usermanagement.service.impl;

import com.leco.usermanagement.dto.AuthResponse;
import com.leco.usermanagement.dto.LoginRequest;
import com.leco.usermanagement.dto.RegisterRequest;
import com.leco.usermanagement.entity.User;
import com.leco.usermanagement.repository.UserRepository;
import com.leco.usermanagement.security.JwtUtils;
import com.leco.usermanagement.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepository;
    private final org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
    private final com.leco.usermanagement.mail.EmailService emailService;

    private final JwtUtils jwtUtils;

    // Fixed: added closing brace '}' in the annotation
    @Value("${app.tokens.verification-expiry-minutes:1440}")
    private long verificationExpiryMinutes;

    @Value("${app.tokens.reset-expiry-minutes:60}")
    private long resetExpiryMinutes;

    // Add JWT expiration property so we can pass it to JwtUtils.generateToken
    @Value("${app.jwt.expiration-ms:3600000}")
    private long jwtExpirationMs;

    public UserServiceImpl(UserRepository userRepository,
                           org.springframework.security.crypto.password.PasswordEncoder passwordEncoder,
                           com.leco.usermanagement.mail.EmailService emailService,
                           JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.jwtUtils = jwtUtils;
    }

    @Override
    public AuthResponse register(RegisterRequest req) {
        Optional<User> existing = userRepository.findByEmail(req.getEmail());
        if (existing.isPresent()) {
            throw new IllegalArgumentException("Email already registered");
        }

        User u = User.builder()
                .firstName(req.getFirstName())
                .lastName(req.getLastName())
                .email(req.getEmail())
                .lawFirm(req.getLawFirm())
                .password(passwordEncoder.encode(req.getPassword()))
                .enabled(false)
                .verificationToken(UUID.randomUUID().toString())
                .createdAt(Instant.now())
                .build();

        // determine role
        String requested = req.getRole();
        if (requested != null && requested.equalsIgnoreCase("admin")) {
            u.getRoles().add("ROLE_ADMIN");
        } else {
            u.getRoles().add("ROLE_ATTORNEY");
        }

        // set verification expiry and save
        u.setVerificationTokenExpiry(Instant.now().plus(java.time.Duration.ofMinutes(verificationExpiryMinutes)));
        userRepository.save(u);

        // send verification email (demo)
        try {
            emailService.sendVerificationEmail(u.getEmail(), u.getVerificationToken());
        } catch (Exception ex) {
            log.warn("Unable to send verification email to {}: {}", u.getEmail(), ex.getMessage());
        }

        // Pass the expiration to the token generator
        String token = jwtUtils.generateToken(u.getEmail(), u.getRoles(), jwtExpirationMs);
        return new AuthResponse(token);
    }

    @Override
    public AuthResponse login(LoginRequest req) {
        User user = userRepository.findByEmail(req.getEmail()).orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));
        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid credentials");
        }
        if (!user.isEnabled()) {
            throw new IllegalStateException("Email not verified");
        }
        // ensure some role exists
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.getRoles().add("ROLE_ATTORNEY");
            userRepository.save(user);
        }

        // Pass the expiration to the token generator
        String token = jwtUtils.generateToken(user.getEmail(), user.getRoles(), jwtExpirationMs);
        return new AuthResponse(token);
    }

    @Override
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setResetToken(UUID.randomUUID().toString());
        user.setResetTokenExpiry(Instant.now().plusSeconds(resetExpiryMinutes * 60));
        userRepository.save(user);
        // send reset email (demo)
        try {
            emailService.sendResetEmail(user.getEmail(), user.getResetToken());
        } catch (Exception ex) {
            log.warn("Unable to send reset email to {}: {}", user.getEmail(), ex.getMessage());
        }
    }

    @Override
    public void resetPassword(String token, String newPassword) {
        User user = userRepository.findByResetToken(token).orElseThrow(() -> new IllegalArgumentException("Invalid token"));
        if (user.getResetTokenExpiry() == null || Instant.now().isAfter(user.getResetTokenExpiry())) {
            throw new IllegalArgumentException("Reset token expired");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        userRepository.save(user);
    }

    @Override
    public boolean verifyEmail(String token) {
        Optional<User> u = userRepository.findByVerificationToken(token);
        if (u.isPresent()) {
            User user = u.get();
            if (user.getVerificationTokenExpiry() == null || Instant.now().isAfter(user.getVerificationTokenExpiry())) {
                return false; // expired
            }
            user.setEnabled(true);
            user.setVerificationToken(null);
            user.setVerificationTokenExpiry(null);
            userRepository.save(user);
            return true;
        }
        return false;
    }

    @Override
    public boolean verifyCaptcha(String captchaToken) {
        // For demo: accept any non-empty token. Replace with real captcha verification (reCAPTCHA, hcaptcha) call.
        return captchaToken != null && !captchaToken.isBlank();
    }

}