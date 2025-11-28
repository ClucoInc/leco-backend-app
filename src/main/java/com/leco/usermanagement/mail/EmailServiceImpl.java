package com.leco.usermanagement.mail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class EmailServiceImpl implements EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailServiceImpl.class);

    private final JavaMailSender mailSender;

    @Value("${app.frontend.base-url:http://localhost:5173}")
    private String frontendBaseUrl;

    @Value("${app.mail.from:}")
    private String fromAddress;

    @Value("${app.mail.log-only:true}")
    private boolean logOnlyMode;

    public EmailServiceImpl(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public void sendVerificationEmail(String to, String token) {
        String link = frontendBaseUrl + "/verify-email?token=" + token;
        String body = "Please verify your email by visiting: " + link + "\nIf you did not request this, ignore.";
        dispatch(to, "Leco — Verify your email", body);
    }

    @Override
    public void sendResetEmail(String to, String token) {
        String link = frontendBaseUrl + "/reset-password?token=" + token;
        String body = "Reset your password by visiting: " + link + "\nIf you did not request this, ignore.";
        dispatch(to, "Leco — Password reset", body);
    }

    private void dispatch(String to, String subject, String body) {
        if (logOnlyMode) {
            log.info("[mail:log-only] to={} subject=\"{}\" body={}", to, subject, body);
            return;
        }

        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(to);
        if (StringUtils.hasText(fromAddress)) {
            msg.setFrom(fromAddress);
        }
        msg.setSubject(subject);
        msg.setText(body);

        try {
            mailSender.send(msg);
            log.info("Sent mail '{}' to {}", subject, to);
        } catch (MailException ex) {
            log.error("Failed sending mail '{}' to {}: {}", subject, to, ex.getMessage(), ex);
            throw ex;
        }
    }
}
