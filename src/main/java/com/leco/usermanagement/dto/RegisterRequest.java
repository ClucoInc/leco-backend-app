package com.leco.usermanagement.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RegisterRequest {
    @NotBlank
    private String firstName;
    @NotBlank
    private String lastName;
    @Email
    @NotBlank
    private String email;
    @NotBlank
    private String password;
    private String lawFirm;
    private String captchaToken;
    private String role; // optional: ROLE_ATTORNEY or ROLE_ADMIN
}
