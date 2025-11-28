package com.leco.usermanagement.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.List;
import java.util.ArrayList;

@Document(collection = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    private String id;

    private String firstName;
    private String lastName;

    private String email;

    private String password;

    private String lawFirm;

    private boolean enabled;

    private String verificationToken;

    private Instant verificationTokenExpiry;

    private String resetToken;

    private Instant resetTokenExpiry;

    private Instant createdAt;

    @Builder.Default
    private List<String> roles = new ArrayList<>();
}
