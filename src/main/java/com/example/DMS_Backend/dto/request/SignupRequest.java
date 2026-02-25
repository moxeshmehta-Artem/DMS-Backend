package com.example.DMS_Backend.dto.request;

import jakarta.validation.constraints.Pattern;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Email;
import lombok.Data;

@Data
public class SignupRequest {
    @NotBlank
    private String username;
    @NotBlank
    @Email
    private String email;
    @NotBlank
    private String password;
    @NotBlank
    private String role;

    private java.time.LocalDate dateOfBirth;

    @Pattern(regexp = "^[a-zA-Z ]*$", message = "First name must not contain numbers")
    private String firstName;
    @Pattern(regexp = "^[a-zA-Z ]*$", message = "Last name must not contain numbers")
    private String lastName;
    private String gender;
    private String phone;
}
