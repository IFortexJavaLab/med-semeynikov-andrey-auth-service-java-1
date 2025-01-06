package com.ifortex.internship.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PasswordResetTokenValidationDto {
    @NotBlank
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Token is required")
    private String token;
}
