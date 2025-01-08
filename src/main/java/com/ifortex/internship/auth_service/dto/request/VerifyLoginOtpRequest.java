package com.ifortex.internship.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class VerifyLoginOtpRequest {

  @Email(message = "Invalid email format")
  @NotBlank(message = "Email is required")
  private String email;

  @NotBlank(message = "One time password is required")
  @Pattern(regexp = "\\d{6}", message = "One time password must consist of exactly 6 digits")
  private String otp;
}
