package com.ifortex.internship.authservice.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ChangePasswordRequest {

  @NotBlank private String currentPassword;

  @NotBlank
  @Size(min = 8, message = "Password must be at least 8 characters long.")
  @Pattern(
      regexp = "^(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]+$",
      message =
          "Password must contain at least 1 uppercase letter, 1 number, and 1 special character.")
  private String newPassword;

  @NotBlank private String passwordConfirmation;
}
