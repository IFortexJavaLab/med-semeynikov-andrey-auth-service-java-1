package com.ifortex.internship.auth_service.model.constant;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum RedisKeyPrefix {
  LOGIN_OTP("login_otp:"),
  PASSWORD_RESET("password_reset_otp:");

  private final String prefix;
}
