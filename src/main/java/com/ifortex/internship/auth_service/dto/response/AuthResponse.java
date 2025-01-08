package com.ifortex.internship.auth_service.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthResponse {
  private CookieTokensResponse cookieTokensResponse;
  private String email;
  private String message;
}
