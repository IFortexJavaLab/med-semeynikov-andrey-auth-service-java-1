package com.ifortex.internship.authservice.exception.custom;

import com.ifortex.internship.authservice.exception.AuthServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class RefreshTokenNotFoundException extends AuthServiceException {
  public RefreshTokenNotFoundException(String invalidRefreshToken) {
    super(invalidRefreshToken);
  }
}
