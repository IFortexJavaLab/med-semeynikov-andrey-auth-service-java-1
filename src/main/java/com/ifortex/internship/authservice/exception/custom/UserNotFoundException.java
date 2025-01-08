package com.ifortex.internship.authservice.exception.custom;

import com.ifortex.internship.authservice.exception.AuthServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UserNotFoundException extends AuthServiceException {
  public UserNotFoundException(Long userId) {
    super(String.format("User with email: %d not found.", userId));
  }

  public UserNotFoundException(String userEmail) {
    super(String.format("User with email: %s not found.", userEmail));
  }
}
