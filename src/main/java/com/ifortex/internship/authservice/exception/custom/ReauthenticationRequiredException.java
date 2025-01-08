package com.ifortex.internship.authservice.exception.custom;

import com.ifortex.internship.authservice.exception.AuthServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

// feature refactor to use authentication exception instead
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class ReauthenticationRequiredException extends AuthServiceException {
  public ReauthenticationRequiredException(String message) {
    super(message);
  }
}
