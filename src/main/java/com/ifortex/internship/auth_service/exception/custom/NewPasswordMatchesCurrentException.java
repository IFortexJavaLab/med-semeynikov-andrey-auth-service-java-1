package com.ifortex.internship.auth_service.exception.custom;

import com.ifortex.internship.auth_service.exception.AuthServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class NewPasswordMatchesCurrentException extends AuthServiceException {
  public NewPasswordMatchesCurrentException(String message) {
    super(message);
  }
}
