package com.ifortex.internship.auth_service.exception.custom;

import com.ifortex.internship.auth_service.exception.AuthServiceException;

public class NewPasswordMatchesCurrentException extends AuthServiceException {
  public NewPasswordMatchesCurrentException(String message) {
    super(message);
  }
}
