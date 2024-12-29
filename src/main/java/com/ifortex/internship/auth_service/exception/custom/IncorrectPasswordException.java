package com.ifortex.internship.auth_service.exception.custom;

import com.ifortex.internship.auth_service.exception.AuthServiceException;

public class IncorrectPasswordException extends AuthServiceException {
  public IncorrectPasswordException(String message) {
    super(message);
  }
}
