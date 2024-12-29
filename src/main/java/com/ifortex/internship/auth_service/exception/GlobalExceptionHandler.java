package com.ifortex.internship.auth_service.exception;

import com.ifortex.internship.auth_service.exception.custom.TokensRefreshException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

  @ExceptionHandler(AuthServiceException.class)
  public ResponseEntity<String> handleAuthServiceExceptions(AuthServiceException ex) {

    ResponseStatus statusAnnotation = ex.getClass().getAnnotation(ResponseStatus.class);
    HttpStatus status =
        statusAnnotation != null ? statusAnnotation.value() : HttpStatus.INTERNAL_SERVER_ERROR;

    if (ex instanceof TokensRefreshException) {
      return new ResponseEntity<>(
          "Failed to refresh access token. Please try logging in again.", status);
    }

    return new ResponseEntity<>(ex.getMessage(), status);
  }

  @ExceptionHandler(UsernameNotFoundException.class)
  public ResponseEntity<String> handleUsernameNotFoundException(UsernameNotFoundException ex) {
    log.debug("UsernameNotFoundException occurred: {}", ex.getMessage());
    log.info("Login attempt failed: invalid email provided.");
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<String> handleBadCredentialsException(BadCredentialsException ex) {
    log.debug("BadCredentialsException occurred: {}", ex.getMessage());
    log.info("Login attempt failed: invalid email or password provided.");
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<Map<String, String>> handleValidationExceptions(
      MethodArgumentNotValidException ex) {

    log.error(ex.getMessage());

    BindingResult bindingResult = ex.getBindingResult();

    Map<String, String> errors = new HashMap<>();
    bindingResult
        .getFieldErrors()
        .forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));

    return ResponseEntity.badRequest().body(errors);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<String> handleOtherExceptions(Exception ex) {
    log.error(ex.toString());
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body("An unexpected error occurred");
  }
}
