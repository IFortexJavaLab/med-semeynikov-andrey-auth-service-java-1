package com.ifortex.internship.auth_service.controller;

import com.ifortex.internship.auth_service.dto.request.LoginRequest;
import com.ifortex.internship.auth_service.dto.request.PasswordResetRequest;
import com.ifortex.internship.auth_service.dto.request.RegistrationRequest;
import com.ifortex.internship.auth_service.dto.response.AuthResponse;
import com.ifortex.internship.auth_service.dto.response.CookieTokensResponse;
import com.ifortex.internship.auth_service.dto.response.SuccessResponse;
import com.ifortex.internship.auth_service.service.AuthService;
import com.ifortex.internship.auth_service.service.TokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final TokenService tokenService;

  @PostMapping("/register")
  public ResponseEntity<?> register(@RequestBody @Valid RegistrationRequest request) {

    log.info("Received registration request for email: {}", request.getEmail());

    SuccessResponse response = authService.register(request);

    return ResponseEntity.ok(
        String.format(
            "User with email: %s has been successfully registered", response.getMessage()));
  }

  @PostMapping("/login")
  public ResponseEntity<?> login(@RequestBody @Valid LoginRequest loginRequest) {

    log.info("Login attempt for email: {}", loginRequest.getEmail());
    AuthResponse authResponse = authService.authenticateUser(loginRequest);

    HttpHeaders headers = new HttpHeaders();
    headers.add(
        HttpHeaders.SET_COOKIE,
        authResponse.getCookieTokensResponse().getAccessCookie().toString());
    headers.add(
        HttpHeaders.SET_COOKIE,
        authResponse.getCookieTokensResponse().getRefreshCookie().toString());

    log.debug("Refresh and access tokens set in cookie for email: {}", loginRequest.getEmail());
    log.info("User: {} successfully logged in", loginRequest.getEmail());

    return ResponseEntity.ok()
        .headers(headers)
        .body(String.format("Login successful with email: %s", loginRequest.getEmail()));
  }

  @PostMapping("/logout")
  public ResponseEntity<?> logout(@CookieValue("refreshToken") String refreshToken) {

    log.info("Logout attempt");

    AuthResponse authResponse = authService.logoutUser(refreshToken);

    HttpHeaders headers = new HttpHeaders();
    headers.add(
        HttpHeaders.SET_COOKIE,
        authResponse.getCookieTokensResponse().getAccessCookie().toString());
    headers.add(
        HttpHeaders.SET_COOKIE,
        authResponse.getCookieTokensResponse().getRefreshCookie().toString());

    log.debug("Clean tokens set in cookie for user with id = {}", authResponse.getUserId());
    log.info("Logout successful for user with id = {}", authResponse.getUserId());

    return ResponseEntity.ok().headers(headers).body("Logout successful");
  }

  @PostMapping("/refresh")
  public ResponseEntity<?> refreshToken(@CookieValue("refreshToken") String refreshToken) {

    log.info("Tokens refresh attempt.");
    CookieTokensResponse cookie = tokenService.refreshTokens(refreshToken);

    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.SET_COOKIE, cookie.getAccessCookie().toString());
    headers.add(HttpHeaders.SET_COOKIE, cookie.getRefreshCookie().toString());

    log.info("Tokens refreshed successfully.");

    return ResponseEntity.ok().headers(headers).body("Tokens refreshed successfully");
  }

  @PostMapping("/reset-password/request")
  public ResponseEntity<?> resetPassword(@RequestBody PasswordResetRequest request) {
    log.info("Reset password attempt for user: {}", request.getEmail());

    SuccessResponse response = authService.resetPassword(request);

    log.info("Email with otp to reset password was sent to the email: {}", request.getEmail());

    return ResponseEntity.ok().body(response);
  }

  /*@PostMapping("/reset-password/verify")
  public ResponseEntity<?> verifyOtp(@RequestBody PasswordResetTokenValidationDto request){
    log.info("Verifying otp attempt for email: {}", request.getEmail());

    SuccessResponse response = authService.verifyOtp(request);

    return
  }*/
}
