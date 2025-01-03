package com.ifortex.internship.auth_service.controller;

import com.ifortex.internship.auth_service.dto.request.ChangePasswordRequest;
import com.ifortex.internship.auth_service.dto.response.AuthResponse;
import com.ifortex.internship.auth_service.dto.response.SuccessResponse;
import com.ifortex.internship.auth_service.model.UserDetailsImpl;
import com.ifortex.internship.auth_service.service.AuthService;
import com.ifortex.internship.auth_service.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

  private final UserService userService;
  private final AuthService authService;

  @PatchMapping("/change-password")
  public ResponseEntity<?> changePassword(
      @RequestBody ChangePasswordRequest request,
      @CookieValue("refreshToken") String refreshToken) {

    String userEmail =
        ((UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal())
            .getEmail();
    log.info("Attempt to change password for user: {}", userEmail);
    SuccessResponse response = userService.changePassword(request, userEmail);

    AuthResponse authResponse = authService.logoutUser(refreshToken);

    HttpHeaders headers = new HttpHeaders();
    headers.add(
        HttpHeaders.SET_COOKIE,
        authResponse.getCookieTokensResponse().getAccessCookie().toString());
    headers.add(
        HttpHeaders.SET_COOKIE,
        authResponse.getCookieTokensResponse().getRefreshCookie().toString());

    log.debug("Clean tokens set in cookie for user with email = {}", userEmail);
    log.info("Logout successful for user with email = {}", userEmail);

    return ResponseEntity.ok().headers(headers).body(response);
  }
}
