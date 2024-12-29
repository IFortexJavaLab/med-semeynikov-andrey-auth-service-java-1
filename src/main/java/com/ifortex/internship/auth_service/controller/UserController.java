package com.ifortex.internship.auth_service.controller;

import com.ifortex.internship.auth_service.dto.request.ChangePasswordRequest;
import com.ifortex.internship.auth_service.dto.response.RegistrationResponse;
import com.ifortex.internship.auth_service.model.UserDetailsImpl;
import com.ifortex.internship.auth_service.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
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

  @PatchMapping("/change-password")
  public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {

    String userEmail =
        ((UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal())
            .getEmail();
    log.info("Attempt to change password for user: {}", userEmail);
    RegistrationResponse response = userService.changePassword(request, userEmail);

    return ResponseEntity.ok(response);
  }
}
