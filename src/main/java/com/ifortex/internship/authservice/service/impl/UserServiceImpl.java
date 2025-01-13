package com.ifortex.internship.authservice.service.impl;

import com.ifortex.internship.authservice.dto.request.ChangePasswordRequest;
import com.ifortex.internship.authservice.dto.response.SuccessResponse;
import com.ifortex.internship.authservice.exception.custom.AuthorizationException;
import com.ifortex.internship.authservice.exception.custom.EntityNotFoundException;
import com.ifortex.internship.authservice.exception.custom.InvalidRequestException;
import com.ifortex.internship.authservice.model.User;
import com.ifortex.internship.authservice.repository.UserRepository;
import com.ifortex.internship.authservice.service.UserService;
import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public User findUserById(Long id) {
    return userRepository
        .findById(id)
        .orElseThrow(
            () -> {
              log.debug("User with ID: {} not found", id);
              return new EntityNotFoundException(
                  String.format("User with email: %d not found", id));
            });
  }

  public User findUserByEmail(String email) {
    return userRepository
        .findByEmail(email)
        .orElseThrow(
            () -> {
              log.debug("User with email: {} not found", email);
              return new EntityNotFoundException(
                  String.format("User with email: %s not found", email));
            });
  }

  public SuccessResponse changePassword(ChangePasswordRequest request, String userEmail) {

    log.debug("Changing password for user with email: {}", userEmail);

    User user = findUserByEmail(userEmail);

    if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
      log.info("Incorrect password for user with email: {}", user.getEmail());
      throw new AuthorizationException(
          String.format("Incorrect password for user with email: %s", user.getEmail()));
    }

    if (request.getCurrentPassword().equals(request.getPasswordConfirmation())) {
      log.info(
          "Current password and new password are equal for user with email: {}", user.getEmail());
      throw new InvalidRequestException(
          String.format(
              "Current password and new password are equal for user with email: %s",
              user.getEmail()));
    }

    boolean passwordMismatch = !request.getNewPassword().equals(request.getPasswordConfirmation());
    if (passwordMismatch) {
      log.info(
          "Password and password confirmation  do not match for user with email: {}",
          user.getEmail());
      throw new InvalidRequestException("Password and confirmation password do not match.");
    }

    String newEncodedPassword = passwordEncoder.encode(request.getNewPassword());
    user.setPassword(newEncodedPassword);
    user.setUpdatedAt(LocalDateTime.now());
    userRepository.save(user);

    log.info("User with email: {} successfully changed password", userEmail);

    // feature refactor it to generate link dynamically
    String link = "http://localhost:8081/api/v1/auth/login";

    return SuccessResponse.builder()
        .message(
            String.format(
                "Changed password successfully for user with email %s, please log in again using this link: %s",
                user.getEmail(), link))
        .build();
  }
}
