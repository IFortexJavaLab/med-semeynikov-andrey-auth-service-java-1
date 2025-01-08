package com.ifortex.internship.auth_service.service.impl;

import com.ifortex.internship.auth_service.dto.request.ChangePasswordRequest;
import com.ifortex.internship.auth_service.dto.response.SuccessResponse;
import com.ifortex.internship.auth_service.exception.custom.IncorrectPasswordException;
import com.ifortex.internship.auth_service.exception.custom.NewPasswordMatchesCurrentException;
import com.ifortex.internship.auth_service.exception.custom.PasswordMismatchException;
import com.ifortex.internship.auth_service.exception.custom.UserNotFoundException;
import com.ifortex.internship.auth_service.model.User;
import com.ifortex.internship.auth_service.repository.UserRepository;
import com.ifortex.internship.auth_service.service.UserService;
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
              log.error("User with ID: {} not found", id);
              return new UserNotFoundException(id);
            });
  }

  public User findUserByEmail(String email) {
    return userRepository
        .findByEmail(email)
        .orElseThrow(
            () -> {
              log.error("User with email: {} not found", email);
              return new UserNotFoundException(email);
            });
  }

  public SuccessResponse changePassword(ChangePasswordRequest request, String userEmail) {

    log.debug("Changing password for user with email: {}", userEmail);

    User user = findUserByEmail(userEmail);

    if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
      log.info("Incorrect password for user with email: {}", user.getEmail());
      throw new IncorrectPasswordException(
          String.format("Incorrect password for user with email: %s", user.getEmail()));
    }

    if (request.getCurrentPassword().equals(request.getPasswordConfirmation())) {
      log.info(
          "Current password and new password are equal for user with email: {}", user.getEmail());
      throw new NewPasswordMatchesCurrentException(
          String.format(
              "Current password and new password are equal for user with email: %s",
              user.getEmail()));
    }

    boolean passwordMismatch = !request.getNewPassword().equals(request.getPasswordConfirmation());
    if (passwordMismatch) {
      log.info(
          "Password and password confirmation  do not match for user with email: {}",
          user.getEmail());
      throw new PasswordMismatchException("Password and confirmation password do not match.");
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
