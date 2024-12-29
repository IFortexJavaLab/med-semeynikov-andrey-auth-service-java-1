package com.ifortex.internship.auth_service.service.impl;

import com.ifortex.internship.auth_service.dto.request.ChangePasswordRequest;
import com.ifortex.internship.auth_service.dto.response.RegistrationResponse;
import com.ifortex.internship.auth_service.exception.custom.IncorrectPasswordException;
import com.ifortex.internship.auth_service.exception.custom.NewPasswordMatchesCurrentException;
import com.ifortex.internship.auth_service.exception.custom.PasswordMismatchException;
import com.ifortex.internship.auth_service.exception.custom.UserNotFoundException;
import com.ifortex.internship.auth_service.model.User;
import com.ifortex.internship.auth_service.repository.UserRepository;
import com.ifortex.internship.auth_service.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public User findUserById(Long id) {
    User user =
        userRepository
            .findById(id)
            .orElseThrow(
                () -> {
                  log.error("User with ID: {} not found", id);
                  return new UserNotFoundException(id);
                });
    return user;
  }

  public User findUserByEmail(String email) {
    User user =
        userRepository
            .findByEmail(email)
            .orElseThrow(
                () -> {
                  log.error("User with email: {} not found", email);
                  return new UserNotFoundException(email);
                });
    return user;
  }

  public RegistrationResponse changePassword(ChangePasswordRequest request, String userEmail) {

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

    return new RegistrationResponse("Changed password successfully", user.getId());
  }
}
