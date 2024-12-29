package com.ifortex.internship.auth_service.service;

import com.ifortex.internship.auth_service.dto.request.LoginRequest;
import com.ifortex.internship.auth_service.dto.request.RegistrationRequest;
import com.ifortex.internship.auth_service.dto.response.AuthResponse;
import com.ifortex.internship.auth_service.dto.response.RegistrationResponse;
import com.ifortex.internship.auth_service.exception.custom.EmailAlreadyRegistered;
import com.ifortex.internship.auth_service.exception.custom.PasswordMismatchException;
import com.ifortex.internship.auth_service.exception.custom.UserNotAuthenticatedException;
import com.ifortex.internship.auth_service.model.User;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Service interface for handling user login and authentication.
 *
 * <p>Provides methods to authenticate users, generate authentication tokens, and prepare cookies
 * for secure storage of access and refresh tokens.
 */
public interface AuthService {

  /**
   * Registers a new user in the system.
   *
   * <p>This method performs the following steps:
   *
   * <ul>
   *   <li>Checks if the email is already registered.
   *   <li>Validates that the password matches its confirmation.
   *   <li>Encodes the password.
   *   <li>Creates and saves a new {@link User} entity in the database.
   * </ul>
   *
   * @param request the {@link RegistrationRequest} containing the user's email, password, and
   *     confirmation password
   * @return a {@link RegistrationResponse} containing the success message and user ID
   * @throws EmailAlreadyRegistered if the email is already registered
   * @throws PasswordMismatchException if the password does not match its confirmation
   */
  RegistrationResponse register(RegistrationRequest request);

  /**
   * Authenticates a user based on their login credentials.
   *
   * <p>This method performs authentication using the provided {@link LoginRequest}, generates an
   * access token and refresh token for the authenticated user, and returns a {@link AuthResponse}
   * containing the tokens and user information.
   *
   * @param loginRequest the LoginRequest containing the user's email and password
   * @return a AuthResponse containing the generated tokens and user details
   * @throws BadCredentialsException if the provided credentials are invalid
   */
  AuthResponse authenticateUser(LoginRequest loginRequest);

  /**
   * Logs out the currently authenticated user by invalidating all their refresh tokens and clearing
   * authentication cookies.
   *
   * <p>This method retrieves the currently authenticated user's details from the {@link
   * SecurityContextHolder}. If the user is authenticated, their refresh tokens are deleted from the
   * database, and cookies for access and refresh tokens are cleared. If the user is not
   * authenticated (anonymous), a {@link UserNotAuthenticatedException} is thrown.
   *
   * @return a AuthResponse containing the cleared access and refresh token cookies and the user ID
   *     of the logged-out user.
   * @throws UserNotAuthenticatedException if the user is not authenticated.
   */
  AuthResponse logoutUser();
}
