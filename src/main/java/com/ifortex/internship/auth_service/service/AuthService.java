package com.ifortex.internship.auth_service.service;

import com.ifortex.internship.auth_service.dto.request.LoginRequest;
import com.ifortex.internship.auth_service.dto.request.PasswordResetRequest;
import com.ifortex.internship.auth_service.dto.request.PasswordResetWithOtpDto;
import com.ifortex.internship.auth_service.dto.request.RegistrationRequest;
import com.ifortex.internship.auth_service.dto.request.VerifyLoginOtpRequest;
import com.ifortex.internship.auth_service.dto.response.AuthResponse;
import com.ifortex.internship.auth_service.dto.response.SuccessResponse;
import com.ifortex.internship.auth_service.exception.custom.EmailAlreadyRegistered;
import com.ifortex.internship.auth_service.exception.custom.EmailSendException;
import com.ifortex.internship.auth_service.exception.custom.InvalidOtpException;
import com.ifortex.internship.auth_service.exception.custom.PasswordMismatchException;
import com.ifortex.internship.auth_service.exception.custom.RoleNotFoundException;
import com.ifortex.internship.auth_service.exception.custom.UserNotAuthenticatedException;
import com.ifortex.internship.auth_service.exception.custom.UserNotFoundException;

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
   * <p>This method validates the registration request, including email uniqueness and password
   * confirmation. If valid, it hashes the user's password, assigns the default "non-subscribed
   * user" role, and saves the user in the database.
   *
   * @param request the registration request containing user details like email, password, and
   *     password confirmation
   * @return a {@link SuccessResponse} indicating successful registration with a message
   * @throws EmailAlreadyRegistered if the email is already registered in the system
   * @throws PasswordMismatchException if the provided password and its confirmation do not match
   * @throws RoleNotFoundException if the default "non-subscribed user" role is not found in the
   *     database
   */
  SuccessResponse registerUser(RegistrationRequest request);

  /**
   * Authenticates a user based on the provided login credentials.
   *
   * <p>This method validates the user's email and password using Spring Security's authentication
   * manager. If the user has two-factor authentication (2FA) enabled, an OTP (one-time password) is
   * generated and sent to the user's email. The method then responds with a message instructing the
   * user to complete the 2FA verification.
   *
   * <p>If 2FA is not enabled, the method generates access and refresh tokens for the user and
   * returns them in the response.
   *
   * @param loginRequest the {@link LoginRequest} containing the user's email and password
   * @return an {@link AuthResponse} containing a message and either instructions for 2FA or
   *     authentication tokens
   * @throws EmailSendException if an error occurs while sending the OTP email for 2FA
   */
  AuthResponse authenticateUser(LoginRequest loginRequest);

  /**
   * Verifies the one-time password (OTP) for two-factor authentication during login.
   *
   * <p>This method checks the provided OTP against the one stored for the given user email. If the
   * OTP is valid, it generates authentication tokens (access and refresh) for the user and returns
   * them in an {@link AuthResponse}.
   *
   * @param verifyLoginOtpRequest the {@link VerifyLoginOtpRequest} containing the user's email and
   *     OTP.
   * @return an AuthResponse containing the authentication tokens and a success message.
   * @throws InvalidOtpException if the OTP is expired or invalid.
   * @throws UserNotFoundException if no user is found with the provided email address.
   */
  AuthResponse completeLoginWithOtp(VerifyLoginOtpRequest verifyLoginOtpRequest);

  /**
   * Logs out the currently authenticated user by invalidating the provided refresh token and
   * clearing authentication cookies.
   *
   * @param refreshToken the refresh token to be invalidated
   * @return an {@link AuthResponse} containing a success message, cleared authentication cookies,
   *     and the user's email
   * @throws UserNotAuthenticatedException if the user is not authenticated
   */
  AuthResponse logoutUser(String refreshToken);

  /**
   * Initiates the password reset process for a user.
   *
   * <p>This method verifies that the provided email address is registered in the system. If the
   * user is found, a one-time password (OTP) is generated and saved with a defined expiration time.
   * An email is sent to the user containing the OTP and a link to reset their password.
   *
   * @param passwordResetRequest the password reset request containing the user's email address.
   * @return a {@link SuccessResponse} containing a message confirming the initiation of the
   *     password reset process and instructions to complete it.
   * @throws UserNotFoundException if no user is found with the provided email address.
   * @throws EmailSendException if an error occurs while sending the email with the OTP.
   */
  SuccessResponse initiatePasswordReset(PasswordResetRequest passwordResetRequest);

  /**
   * Resets the user's password using a one-time password (OTP) sent to their email.
   *
   * @param passwordResetWithOtpDto the {@link PasswordResetWithOtpDto} containing the user's email,
   *     OTP, new password, and password confirmation.
   * @return a {@link SuccessResponse} containing a message indicating that the password was
   *     successfully reset.
   * @throws InvalidOtpException if the provided OTP does not match the stored OTP.
   * @throws PasswordMismatchException if the new password and its confirmation do not match.
   */
  SuccessResponse resetPasswordWithOtp(PasswordResetWithOtpDto passwordResetWithOtpDto);
}
