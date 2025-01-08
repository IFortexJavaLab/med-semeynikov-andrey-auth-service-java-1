package com.ifortex.internship.authservice.service;

import com.ifortex.internship.authservice.dto.request.ChangePasswordRequest;
import com.ifortex.internship.authservice.dto.response.SuccessResponse;
import com.ifortex.internship.authservice.exception.custom.IncorrectPasswordException;
import com.ifortex.internship.authservice.exception.custom.NewPasswordMatchesCurrentException;
import com.ifortex.internship.authservice.exception.custom.PasswordMismatchException;
import com.ifortex.internship.authservice.exception.custom.UserNotFoundException;
import com.ifortex.internship.authservice.model.User;

/**
 * Service interface for managing user-related operations.
 *
 * <p>Provides methods for finding users by their unique identifiers or email addresses, as well as
 * updating sensitive information such as passwords.
 */
public interface UserService {

  /**
   * Finds a user by their unique identifier (ID).
   *
   * @param id the unique identifier of the user
   * @return the {@link User} corresponding to the provided ID
   * @throws UserNotFoundException if a user with the specified ID is not found
   */
  User findUserById(Long id);

  /**
   * Finds a user by their email address.
   *
   * @param email the email address of the user
   * @return the User corresponding to the provided email
   * @throws UserNotFoundException if a user with the specified email is not found
   */
  User findUserByEmail(String email);

  /**
   * Changes the password of a user.
   *
   * <p>Verifies the current password provided by the user, ensures that the new password meets the
   * necessary requirements, and updates the password if all validations pass.
   *
   * @param request the {@link ChangePasswordRequest} containing the current password, new password,
   *     and password confirmation
   * @param userEmail the email address of the user requesting the password change
   * @return a {@link SuccessResponse} indicating the success of the operation
   * @throws IncorrectPasswordException if the current password does not match the user's existing
   *     password
   * @throws NewPasswordMatchesCurrentException if the new password matches the current password
   * @throws PasswordMismatchException if the new password and its confirmation do not match
   */

  SuccessResponse changePassword(ChangePasswordRequest request, String userEmail);
}
