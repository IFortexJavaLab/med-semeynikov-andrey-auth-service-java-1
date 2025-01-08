package com.ifortex.internship.auth_service.service.impl;

import com.ifortex.internship.auth_service.dto.request.LoginRequest;
import com.ifortex.internship.auth_service.dto.request.PasswordResetRequest;
import com.ifortex.internship.auth_service.dto.request.PasswordResetWithOtpDto;
import com.ifortex.internship.auth_service.dto.request.RegistrationRequest;
import com.ifortex.internship.auth_service.dto.request.VerifyLoginOtpRequest;
import com.ifortex.internship.auth_service.dto.response.AuthResponse;
import com.ifortex.internship.auth_service.dto.response.CookieTokensResponse;
import com.ifortex.internship.auth_service.dto.response.SuccessResponse;
import com.ifortex.internship.auth_service.email.EmailService;
import com.ifortex.internship.auth_service.exception.custom.EmailAlreadyRegistered;
import com.ifortex.internship.auth_service.exception.custom.EmailSendException;
import com.ifortex.internship.auth_service.exception.custom.InvalidOtpException;
import com.ifortex.internship.auth_service.exception.custom.PasswordMismatchException;
import com.ifortex.internship.auth_service.exception.custom.RoleNotFoundException;
import com.ifortex.internship.auth_service.exception.custom.UserNotAuthenticatedException;
import com.ifortex.internship.auth_service.model.constant.ERole;
import com.ifortex.internship.auth_service.model.RefreshToken;
import com.ifortex.internship.auth_service.model.Role;
import com.ifortex.internship.auth_service.model.User;
import com.ifortex.internship.auth_service.model.UserDetailsImpl;
import com.ifortex.internship.auth_service.model.constant.RedisKeyPrefix;
import com.ifortex.internship.auth_service.repository.RefreshTokenRepository;
import com.ifortex.internship.auth_service.repository.RoleRepository;
import com.ifortex.internship.auth_service.repository.UserRepository;
import com.ifortex.internship.auth_service.service.AuthService;
import com.ifortex.internship.auth_service.service.CookieService;
import com.ifortex.internship.auth_service.service.RedisService;
import com.ifortex.internship.auth_service.service.TokenService;
import com.ifortex.internship.auth_service.service.UserService;
import jakarta.mail.MessagingException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

  private final UserRepository userRepository;
  private final TokenService tokenService;
  private final AuthenticationManager authenticationManager;
  private final CookieService cookieService;
  private final RefreshTokenRepository refreshTokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final RoleRepository roleRepository;
  private final EmailService emailService;
  private final RedisService redisService;
  private final UserService userService;

  @Getter
  @Value("${app.otp.expirationMinutes}")
  private int expirationMinutes;

  @Transactional
  public SuccessResponse registerUser(RegistrationRequest request) {

    log.debug("Register user: {}", request.getEmail());
    if (userRepository.findByEmail(request.getEmail()).isPresent()) {
      log.debug("Email: {} is already registered.", request.getEmail());
      log.info("Failed to register user");
      throw new EmailAlreadyRegistered("Email: " + request.getEmail() + " is already registered.");
    }

    boolean passwordMismatch = !request.getPassword().equals(request.getPasswordConfirmation());
    if (passwordMismatch) {
      log.debug("Password and confirmation password do not match.");
      log.info("Failed to register user");
      throw new PasswordMismatchException("Password and confirmation password do not match.");
    }

    String hashedPassword = passwordEncoder.encode(request.getPassword());

    // how should I handle this exception?
    // it can occurs only if there is no such role in the db
    // but it responsibility of developer to create such fields in the db
    // user do not send role during registration
    Role nonSubscribedUser =
        roleRepository
            .findByName(ERole.ROLE_NON_SUBSCRIBED_USER)
            .orElseThrow(
                () -> {
                  log.error("Role: {} is not found", ERole.ROLE_NON_SUBSCRIBED_USER);
                  return new RoleNotFoundException("Role NON_SUBSCRIBED_USER is not found");
                });

    User user = new User();
    user.setEmail(request.getEmail());
    user.setPassword(hashedPassword);
    user.setRoles(List.of(nonSubscribedUser));
    user.setCreatedAt(LocalDateTime.now());
    user.setUpdatedAt(LocalDateTime.now());
    userRepository.save(user);
    log.debug("User: {} saved to db successfully", request.getEmail());

    log.info("User: {} register successfully", request.getEmail());

    String message =
        String.format("User with email: %s has been successfully registered", user.getEmail());

    return SuccessResponse.builder().message(message).build();
  }

  public AuthResponse authenticateUser(LoginRequest loginRequest) {

    String userEmail = loginRequest.getEmail();
    log.debug("Authenticating user with email: {}", userEmail);

    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(userEmail, loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    log.debug("User: {} successfully authenticated.", userEmail);

    UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();

    if (user.isTwoFactorEnabled()) {
      log.debug("User: {} has 2FA enabled. Sending OTP", userEmail);

      String otp = generateOtp();
      String redisKey = RedisKeyPrefix.LOGIN_OTP.getPrefix() + userEmail;
      redisService.saveOtp(redisKey, otp, expirationMinutes);
      log.debug("Otp for user: {} generated and saved successfully", userEmail);

      // feature refactor method with dotry
      try {
        emailService.sendVerificationEmail(userEmail, "2FA Verification Code", otp);
      } catch (MessagingException e) {
        log.error(
            "Error during sending 2FA verification email for: {}. There details: {}",
            userEmail,
            e.getMessage());
        throw new EmailSendException("Failed to send 2FA verification email");
      }

      // feature refactor it to generate link dynamically
      String verifyOtpLink = "http://localhost:8081/api/v1/auth/verify-otp.";
      String message =
          String.format(
              "Two-factor authentication is required to complete your login. A verification code has been sent "
                  + "to your email: %s. Please enter the code along with your email at the following link: %s",
              userEmail, verifyOtpLink);
      return AuthResponse.builder().message(message).build();
    }

    List<String> roles =
        user.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList());

    return buildAuthResponse(userEmail, roles, user.getId());
  }

  public AuthResponse completeLoginWithOtp(VerifyLoginOtpRequest request) {

    String userEmail = request.getEmail();
    log.debug("Verifying otp to log in for email: {}", userEmail);

    String otpFromRequest = request.getOtp();
    String redisKey = RedisKeyPrefix.LOGIN_OTP.getPrefix() + userEmail;
    String storedOtp = redisService.getOtp(redisKey);

    if (!otpFromRequest.equals(storedOtp)) {
      log.debug("OTP has expired or is invalid for email: {}", userEmail);
      log.info("Failed to reset password for user: {}", userEmail);
      throw new InvalidOtpException("OTP has expired or is invalid. Please try again.");
    }

    var user = userService.findUserByEmail(userEmail);

    List<String> roles =
        user.getRoles().stream().map(role -> role.getName().name()).collect(Collectors.toList());

    return buildAuthResponse(userEmail, roles, user.getId());
  }

  public AuthResponse logoutUser(String refreshToken) {

    Object principle = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

    UserDetailsImpl userDetails;
    if (!"anonymousUser".equals(principle.toString())) {
      userDetails = (UserDetailsImpl) principle;
      log.debug("Deleting refresh token for user: {}", userDetails.getUsername());
      refreshTokenRepository.deleteRefreshTokenByToken(refreshToken);
      log.debug("Refresh token deleted successfully for user: {}", userDetails.getUsername());
    } else {
      log.warn("Logout attempt by anonymous or unauthenticated user.");
      throw new UserNotAuthenticatedException("User is not authenticated. Please log in.");
    }

    ResponseCookie accessTokenCookie = cookieService.deleteAccessTokenCookie();
    ResponseCookie refreshTokenCookie = cookieService.deleteRefreshTokenCookie();

    return AuthResponse.builder()
        .cookieTokensResponse(new CookieTokensResponse(accessTokenCookie, refreshTokenCookie))
        .email(userDetails.getUsername())
        .message(String.format("Logout successful for user %s", userDetails.getUsername()))
        .build();
  }

  public SuccessResponse initiatePasswordReset(PasswordResetRequest passwordResetRequest) {

    String userEmail = passwordResetRequest.getEmail();
    log.debug("Initiating password reset for email: {}", userEmail);

    userService.findUserByEmail(userEmail);

    String otp = generateOtp();
    log.debug("Otp for user: {} generated successfully", userEmail);

    String redisKey = RedisKeyPrefix.PASSWORD_RESET.getPrefix() + userEmail;
    redisService.saveOtp(redisKey, otp, expirationMinutes);
    log.debug("Otp saved to db successfully for user: {}", userEmail);

    try {
      emailService.sendVerificationEmail(userEmail, "Password reset", otp);
    } catch (MessagingException e) {
      log.error(
          "Error during sending verification email for: {}. There details: {}",
          userEmail,
          e.getMessage());
      throw new EmailSendException("Failed to send verification email");
    }

    // feature generate link dynamically
    String resetPasswordLink = "http://localhost:8081/api/v1/auth/reset-password/confirm";
    String message =
        String.format(
            "An email with a password reset code has been sent to your email: %s, please follow this link: %s",
            userEmail, resetPasswordLink);

    return SuccessResponse.builder().message(message).build();
  }

  public SuccessResponse resetPasswordWithOtp(PasswordResetWithOtpDto request) {

    String userEmail = request.getEmail();
    log.debug("Reset password with otp started for user: {}", userEmail);

    String otpFromRequest = request.getOtp();
    String redisKey = RedisKeyPrefix.PASSWORD_RESET.getPrefix() + userEmail;
    String storedOtp = redisService.getOtp(redisKey);

    if (!otpFromRequest.equals(storedOtp)) {
      log.debug("OTP has expired or is invalid for email: {}", userEmail);
      log.info("Failed to reset password for user: {}", userEmail);
      throw new InvalidOtpException("Invalid OTP provided. Please try again.");
    }

    boolean passwordMismatch = !request.getNewPassword().equals(request.getPasswordConfirmation());
    if (passwordMismatch) {
      log.debug("Password and confirmation password do not match.");
      log.info("Failed to reset password for user: {}", userEmail);
      throw new PasswordMismatchException("Password and confirmation password do not match.");
    }

    var user = userService.findUserByEmail(userEmail);

    String newEncodedPassword = passwordEncoder.encode(request.getNewPassword());
    user.setPassword(newEncodedPassword);
    user.setUpdatedAt(LocalDateTime.now());
    userRepository.save(user);

    redisService.deleteOtp(redisKey);

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

  /**
   * Constructs an {@link AuthResponse} containing authentication tokens and cookies for the
   * specified user.
   *
   * <p>This method generates a new access token and refresh token for the user, creates cookies to
   * store the tokens, and packages them into an AuthResponse.
   *
   * @param userEmail the email of the authenticated user
   * @param roles the roles assigned to the user
   * @param id the unique identifier of the user
   * @return an AuthResponse containing access and refresh token cookies, as well as a success
   *     message
   */
  private AuthResponse buildAuthResponse(String userEmail, List<String> roles, Long id) {

    String newAccessToken = tokenService.generateAccessToken(userEmail, roles);
    log.debug("Access token generated successfully for user: {}", userEmail);

    RefreshToken newRefreshToken = tokenService.createRefreshToken(id);

    ResponseCookie accessTokenCookie = cookieService.createAccessTokenCookie(newAccessToken);
    ResponseCookie refreshTokenCookie =
        cookieService.createRefreshTokenCookie(newRefreshToken.getToken());
    log.debug(
        "Cookies with access and refresh tokens generated successfully for user: {}", userEmail);

    return AuthResponse.builder()
        .cookieTokensResponse(new CookieTokensResponse(accessTokenCookie, refreshTokenCookie))
        .email(userEmail)
        .message(String.format("Login successful for user: %s.", userEmail))
        .build();
  }

  /**
   * Generates a random 6-digit one-time password (OTP) for authentication purposes.
   *
   * @return a 6-digit OTP as a String
   */
  private String generateOtp() {
    Random random = new Random();
    int code = random.nextInt(900000) + 100000;
    return String.valueOf(code);
  }
}
