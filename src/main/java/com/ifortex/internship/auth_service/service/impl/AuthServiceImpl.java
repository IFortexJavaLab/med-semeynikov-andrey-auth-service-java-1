package com.ifortex.internship.auth_service.service.impl;

import com.ifortex.internship.auth_service.dto.request.LoginRequest;
import com.ifortex.internship.auth_service.dto.request.RegistrationRequest;
import com.ifortex.internship.auth_service.dto.response.AuthResponse;
import com.ifortex.internship.auth_service.dto.response.CookieTokensResponse;
import com.ifortex.internship.auth_service.dto.response.SuccessResponse;
import com.ifortex.internship.auth_service.exception.custom.EmailAlreadyRegistered;
import com.ifortex.internship.auth_service.exception.custom.PasswordMismatchException;
import com.ifortex.internship.auth_service.exception.custom.RoleNotFoundException;
import com.ifortex.internship.auth_service.exception.custom.UserNotAuthenticatedException;
import com.ifortex.internship.auth_service.model.ERole;
import com.ifortex.internship.auth_service.model.RefreshToken;
import com.ifortex.internship.auth_service.model.Role;
import com.ifortex.internship.auth_service.model.User;
import com.ifortex.internship.auth_service.model.UserDetailsImpl;
import com.ifortex.internship.auth_service.repository.RefreshTokenRepository;
import com.ifortex.internship.auth_service.repository.RoleRepository;
import com.ifortex.internship.auth_service.repository.UserRepository;
import com.ifortex.internship.auth_service.service.AuthService;
import com.ifortex.internship.auth_service.service.CookieService;
import com.ifortex.internship.auth_service.service.TokenService;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

  @Transactional
  public SuccessResponse register(RegistrationRequest request) {

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
            .findByName(ERole.NON_SUBSCRIBED_USER)
            .orElseThrow(
                () -> {
                  log.error("Role: {} is not found", ERole.NON_SUBSCRIBED_USER);
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
    return SuccessResponse.builder().message(user.getEmail()).build();
  }

  public AuthResponse authenticateUser(LoginRequest loginRequest) {
    log.debug("Authenticating user with email: {}", loginRequest.getEmail());

    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.getEmail(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    List<String> roles =
        userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList());

    log.debug("User: {} successfully authenticated.", userDetails.getUsername());

    // feature add email verification

    String newAccessToken = tokenService.generateAccessToken(userDetails.getUsername(), roles);
    log.debug("Access token generated successfully for user: {}", userDetails.getEmail());

    RefreshToken newRefreshToken = tokenService.createRefreshToken(userDetails.getId());

    ResponseCookie accessTokenCookie = cookieService.createAccessTokenCookie(newAccessToken);
    ResponseCookie refreshTokenCookie =
        cookieService.createRefreshTokenCookie(newRefreshToken.getToken());
    log.debug(
        "Cookies with access and refresh tokens generated successfully for user: {}",
        userDetails.getEmail());

    return new AuthResponse(
        new CookieTokensResponse(accessTokenCookie, refreshTokenCookie), userDetails.getId());
  }

  public AuthResponse logoutUser(String refreshToken) {
    Object principle = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    if (!"anonymousUser".equals(principle.toString())) {
      log.debug("Deleting refresh token");
      refreshTokenRepository.deleteRefreshTokenByToken(refreshToken);
      log.debug("Refresh token deleted successfully");
    } else {
      log.warn("Logout attempt by anonymous or unauthenticated user.");
      throw new UserNotAuthenticatedException("User is not authenticated. Please log in.");
    }

    ResponseCookie accessTokenCookie = cookieService.deleteAccessTokenCookie();
    ResponseCookie refreshTokenCookie = cookieService.deleteRefreshTokenCookie();

    return new AuthResponse(new CookieTokensResponse(accessTokenCookie, refreshTokenCookie), null);
  }
}
