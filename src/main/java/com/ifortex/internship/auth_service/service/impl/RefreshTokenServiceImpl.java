package com.ifortex.internship.auth_service.service.impl;

import com.ifortex.internship.auth_service.exception.custom.RefreshTokenExpiredException;
import com.ifortex.internship.auth_service.exception.custom.RefreshTokenNotFoundException;
import com.ifortex.internship.auth_service.exception.custom.UserNotFoundException;
import com.ifortex.internship.auth_service.model.RefreshToken;
import com.ifortex.internship.auth_service.model.User;
import com.ifortex.internship.auth_service.repository.RefreshTokenRepository;
import com.ifortex.internship.auth_service.repository.UserRepository;
import com.ifortex.internship.auth_service.service.RefreshTokenService;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {
  private final RefreshTokenRepository refreshTokenRepository;
  private final UserRepository userRepository;

  @Value("${app.refreshTokenExpirationS}")
  private int refreshTokenDurationS;

  @Transactional
  public RefreshToken createRefreshToken(Long userId) {
    log.debug("Creating refresh token for user with ID: {}", userId);
    User user =
        userRepository
            .findById(userId)
            .orElseThrow(
                () -> {
                  log.error("User with ID: {} not found", userId);
                  return new UserNotFoundException(userId);
                });

    deleteTokensByUserId(userId);

    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setUser(user);
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken.setExpiryDate(Instant.now().plusSeconds(refreshTokenDurationS));

    refreshToken = refreshTokenRepository.save(refreshToken);
    log.debug("Refresh token created for user {}", user.getEmail());
    return refreshToken;
  }

  public RefreshToken verifyExpiration(RefreshToken refreshToken) {
    log.debug("Verifying refresh token expiration.");
    boolean isTokenExpired = refreshToken.getExpiryDate().isBefore(Instant.now());
    if (isTokenExpired) {
      log.warn(
          "Refresh token expired. UserId={}, ExpiryDate={}",
          refreshToken.getUser().getId(),
          refreshToken.getExpiryDate());
      log.debug("Deleting refresh token from db");
      refreshTokenRepository.delete(refreshToken);
      log.debug("Refresh token has been deleted from db");
      throw new RefreshTokenExpiredException("Your session has expired. Please log in again.");
    }
    log.debug(
        "Refresh token is valid. UserId = {}, ExpiryDate = {}",
        refreshToken.getUser().getId(),
        refreshToken.getExpiryDate());
    return refreshToken;
  }

  @Transactional
  public void deleteTokensByUserId(Long userId) {
    log.debug("Deleting refresh tokens for user with ID: {}", userId);
    refreshTokenRepository.deleteByUserId(userId);
    log.debug("Deleted all refresh tokens for user with ID: {}", userId);
  }

  public RefreshToken findByToken(String token) {
    log.debug("Searching for refresh token");
    return refreshTokenRepository
        .findByToken(token)
        .orElseThrow(
            () -> {
              log.error("Invalid refresh token: {}", token);
              return new RefreshTokenNotFoundException(
                  "Refresh token not found for the provided value: " + token);
            });
  }

  public void deleteToken(RefreshToken token) {
    refreshTokenRepository.delete(token);
  }
}
