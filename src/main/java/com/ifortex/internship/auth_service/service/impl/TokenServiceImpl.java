package com.ifortex.internship.auth_service.service.impl;

import com.ifortex.internship.auth_service.dto.response.CookieTokensResponse;
import com.ifortex.internship.auth_service.exception.AuthServiceException;
import com.ifortex.internship.auth_service.exception.custom.RefreshTokenExpiredException;
import com.ifortex.internship.auth_service.exception.custom.TokensRefreshException;
import com.ifortex.internship.auth_service.exception.custom.UserNotFoundForRefreshTokenException;
import com.ifortex.internship.auth_service.model.RefreshToken;
import com.ifortex.internship.auth_service.model.User;
import com.ifortex.internship.auth_service.service.CookieService;
import com.ifortex.internship.auth_service.service.RefreshTokenService;
import com.ifortex.internship.auth_service.service.TokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class TokenServiceImpl implements TokenService {

  @Value("${app.jwtSecret}")
  private String jwtSecret;

  @Value("${app.jwtExpirationMs}")
  private int jwtExpirationMs;

  private final RefreshTokenService refreshTokenService;
  private final CookieService cookieService;

  public TokenServiceImpl(RefreshTokenService refreshTokenService, CookieService cookieService) {
    this.refreshTokenService = refreshTokenService;
    this.cookieService = cookieService;
  }

  public String generateAccessToken(String email, List<String> roles) {
    String token =
        Jwts.builder()
            .subject(email)
            .claim("roles", roles)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
            .signWith(getSigningKey())
            .compact();

    return token;
  }

  public CookieTokensResponse refreshTokens(String refreshToken) {
    log.debug("Refreshing access token");

    try {
      RefreshToken storedRefreshtoken = refreshTokenService.findByToken(refreshToken);
      refreshTokenService.verifyExpiration(storedRefreshtoken);

      User user = storedRefreshtoken.getUser();

      if (user == null) {
        log.error("User not found for the refresh token: {}", refreshToken);
        throw new UserNotFoundForRefreshTokenException("User not found for this refresh token");
      }

      List<String> roles = user.getRoles().stream().map(role -> role.getName().name()).toList();

      String newAccessToken = generateAccessToken(user.getEmail(), roles);
      log.debug("Access token refreshed successfully for user: {}", user.getEmail());

      RefreshToken newRefreshToken = createRefreshToken(user.getId());

      ResponseCookie accessTokenCookie = cookieService.createAccessTokenCookie(newAccessToken);
      ResponseCookie refreshTokenCookie =
          cookieService.createRefreshTokenCookie(newRefreshToken.getToken());

      return new CookieTokensResponse(accessTokenCookie, refreshTokenCookie);
    } catch (RefreshTokenExpiredException e) {
      log.error(e.getMessage());
      throw e;
    } catch (AuthServiceException e) {
      log.error("Failed to refresh tokens: {}", e.getMessage());
      throw new TokensRefreshException("Failed to refresh tokens.");
    }
  }

  public boolean isValid(String authToken) {

    try {
      Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(authToken);
      log.debug("Access token is valid");
      return true;
    } catch (SignatureException e) {
      log.debug("Invalid JWT signature: {}", e.getMessage());
      throw e;
    } catch (MalformedJwtException e) {
      log.debug("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      log.debug("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      log.debug("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      log.debug("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }

  private SecretKey getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public RefreshToken createRefreshToken(Long userId) {
    return refreshTokenService.createRefreshToken(userId);
  }

  public String getUsernameFromToken(String token) {
    return Jwts.parser()
        .verifyWith(getSigningKey())
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .getSubject();
  }

  public List<String> getRolesFromToken(String token) {
    final Claims claims =
        Jwts.parser().verifyWith(getSigningKey()).build()
                .parseSignedClaims(token).getPayload();
    List<String> roles = claims.get("roles", List.class);
    log.debug("Got roles from token: {}", roles.toString());
    return roles;
  }
}
