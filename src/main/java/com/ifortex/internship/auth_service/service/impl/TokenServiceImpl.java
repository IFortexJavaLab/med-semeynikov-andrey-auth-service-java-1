package com.ifortex.internship.auth_service.service.impl;

import com.ifortex.internship.auth_service.dto.response.CookieTokensResponse;
import com.ifortex.internship.auth_service.exception.AuthServiceException;
import com.ifortex.internship.auth_service.exception.custom.InvalidJwtTokenException;
import com.ifortex.internship.auth_service.exception.custom.ReauthenticationRequiredException;
import com.ifortex.internship.auth_service.exception.custom.RefreshTokenExpiredException;
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
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
      log.debug(e.getMessage());
      throw e;
    } catch (AuthServiceException e) {
      throw new ReauthenticationRequiredException(
          "Your session has expired or your token is invalid. Please log in again.");
    }
  }

  public boolean isValid(String authToken) {

    try {
      Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(authToken);
      log.debug("Access token is valid");
      return true;
    } catch (SignatureException e) {
      log.debug("Invalid JWT signature: {}", e.getMessage());
      throw new InvalidJwtTokenException("JWT token is invalid. Please log in again.");
    } catch (MalformedJwtException e) {
      log.debug("Invalid JWT token: {}", e.getMessage());
      throw new InvalidJwtTokenException("JWT token is malformed. Please log in again.");
    } catch (UnsupportedJwtException e) {
      log.debug("JWT token is unsupported: {}", e.getMessage());
      throw new InvalidJwtTokenException("JWT token is unsupported. Please log in again.");
    } catch (IllegalArgumentException e) {
      log.debug("JWT claims string is empty: {}", e.getMessage());
      throw new InvalidJwtTokenException("JWT claims string is empty. Please log in again.");
    } catch (ExpiredJwtException e) {
      log.debug("JWT token is expired: {}", e.getMessage());
    }

    return false;
  }

  public boolean isExpired(String authToken) {

    try {
      Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(authToken);
      return false;
    } catch (ExpiredJwtException e) {
      log.debug("JWT token is expired: {}", e.getMessage());
      return true;
    } catch (Exception e) {
      return false;
    }
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

  public Collection<? extends GrantedAuthority> getAuthorityFromToken(String token) {

    log.debug("Getting authorities from access token");

    final Claims claims =
        Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).getPayload();
    List<String> roles = claims.get("roles", List.class);

    log.debug("Got roles from token: {}", roles.toString());

    List<SimpleGrantedAuthority> authorities =
        roles.stream().map(SimpleGrantedAuthority::new).toList();

    log.debug("Made authority from roles: {}", authorities);

    return authorities;
  }

  public String getRefreshTokenFromRequest(HttpServletRequest request) {

    return Optional.ofNullable(request.getCookies()).stream()
        .flatMap(Stream::of)
        .filter(cookie -> "refreshToken".equals(cookie.getName()))
        .map(Cookie::getValue)
        .findFirst()
        .orElse(null);
  }
}
