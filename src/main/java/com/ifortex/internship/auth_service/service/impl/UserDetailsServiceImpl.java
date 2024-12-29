package com.ifortex.internship.auth_service.service.impl;

import com.ifortex.internship.auth_service.model.User;
import com.ifortex.internship.auth_service.model.UserDetailsImpl;
import com.ifortex.internship.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user =
        userRepository
            .findByEmail(username)
            .orElseThrow(
                () ->
                    new UsernameNotFoundException(
                        String.format("User not found with email: %s", username)));

    return UserDetailsImpl.build(user);
  }
}
