package com.sanctuary.auth.security;

import com.sanctuary.auth.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  private UserRepository userRepository;

  public UserDetailsServiceImpl(UserRepository userRepository) {
      this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
      return userRepository.findByUsername(username)
              .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
  }
}
