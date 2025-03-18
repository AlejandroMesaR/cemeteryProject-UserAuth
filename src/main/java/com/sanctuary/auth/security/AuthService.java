package com.sanctuary.auth.security;

import com.sanctuary.auth.model.AppUser;
import com.sanctuary.auth.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsServiceImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;

    // Inyección de dependencias
    public AuthService(UserRepository userRepository, 
                       AuthenticationManager authenticationManager, 
                       UserDetailsServiceImpl userDetailsService,
                       PasswordEncoder passwordEncoder) { 
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    public String register(AppUser user) {
        user.setPassword(passwordEncoder.encode(user.getPassword())); 
        userRepository.save(user);
        return "Usuario registrado exitosamente";
    }

    public UserDetails authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        return userDetailsService.loadUserByUsername(username);
    }
}
