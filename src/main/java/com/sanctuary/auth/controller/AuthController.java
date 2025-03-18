package com.sanctuary.auth.controller;

import com.sanctuary.auth.dto.AuthResponse;
import com.sanctuary.auth.dto.LoginRequest;
import com.sanctuary.auth.dto.RegisterRequest;
import com.sanctuary.auth.model.AppUser;
import com.sanctuary.auth.model.Role;
import com.sanctuary.auth.repository.UserRepository;
import com.sanctuary.auth.security.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    /** Endpoint para registrar un nuevo usuario */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest request) {
        System.out.println("registerUser");
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("El usuario ya existe.");
        }
        
        AppUser newUser = new AppUser();
        newUser.setUsername(request.getUsername());
        newUser.setEmail(request.getEmail());
        newUser.setIdentificationNumber(request.getIdentificationNumber());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        newUser.setRole(Role.USER); // Se asigna el rol USER por defecto

        userRepository.save(newUser);
        return ResponseEntity.ok("Usuario registrado exitosamente.");
    }

    /** Endpoint para registrar un nuevo usuario */
    @PostMapping("/register_admin")
    public ResponseEntity<?> registerAdmin(@RequestBody RegisterRequest request) {
        System.out.println("registerAdmin");

        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("El usuario ya existe.");
        }
        
        AppUser newUser = new AppUser();
        newUser.setUsername(request.getUsername());
        newUser.setEmail(request.getEmail());
        newUser.setIdentificationNumber(request.getIdentificationNumber());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        newUser.setRole(Role.ADMIN); // Se asigna el rol USER por defecto

        userRepository.save(newUser);
        return ResponseEntity.ok("Usuario registrado exitosamente.");
    }
    

    /** Endpoint para iniciar sesión */
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest request) {
        Optional<AppUser> userOptional = userRepository.findByUsername(request.getUsername());

        if (userOptional.isEmpty() || !passwordEncoder.matches(request.getPassword(), userOptional.get().getPassword())) {
            return ResponseEntity.status(401).body("Credenciales inválidas.");
        }

        // Crear un objeto UserDetails basado en AppUser
        AppUser appUser = userOptional.get();
        UserDetails userDetails = new User(
                appUser.getUsername(),
                appUser.getPassword(),
                Collections.singletonList(() -> "ROLE_" + appUser.getRole().name()) // Asigna el rol
        );

        String token = jwtService.generateToken(userDetails);
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
