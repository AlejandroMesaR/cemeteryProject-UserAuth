package com.sanctuary.auth.services;

import com.sanctuary.auth.dto.AuthResponse;
import com.sanctuary.auth.dto.LoginRequest;
import com.sanctuary.auth.dto.RegisterRequest;
import com.sanctuary.auth.dto.UserShowRequest;
import com.sanctuary.auth.model.AppUser;
import com.sanctuary.auth.model.Role;
import com.sanctuary.auth.repository.UserRepository;
import com.sanctuary.auth.security.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service("authUserService")
public class AuthUserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    public String registerUser(RegisterRequest request, Role role) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new IllegalArgumentException("El usuario ya existe.");
        }
        AppUser newUser = new AppUser();
        newUser.setUsername(request.getUsername());
        newUser.setEmail(request.getEmail());
        newUser.setIdentificationNumber(request.getIdentificationNumber());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        newUser.setRole(role);
        userRepository.save(newUser);
        return "Usuario registrado exitosamente.";
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
            )
        );
        AppUser user = userRepository.findByUsername(request.getUsername())
            .orElseThrow(() -> new IllegalArgumentException("Credenciales inválidas."));
        String token = jwtService.generateToken(user);
        return new AuthResponse(token);
    }

    public List<UserShowRequest> getAllUsers() {
        return userRepository.findAll().stream()
            .map(this::convertToDTO)
            .collect(Collectors.toList());
    }

    public Optional<UserShowRequest> getUserById(Long id) {
        return userRepository.findById(id)
            .map(this::convertToDTO);
    }

    public String updateUser(Long id, RegisterRequest request) {
        AppUser user = userRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado."));

        if (request.getUsername() != null && !request.getUsername().isEmpty()) {
            Optional<AppUser> existing = userRepository.findByUsername(request.getUsername());
            if (existing.isPresent() && !existing.get().getId().equals(id)) {
                throw new IllegalArgumentException("El nombre de usuario ya está en uso.");
            }
            user.setUsername(request.getUsername());
        }
        if (request.getEmail() != null && !request.getEmail().isEmpty()) {
            user.setEmail(request.getEmail());
        }
        if (request.getIdentificationNumber() != null && !request.getIdentificationNumber().isEmpty()) {
            user.setIdentificationNumber(request.getIdentificationNumber());
        }
        if (request.getPassword() != null && !request.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }
        userRepository.save(user);
        return "Usuario actualizado exitosamente.";
    }

    public boolean deleteUser(Long id) {
        if (userRepository.existsById(id)) {
            userRepository.deleteById(id);
            return true;
        }
        return false;
    }

    // Conversión a DTO
    private UserShowRequest convertToDTO(AppUser user) {
        UserShowRequest dto = new UserShowRequest();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setIdentificationNumber(user.getIdentificationNumber());
        dto.setRole(user.getRole());
        return dto;
    }
}

