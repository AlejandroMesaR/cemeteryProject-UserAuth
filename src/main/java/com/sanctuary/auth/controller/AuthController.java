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
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;
import com.sanctuary.auth.dto.UserShowRequest;
import java.util.List;
import java.util.stream.Collectors;

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
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + appUser.getRole().name()))

        );

        String token = jwtService.generateToken(userDetails);
        return ResponseEntity.ok(new AuthResponse(token));        
    }


    /** Endpoint para obtener todos los usuarios sin mostrar sus contraseñas */
    @GetMapping("/allUsers")
    public ResponseEntity<List<UserShowRequest>> getAllUsers() {
        List<AppUser> users = userRepository.findAll();
        
        List<UserShowRequest> userDTOs = users.stream()
            .map(user -> new UserShowRequest(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getIdentificationNumber(),
                user.getRole()
            ))
            .collect(Collectors.toList());
        
        return ResponseEntity.ok(userDTOs);
    }


    /** Endpoint para actualizar un usuario existente */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody RegisterRequest request) {
        Optional<AppUser> userOptional = userRepository.findById(id);
        
        if (userOptional.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        AppUser user = userOptional.get();
        
        // Actualizar los campos del usuario
        if (request.getUsername() != null && !request.getUsername().isEmpty()) {
            // Verificar si el nuevo username ya existe y no pertenece a este usuario
            Optional<AppUser> existingUser = userRepository.findByUsername(request.getUsername());
            if (existingUser.isPresent() && !existingUser.get().getId().equals(id)) {
                return ResponseEntity.badRequest().body("El nombre de usuario ya está en uso.");
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
        
        // No actualizamos el rol por seguridad, a menos que se implemente un endpoint específico para eso
        
        userRepository.save(user);
        return ResponseEntity.ok("Usuario actualizado exitosamente.");
    }

    /** Endpoint para eliminar un usuario */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }

        System.out.println("deleteUser "+id);
        
        userRepository.deleteById(id);
        return ResponseEntity.ok("Usuario eliminado exitosamente.");
    }
    
}
