package com.sanctuary.auth.controller;

import com.sanctuary.auth.dto.AuthResponse;
import com.sanctuary.auth.dto.LoginRequest;
import com.sanctuary.auth.dto.RegisterRequest;
import com.sanctuary.auth.model.Role;
import com.sanctuary.auth.services.AuthUserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.sanctuary.auth.dto.UserShowRequest;
import java.util.List;

import java.util.Optional;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthUserService authService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody RegisterRequest request) {
        String msg = authService.registerUser(request, Role.USER);
        return ResponseEntity.ok(msg);
    }

    @PostMapping("/register_admin")
    public ResponseEntity<String> registerAdmin(@RequestBody RegisterRequest request) {
        String msg = authService.registerUser(request, Role.ADMIN);
        return ResponseEntity.ok(msg);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> loginUser(@RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/allUsers")
    public ResponseEntity<List<UserShowRequest>> getAllUsers() {
        List<UserShowRequest> users = authService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserShowRequest> getUserById(@PathVariable Long id) {
        Optional<UserShowRequest> userOpt = authService.getUserById(id);
        return userOpt.map(ResponseEntity::ok)
                      .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/{id}")
    public ResponseEntity<String> updateUser(@PathVariable Long id, @RequestBody RegisterRequest request) {
        String msg = authService.updateUser(id, request);
        return ResponseEntity.ok(msg);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        boolean deleted = authService.deleteUser(id);
        return deleted ? ResponseEntity.ok().build() : ResponseEntity.notFound().build();
    }
}
