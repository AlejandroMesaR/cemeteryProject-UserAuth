package com.sanctuary.auth.controller;

import org.springframework.web.bind.annotation.*;

import com.sanctuary.auth.model.AppUser;
import com.sanctuary.auth.repository.UserRepository;

import java.util.List;

import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/test")
public class DatabaseTestController {
    private final UserRepository userRepository;

    public DatabaseTestController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/db-status")
    public ResponseEntity<String> checkDatabaseConnection() {
        try {
            long count = userRepository.count();
            return ResponseEntity.ok("Conexión exitosa. Número de usuarios: " + count);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error de conexión a la base de datos: " + e.getMessage());
        }
    }

    // Endpoint para listar todos los usuarios en la base de datos
    @GetMapping("/users")
    public ResponseEntity<List<AppUser>> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }
}
