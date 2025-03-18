package com.sanctuary.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.sanctuary.auth.model.AppUser;

import java.util.Optional;

// Anotación para indicar que esta interfaz es un repositorio de Spring
@Repository
public interface UserRepository extends JpaRepository<AppUser, Long> {
    // Método para encontrar un usuario por su nombre de usuario
    Optional<AppUser> findByUsername(String username);
}
