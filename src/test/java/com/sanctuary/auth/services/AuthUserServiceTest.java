package com.sanctuary.auth.services;

import com.sanctuary.auth.dto.AuthResponse;
import com.sanctuary.auth.dto.LoginRequest;
import com.sanctuary.auth.dto.RegisterRequest;
import com.sanctuary.auth.dto.UserShowRequest;
import com.sanctuary.auth.model.AppUser;
import com.sanctuary.auth.model.Role;
import com.sanctuary.auth.repository.UserRepository;
import com.sanctuary.auth.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthUserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private AuthUserService authUserService;

    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;
    private AppUser testUser;

    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");
        registerRequest.setEmail("test@example.com");
        registerRequest.setIdentificationNumber("12345");
        registerRequest.setPassword("password");

        loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password");

        testUser = new AppUser();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");
        testUser.setIdentificationNumber("12345");
        testUser.setPassword("encodedPassword");
        testUser.setRole(Role.USER);
    }

    @Test
    void testRegisterUser_WhenUserDoesNotExist_ShouldRegisterSuccessfully() {
        // Arrange
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(userRepository.save(any(AppUser.class))).thenReturn(testUser);

        // Act
        String result = authUserService.registerUser(registerRequest, Role.USER);

        // Assert
        assertEquals("Usuario registrado exitosamente.", result);
        verify(userRepository).findByUsername("testuser");
        verify(passwordEncoder).encode("password");
        verify(userRepository).save(any(AppUser.class));
    }

    @Test
    void testRegisterUser_WhenUserExists_ShouldThrowException() {
        // Arrange
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));

        // Act & Assert
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            authUserService.registerUser(registerRequest, Role.USER);
        });

        assertEquals("El usuario ya existe.", exception.getMessage());
        verify(userRepository).findByUsername("testuser");
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void testLogin_WhenCredentialsAreValid_ShouldReturnToken() {
        // Arrange
        String token = "jwt.token.here";
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(jwtService.generateToken(any(AppUser.class))).thenReturn(token);

        // Act
        AuthResponse response = authUserService.login(loginRequest);

        // Assert
        assertNotNull(response);
        assertEquals(token, response.getToken());
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(userRepository).findByUsername("testuser");
        verify(jwtService).generateToken(testUser);
    }

    @Test
    void testLogin_WhenUserNotFound_ShouldThrowException() {
        // Arrange
        when(authenticationManager.authenticate(any())).thenReturn(null);
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());

        // Act & Assert
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            authUserService.login(loginRequest);
        });

        assertEquals("Credenciales inválidas.", exception.getMessage());
    }

    @Test
    void testGetAllUsers_ShouldReturnListOfUsers() {
        // Arrange
        AppUser user1 = testUser;
        AppUser user2 = new AppUser();
        user2.setId(2L);
        user2.setUsername("user2");
        user2.setEmail("user2@example.com");
        user2.setRole(Role.ADMIN);

        when(userRepository.findAll()).thenReturn(Arrays.asList(user1, user2));

        // Act
        List<UserShowRequest> users = authUserService.getAllUsers();

        // Assert
        assertEquals(2, users.size());
        assertEquals("testuser", users.get(0).getUsername());
        assertEquals("user2", users.get(1).getUsername());
        verify(userRepository).findAll();
    }

    @Test
    void testGetUserById_WhenUserExists_ShouldReturnUser() {
        // Arrange
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));

        // Act
        Optional<UserShowRequest> user = authUserService.getUserById(1L);

        // Assert
        assertTrue(user.isPresent());
        assertEquals("testuser", user.get().getUsername());
        assertEquals("test@example.com", user.get().getEmail());
        verify(userRepository).findById(1L);
    }

    @Test
    void testGetUserById_WhenUserDoesNotExist_ShouldReturnEmpty() {
        // Arrange
        when(userRepository.findById(anyLong())).thenReturn(Optional.empty());

        // Act
        Optional<UserShowRequest> user = authUserService.getUserById(999L);

        // Assert
        assertFalse(user.isPresent());
        verify(userRepository).findById(999L);
    }

    @Test
    void testUpdateUser_WhenUserExists_ShouldUpdateSuccessfully() {
        // Arrange
        RegisterRequest updateRequest = new RegisterRequest();
        updateRequest.setUsername("updateduser");
        updateRequest.setEmail("updated@example.com");
        updateRequest.setPassword("newpassword");

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(userRepository.findByUsername("updateduser")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("newpassword")).thenReturn("newEncodedPassword");
        when(userRepository.save(any(AppUser.class))).thenReturn(testUser);

        // Act
        String result = authUserService.updateUser(1L, updateRequest);

        // Assert
        assertEquals("Usuario actualizado exitosamente.", result);
        assertEquals("updateduser", testUser.getUsername());
        assertEquals("updated@example.com", testUser.getEmail());
        assertEquals("newEncodedPassword", testUser.getPassword());
        verify(userRepository).findById(1L);
        verify(userRepository).findByUsername("updateduser");
        verify(passwordEncoder).encode("newpassword");
        verify(userRepository).save(testUser);
    }

    @Test
    void testUpdateUser_WhenUserDoesNotExist_ShouldThrowException() {
        // Arrange
        when(userRepository.findById(anyLong())).thenReturn(Optional.empty());

        // Act & Assert
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            authUserService.updateUser(999L, registerRequest);
        });

        assertEquals("Usuario no encontrado.", exception.getMessage());
        verify(userRepository).findById(999L);
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void testUpdateUser_WhenUsernameAlreadyExists_ShouldThrowException() {
        // Arrange
        AppUser existingUser = new AppUser();
        existingUser.setId(2L);
        existingUser.setUsername("updateduser");

        RegisterRequest updateRequest = new RegisterRequest();
        updateRequest.setUsername("updateduser");

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(userRepository.findByUsername("updateduser")).thenReturn(Optional.of(existingUser));

        // Act & Assert
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            authUserService.updateUser(1L, updateRequest);
        });

        assertEquals("El nombre de usuario ya está en uso.", exception.getMessage());
        verify(userRepository).findById(1L);
        verify(userRepository).findByUsername("updateduser");
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void testDeleteUser_WhenUserExists_ShouldReturnTrue() {
        // Arrange
        when(userRepository.existsById(1L)).thenReturn(true);
        doNothing().when(userRepository).deleteById(1L);

        // Act
        boolean result = authUserService.deleteUser(1L);

        // Assert
        assertTrue(result);
        verify(userRepository).existsById(1L);
        verify(userRepository).deleteById(1L);
    }

    @Test
    void testDeleteUser_WhenUserDoesNotExist_ShouldReturnFalse() {
        // Arrange
        when(userRepository.existsById(999L)).thenReturn(false);

        // Act
        boolean result = authUserService.deleteUser(999L);

        // Assert
        assertFalse(result);
        verify(userRepository).existsById(999L);
        verify(userRepository, never()).deleteById(anyLong());
    }
}