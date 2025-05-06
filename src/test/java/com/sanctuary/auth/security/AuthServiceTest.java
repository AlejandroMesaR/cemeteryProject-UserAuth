package com.sanctuary.auth.security;

import com.sanctuary.auth.model.AppUser;
import com.sanctuary.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserDetailsServiceImpl userDetailsService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    private AppUser testUser;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        testUser = new AppUser();
        testUser.setUsername("testuser");
        testUser.setPassword("password");
        
        userDetails = mock(UserDetails.class);
    }

    @Test
    void testRegister_ShouldEncodePasswordAndSaveUser() {
        // Arrange
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(userRepository.save(any(AppUser.class))).thenReturn(testUser);

        // Act
        String result = authService.register(testUser);

        // Assert
        assertEquals("Usuario registrado exitosamente", result);
        verify(passwordEncoder).encode("password");
        verify(userRepository).save(testUser);
        assertEquals("encodedPassword", testUser.getPassword());
    }

    @Test
    void testAuthenticate_ShouldValidateCredentialsAndReturnUserDetails() {
        // Arrange
        String username = "testuser";
        String password = "password";
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);

        // Act
        UserDetails result = authService.authenticate(username, password);

        // Assert
        assertNotNull(result);
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(userDetailsService).loadUserByUsername(username);
    }
}