package com.sanctuary.auth.dto;

import com.sanctuary.auth.model.Role;

public class UserShowRequest {
    private Long id;
    private String username;
    private String email;
    private String identificationNumber;
    private Role role;

    // Constructor vacío
    public UserShowRequest() {
    }

    // Constructor con todos los campos
    public UserShowRequest(Long id, String username, String email, String identificationNumber, Role role) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.identificationNumber = identificationNumber;
        this.role = role;
    }

    // Getters y setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getIdentificationNumber() {
        return identificationNumber;
    }

    public void setIdentificationNumber(String identificationNumber) {
        this.identificationNumber = identificationNumber;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}