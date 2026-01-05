package com.dnr.erp.common.security;

import java.util.UUID;

public class UserPrincipal {
    private final UUID userId;
    private final String email;
    private final String name;
    private final Role role;

    public UserPrincipal(UUID userId, String email, String name, Role role) {
        this.userId = userId;
        this.email = email;
        this.name = name;
        this.role = role;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }

    public Role getRole() {
        return role;
    }

    @Override
    public String toString() {
        return userId.toString();
    }
}
