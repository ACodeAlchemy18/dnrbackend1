package com.dnr.erp.common.dto;

public class UserSummaryDto {
    private String fullName;
    private String email;
    private String employeeId;
    private String role;

    public UserSummaryDto(String fullName, String email, String employeeId, String role) {
        this.fullName = fullName;
        this.email = email;
        this.employeeId = employeeId;
        this.role = role;
    }

    // Getters
    public String getFullName() {
        return fullName;
    }

    public String getEmail() {
        return email;
    }

    public String getEmployeeId() {
        return employeeId;
    }

    public String getRole() {
        return role;
    }
}