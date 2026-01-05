package com.dnr.erp.modules.auth.controller;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.dnr.erp.common.dto.AuthResponseDto;
import com.dnr.erp.common.dto.LoginRequestDto;
import com.dnr.erp.common.dto.SignUpRequestDto;
import com.dnr.erp.common.security.UserPrincipal;
import com.dnr.erp.modules.auth.service.AuthService;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "${frontend.origin}", allowCredentials = "true")
public class AuthController {
	
	private final AuthService authService;
	
	public AuthController(AuthService authService) {
		this.authService = authService;
	}
	
	@GetMapping("/verify")
	public ResponseEntity<?> verify(Authentication authentication) {
	    if (authentication == null || !authentication.isAuthenticated()) {
	        return ResponseEntity.status(401).body(Map.of(
	            "message", "Unauthorized"
	        ));
	    }

	    UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();

	    Map<String, Object> userData = Map.of(
	        "id", principal.getUserId(),
	        "email", principal.getEmail(),
	        "fullName", principal.getName(),
	        "role", principal.getRole().name()
	    );

	    return ResponseEntity.ok(Map.of(
	        "message", "Authorized",
	        "user", userData
	    ));
	}
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequestDto request, HttpServletResponse response) {
	    AuthResponseDto auth = authService.login(request);
	    if (auth != null) {
	        authService.setTokenCookie(response, auth.getToken()); 
	        return ResponseEntity.ok("Login successful");
	    }
	    return ResponseEntity.status(401).body("Invalid email or password");
	}
	
	@PostMapping("/signup")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<String> signup(@RequestBody SignUpRequestDto request) {
		return authService.signup(request);
	}
	
	@PostMapping("/logout")
	public ResponseEntity<String> logout(HttpServletResponse response) {
		authService.clearTokenCookie(response);
		return ResponseEntity.ok("Logged out");
	}
	
	@PostMapping("/all-users")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> getAllUsersForAdmin() {
	    List<Map<String, Object>> users = authService.getAllUserDetailsForAdmin();
	    return ResponseEntity.ok(users);
	}		
	
	@PostMapping("/delete-user")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<String> deleteUser(@RequestBody Map<String, String> request) {
	    String idStr = request.get("id");

	    if (idStr == null || idStr.isBlank()) {
	        return ResponseEntity.badRequest().body("Missing user ID");
	    }

	    try {
	        UUID userId = UUID.fromString(idStr);
	        boolean deleted = authService.deleteUserById(userId);

	        if (deleted) {
	            return ResponseEntity.ok("User deleted successfully");
	        } else {
	            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
	        }

	    } catch (IllegalArgumentException e) {
	        return ResponseEntity.badRequest().body("Invalid UUID format");
	    }
	}
	
	@PostMapping("/edit")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<String> editPassword(@RequestBody Map<String, String> request) {
	    String idStr = request.get("id");
	    String newPassword = request.get("newPassword");

	    if (idStr == null || idStr.isBlank()) {
	        return ResponseEntity.badRequest().body("Missing user ID");
	    }
	    if (newPassword == null || newPassword.isBlank()) {
	        return ResponseEntity.badRequest().body("Missing new password");
	    }
	    // (Optional) basic validation; keep or tweak as you like
	    if (newPassword.length() < 6) {
	        return ResponseEntity.badRequest().body("Password must be at least 6 characters");
	    }

	    try {
	        UUID userId = UUID.fromString(idStr);
	        boolean updated = authService.updatePasswordById(userId, newPassword);

	        if (updated) {
	            return ResponseEntity.ok("Password updated successfully");
	        } else {
	            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
	        }
	    } catch (IllegalArgumentException e) {
	        return ResponseEntity.badRequest().body("Invalid UUID format");
	    }
	}


}