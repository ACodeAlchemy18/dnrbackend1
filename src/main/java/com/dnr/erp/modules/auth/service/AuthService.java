package com.dnr.erp.modules.auth.service;

import com.dnr.erp.common.dto.AuthResponseDto;
import com.dnr.erp.common.dto.LoginRequestDto;
import com.dnr.erp.common.dto.SignUpRequestDto;
import com.dnr.erp.common.security.JwtUtil;
import com.dnr.erp.common.security.Role;
import com.dnr.erp.modules.auth.entity.User;
import com.dnr.erp.modules.auth.repository.UserRepository;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.auth.cookie-secure:true}")
    private boolean cookieSecure;

    @Value("${app.auth.cookie-samesite:None}")
    private String cookieSameSite;

    public AuthService(UserRepository userRepository, JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    public void setTokenCookie(HttpServletResponse response, String token) {
        ResponseCookie cookie = ResponseCookie.from("token", token)
            .httpOnly(true)
            .secure(cookieSecure)                 // ← false on localhost, true in prod
            .sameSite(cookieSameSite)             // ← None if your frontend is on a different origin
            .path("/")
            .maxAge(60 * 60 * 5)                         // 5 hour
            .build();

        response.addHeader("Set-Cookie", cookie.toString());
    }

    public void clearTokenCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from("token", "")
            .httpOnly(true)
            .secure(cookieSecure)
            .sameSite(cookieSameSite)
            .path("/")
            .maxAge(0)
            .build();

        response.addHeader("Set-Cookie", cookie.toString());
    }
    
    private String normEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(java.util.Locale.ROOT);
    }

    public AuthResponseDto login(LoginRequestDto request) {
        String email = normEmail(request.getEmail());
        return userRepository.findByEmail(email)   // storage will be lowercased too
            .map(user -> {
                String raw = request.getPassword();
                String stored = user.getPassword();
                boolean isBcrypt = stored != null &&
                    (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$"));

                boolean ok = isBcrypt ? passwordEncoder.matches(raw, stored) : stored != null && stored.equals(raw);
                if (!ok) return null;

                if (!isBcrypt) { user.setPassword(passwordEncoder.encode(raw)); userRepository.save(user); }
                String token = jwtUtil.generateToken(user.getId(), user.getRole(), user.getEmail(), user.getFullName());
                return new AuthResponseDto(token, user.getEmail(), user.getFullName(), user.getRole().name());
            })
            .orElse(null);
    }

    private String generateEmployeeId() {
        return "DNR" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();
    }

    public ResponseEntity<String> signup(SignUpRequestDto request) {
        String email = normEmail(request.getEmail());
        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.status(409).body("Email already in use");
        }
        String newEmployeeId = generateEmployeeId();
        User user = new User();
        user.setEmail(email); // ← normalized
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFullName(request.getFullName());
        user.setRole(Role.valueOf(request.getRole()));
        user.setEmployeeId(newEmployeeId);
        userRepository.save(user);
        return ResponseEntity.ok("Signup successful. Employee ID = " + newEmployeeId);
    }

    public List<Map<String, Object>> getAllUserDetailsForAdmin() {
        return userRepository.findAll().stream()
            .map(user -> {
                Map<String, Object> map = new HashMap<>();
                map.put("id", user.getId());
                map.put("fullName", user.getFullName());
                map.put("email", user.getEmail());
                map.put("employeeId", user.getEmployeeId());
                map.put("role", user.getRole().name());
                return map;
            })
            .collect(Collectors.toList());
    }

    public boolean deleteUserById(UUID id) {
        Optional<User> user = userRepository.findById(id);
        if (user.isPresent()) {
            userRepository.deleteById(id);
            return true;
        }
        return false;
    }

    public boolean updatePasswordById(UUID id, String newPassword) {
        Optional<User> opt = userRepository.findById(id);
        if (opt.isEmpty()) return false;

        User user = opt.get();
        user.setPassword(passwordEncoder.encode(newPassword)); // hash
        userRepository.save(user);
        return true;
    }
}
