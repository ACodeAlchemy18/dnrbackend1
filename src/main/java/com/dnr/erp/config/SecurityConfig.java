package com.dnr.erp.config;

import com.dnr.erp.common.security.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import com.dnr.erp.common.security.Role;
import com.dnr.erp.common.security.UserPrincipal;

import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@EnableMethodSecurity
@Configuration
public class SecurityConfig {

    @Autowired
    private JwtUtil jwtUtil;
    
    @Value("${frontend.origin}")
    private String frontendOrigin;
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
    
//    @Bean
//    public RateLimitFilter rateLimitFilter(JwtUtil jwtUtil) {
//        return new RateLimitFilter(jwtUtil);
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(List.of(frontendOrigin)); // For dev; restrict in prod
                config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
//                config.setExposedHeaders(List.of("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"));
                config.setAllowCredentials(true);
//                config.setMaxAge(3600L);
                return config;
            }))
            .authorizeHttpRequests(auth -> auth
            	.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()    //might remove later # Varun
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public OncePerRequestFilter jwtFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                    throws ServletException, IOException {

                String token = null;

                // Authorization
                String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    token = authHeader.substring(7);
                }

                // Fallback to cookie
                if (token == null && request.getCookies() != null) {
                    for (var cookie : request.getCookies()) {
                        if ("token".equals(cookie.getName())) {
                            token = cookie.getValue();
                            break;
                        }
                    }
                }

                if (token != null) {
                    try {
                        var claims = jwtUtil.parseAllClaims(token);

                        UUID userId = jwtUtil.validateAndExtractUserId(token);
                        Role role = jwtUtil.extractUserRole(token);
                        String email = claims.get("email", String.class);
                        String name = claims.get("name", String.class);

                        var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
                        var principal = new UserPrincipal(userId, email, name, role); // ✅ full object

                        var authentication = new UsernamePasswordAuthenticationToken(
                                principal, // ✅ full UserPrincipal, not String
                                null,
                                authorities
                        );

                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    } catch (Exception ex) {
                        System.err.println("❌ Invalid JWT: " + ex.getMessage());
                    }
                }

                chain.doFilter(request, response);
            }
        };
    }
}