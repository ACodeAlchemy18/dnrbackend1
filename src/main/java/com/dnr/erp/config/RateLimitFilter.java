//package com.dnr.erp.config;
//
//import com.dnr.erp.common.security.JwtUtil;
//import com.dnr.erp.common.security.Role;
//import io.github.bucket4j.Bandwidth;
//import io.github.bucket4j.Bucket;
//import io.github.bucket4j.Refill;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.http.HttpStatus;
//import org.springframework.util.AntPathMatcher;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.time.Duration;
//import java.util.Map;
//import java.util.Objects;
//import java.util.UUID;
//import java.util.concurrent.ConcurrentHashMap;
//import java.util.function.Supplier;
//
//public class RateLimitFilter extends OncePerRequestFilter {
//
//    private final JwtUtil jwtUtil;
//    private final AntPathMatcher pathMatcher = new AntPathMatcher();
//    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();
//
//    // Per-endpoint rules
//    private final Map<String, Supplier<Bandwidth[]>> policies = Map.of(
//        "/api/auth/login", () -> new Bandwidth[]{
//            Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)))
//        },
//        "/api/auth/signup", () -> new Bandwidth[]{
//            Bandwidth.classic(30, Refill.greedy(30, Duration.ofHours(1)))
//        },
//        "/api/auth/verify", () -> new Bandwidth[]{
//            Bandwidth.classic(120, Refill.greedy(120, Duration.ofMinutes(1)))
//        }
//    );
//
//    public RateLimitFilter(JwtUtil jwtUtil) {
//        this.jwtUtil = jwtUtil;
//    }
//
//    @Override
//    protected boolean shouldNotFilter(HttpServletRequest request) {
//        // only guard /api/**
//        return !request.getRequestURI().startsWith("/api/");
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
//            throws ServletException, IOException {
//
//        String path = req.getRequestURI();
//
//        Supplier<Bandwidth[]> supplier = policies.entrySet().stream()
//                .filter(e -> Objects.equals(e.getKey(), path) || pathMatcher.match(e.getKey(), path))
//                .map(Map.Entry::getValue)
//                .findFirst()
//                .orElse(() -> new Bandwidth[]{
//                        Bandwidth.classic(300, Refill.greedy(300, Duration.ofMinutes(1)))
//                });
//
//        String key = resolveKey(req, path);
//
//        Bucket bucket = buckets.computeIfAbsent(key,
//                k -> Bucket.builder().addLimit(supplier.get()).build());
//
//        if (bucket.tryConsume(1)) {
//            chain.doFilter(req, res);
//        } else {
//            res.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
//            res.setContentType("application/json");
//            res.getWriter().write("{\"message\":\"Too many requests. Please slow down.\"}");
//        }
//    }
//
//    private String resolveKey(HttpServletRequest req, String path) {
//        if ("/api/auth/login".equals(path)) {
//            return "ip:" + clientIp(req) + "|path:" + path;
//        }
//
//        String token = extractToken(req);
//        if (token != null) {
//            try {
//                UUID uid = jwtUtil.validateAndExtractUserId(token);
//                return "uid:" + uid + "|path:" + path;
//            } catch (Exception ignored) {}
//        }
//        return "ip:" + clientIp(req) + "|path:" + path;
//    }
//
//    private String extractToken(HttpServletRequest req) {
//        String auth = req.getHeader("Authorization");
//        if (auth != null && auth.startsWith("Bearer ")) return auth.substring(7);
//        if (req.getCookies() != null) {
//            for (var c : req.getCookies()) {
//                if ("token".equals(c.getName())) return c.getValue();
//            }
//        }
//        return null;
//    }
//
//    private String clientIp(HttpServletRequest req) {
//        String hdr = req.getHeader("X-Forwarded-For");
//        if (hdr != null && !hdr.isBlank()) return hdr.split(",")[0].trim();
//        return req.getRemoteAddr();
//    }
//}
