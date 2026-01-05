package com.dnr.erp.common.security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.dnr.erp.modules.auth.repository.UserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;

@Component
@Profile("migrate-passwords") // run with --spring.profiles.active=migrate-passwords
public class PasswordHashMigrationRunner implements CommandLineRunner {

    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public PasswordHashMigrationRunner(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @Override
    public void run(String... args) {
        repo.findAll().forEach(u -> {
            String p = u.getPassword();
            // BCrypt hashes start with $2a/$2b/$2y — skip if already encoded
            if (p != null && !p.startsWith("$2a$") && !p.startsWith("$2b$") && !p.startsWith("$2y$")) {
                u.setPassword(encoder.encode(p));
                repo.save(u);
            }
        });
        System.out.println("✅ Password migration complete.");
    }
}

