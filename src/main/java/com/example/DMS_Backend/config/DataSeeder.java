package com.example.DMS_Backend.config;

import com.example.DMS_Backend.models.Role;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner initDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            // Admin
            if (!userRepository.existsByUsername("admin")) {
                User admin = User.builder()
                        .username("admin")
                        .email("admin@test.com")
                        .password(passwordEncoder.encode("admin123"))
                        .role(Role.ROLE_ADMIN)
                        .firstName("Super")
                        .lastName("Admin")
                        .build();
                userRepository.save(admin);
                System.out.println("Seeded Admin User");
            }

            // Frontdesk
            if (!userRepository.existsByUsername("frontdesk")) {
                User frontdesk = User.builder()
                        .username("frontdesk")
                        .email("frontdesk@test.com")
                        .password(passwordEncoder.encode("frontdesk123"))
                        .role(Role.ROLE_FRONTDESK)
                        .firstName("Front")
                        .lastName("Desk")
                        .build();
                userRepository.save(frontdesk);
                System.out.println("Seeded Frontdesk User");
            }

            // Dietitian
            if (!userRepository.existsByUsername("dietitian")) {
                User dietitian = User.builder()
                        .username("dietitian")
                        .email("dietitian@test.com")
                        .password(passwordEncoder.encode("dietitian123"))
                        .role(Role.ROLE_DIETITIAN)
                        .firstName("Sarah")
                        .lastName("Nutritionist")
                        .gender("Female")
                        .build();
                userRepository.save(dietitian);
                System.out.println("Seeded Dietitian User");
            }

            // Patient
            if (!userRepository.existsByUsername("patient")) {
                User patient = User.builder()
                        .username("patient")
                        .email("patient@test.com")
                        .password(passwordEncoder.encode("patient123"))
                        .role(Role.ROLE_PATIENT)
                        .firstName("John")
                        .lastName("Doe")
                        .gender("Male")
                        .build();
                userRepository.save(patient);
                System.out.println("Seeded Patient User");
            }
        };
    }
}
