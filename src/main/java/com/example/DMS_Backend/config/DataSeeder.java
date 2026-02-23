package com.example.DMS_Backend.config;

import com.example.DMS_Backend.entities.Role;
import com.example.DMS_Backend.entities.User;
import com.example.DMS_Backend.repositories.UserRepository;
import com.example.DMS_Backend.service.DietitianScheduleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataSeeder implements CommandLineRunner {

        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;
        private final DietitianScheduleService dietitianScheduleService;

        @Override
        public void run(String... args) throws Exception {
                log.info("Starting Data Seeding...");

                seedUsers();
                seedDoctorSchedules();

                log.info("Data Seeding Completed.");
        }

        private void seedUsers() {
                // Admin
                if (!userRepository.existsByUsername("admin")) {
                        User admin = User.builder()
                                        .username("admin")
                                        .email("admin@test.com")
                                        .password(passwordEncoder.encode("admin123"))
                                        .role(Role.ROLE_ADMIN)
                                        .firstName("Super")
                                        .lastName("Admin")
                                        .dateOfBirth(java.time.LocalDate.of(1985, 5, 20))
                                        .age(calculateAge(java.time.LocalDate.of(1985, 5, 20)))
                                        .build();
                        userRepository.save(admin);
                        log.info("Seeded Admin User");
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
                                        .dateOfBirth(java.time.LocalDate.of(1990, 10, 15))
                                        .age(calculateAge(java.time.LocalDate.of(1990, 10, 15)))
                                        .build();
                        userRepository.save(frontdesk);
                        log.info("Seeded Frontdesk User");
                }

                // Dietitian
                if (!userRepository.existsByUsername("sarah")) { // Renamed from dietitian to something unique
                        User dietitian = User.builder()
                                        .username("sarah")
                                        .email("sarah@test.com")
                                        .password(passwordEncoder.encode("sarah123"))
                                        .role(Role.ROLE_DIETITIAN)
                                        .firstName("Sarah")
                                        .lastName("Nutritionist")
                                        .gender("Female")
                                        .dateOfBirth(java.time.LocalDate.of(1988, 3, 10))
                                        .age(calculateAge(java.time.LocalDate.of(1988, 3, 10)))
                                        .build();
                        userRepository.save(dietitian);
                        log.info("Seeded Dietitian User: Sarah");
                }

                // Patient
                if (!userRepository.existsByUsername("john")) { // Renamed from patient to something unique
                        User patient = User.builder()
                                        .username("john")
                                        .email("john@test.com")
                                        .password(passwordEncoder.encode("john123"))
                                        .role(Role.ROLE_PATIENT)
                                        .firstName("John")
                                        .lastName("Doe")
                                        .gender("Male")
                                        .dateOfBirth(java.time.LocalDate.of(1995, 7, 25))
                                        .age(calculateAge(java.time.LocalDate.of(1995, 7, 25)))
                                        .build();
                        userRepository.save(patient);
                        log.info("Seeded Patient User: John");
                }
        }

        private void seedDoctorSchedules() {
                List<User> dietitians = userRepository.findByRole(Role.ROLE_DIETITIAN);
                for (User dietitian : dietitians) {
                        dietitianScheduleService.createDefaultSchedule(dietitian);
                }
        }

        private int calculateAge(java.time.LocalDate dob) {
                return java.time.Period.between(dob, java.time.LocalDate.now()).getYears();
        }
}
