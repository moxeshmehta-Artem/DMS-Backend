package com.example.DMS_Backend.config;

import com.example.DMS_Backend.models.Role;
import com.example.DMS_Backend.models.User;
import com.example.DMS_Backend.repositories.UserRepository;
import com.example.DMS_Backend.service.DietitianScheduleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j; // Add logging
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final DietitianScheduleService dietitianScheduleService;

    @Override
    public void run(String... args) throws Exception {
        log.info("Starting Data Initialization...");
        seedDoctorSchedules();
        log.info("Data Initialization Completed.");
    }

    private void seedDoctorSchedules() {
        List<User> dietitians = userRepository.findByRole(Role.ROLE_DIETITIAN);
        if (dietitians.isEmpty()) {
            log.info("No dietitians found to seed schedules.");
            return;
        }

        for (User dietitian : dietitians) {
            log.info("Seeding schedule for dietitian: {}", dietitian.getUsername());
            dietitianScheduleService.createDefaultSchedule(dietitian);
        }
    }
}
