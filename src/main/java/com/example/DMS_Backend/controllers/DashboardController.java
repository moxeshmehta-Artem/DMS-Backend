package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.dto.response.DashboardSummaryResponse;
import com.example.DMS_Backend.models.AppointmentStatus;
import com.example.DMS_Backend.models.Role;
import com.example.DMS_Backend.repositories.AppointmentRepository;
import com.example.DMS_Backend.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;

@RestController
@RequestMapping("/api/v1/dashboard")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class DashboardController {

    private final UserRepository userRepository;
    private final AppointmentRepository appointmentRepository;

    @GetMapping("/summary")
    public ResponseEntity<DashboardSummaryResponse> getDashboardSummary() {
        long totalPatients = userRepository.countByRole(Role.ROLE_PATIENT); // Assuming Role enum has ROLE_PATIENT
        long totalDoctors = userRepository.countByRole(Role.ROLE_DIETITIAN); // Assuming Role enum has ROLE_DIETITIAN

        long totalAppointments = appointmentRepository.count();
        long pendingAppointments = appointmentRepository.countByStatus(AppointmentStatus.PENDING);
        long todayAppointments = appointmentRepository.countByAppointmentDate(LocalDate.now());

        DashboardSummaryResponse response = DashboardSummaryResponse.builder()
                .totalPatients(totalPatients)
                .totalDoctors(totalDoctors)
                .totalAppointments(totalAppointments)
                .pendingAppointments(pendingAppointments)
                .todayAppointments(todayAppointments)
                .build();

        return ResponseEntity.ok(response);
    }
}
