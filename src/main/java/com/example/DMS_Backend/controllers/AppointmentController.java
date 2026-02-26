package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.config.RequireRole;
import com.example.DMS_Backend.dto.request.AppointmentRequest;
import com.example.DMS_Backend.dto.response.AppointmentResponse;
import com.example.DMS_Backend.entities.AppointmentStatus;
import com.example.DMS_Backend.service.AppointmentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/appointments")
@RequiredArgsConstructor
public class AppointmentController {

    private final AppointmentService appointmentService;

    @PostMapping
    @RequireRole({ "ROLE_PATIENT", "ROLE_FRONTDESK" })
    public ResponseEntity<AppointmentResponse> bookAppointment(@Valid @RequestBody AppointmentRequest request) {
        return ResponseEntity.ok(appointmentService.bookAppointment(request));
    }

    @GetMapping
    @RequireRole({ "ROLE_ADMIN", "ROLE_FRONTDESK" })
    public ResponseEntity<List<AppointmentResponse>> getAllAppointments() {
        return ResponseEntity.ok(appointmentService.getAllAppointments());
    }

    @GetMapping("/patient/{patientId}")
    @RequireRole({ "ROLE_PATIENT", "ROLE_FRONTDESK", "ROLE_ADMIN" })
    public ResponseEntity<List<AppointmentResponse>> getPatientAppointments(@PathVariable Long patientId) {
        return ResponseEntity.ok(appointmentService.getPatientAppointments(patientId));
    }

    @GetMapping("/provider/{providerId}")
    @RequireRole({ "ROLE_DIETITIAN", "ROLE_ADMIN" })
    public ResponseEntity<List<AppointmentResponse>> getProviderAppointments(@PathVariable Long providerId) {
        return ResponseEntity.ok(appointmentService.getProviderAppointments(providerId));
    }

    @PutMapping("/{id}/status")
    @RequireRole({ "ROLE_FRONTDESK", "ROLE_DIETITIAN" })
    public ResponseEntity<AppointmentResponse> updateStatus(
            @PathVariable Long id,
            @RequestParam AppointmentStatus status,
            @RequestParam(required = false) String notes) {
        return ResponseEntity.ok(appointmentService.updateStatus(id, status, notes));
    }

    @GetMapping("/available-slots")
    @RequireRole({ "ROLE_PATIENT", "ROLE_FRONTDESK" })
    public ResponseEntity<List<String>> getAvailableSlots(
            @RequestParam Long providerId,
            @RequestParam @org.springframework.format.annotation.DateTimeFormat(iso = org.springframework.format.annotation.DateTimeFormat.ISO.DATE) java.time.LocalDate date) {
        return ResponseEntity.ok(appointmentService.getAvailableSlots(providerId, date));
    }
}
