package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.dto.request.AppointmentRequest;
import com.example.DMS_Backend.dto.response.AppointmentResponse;
import com.example.DMS_Backend.models.AppointmentStatus;
import com.example.DMS_Backend.service.AppointmentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/appointments")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class AppointmentController {

    private final AppointmentService appointmentService;

    @PostMapping
    public ResponseEntity<AppointmentResponse> bookAppointment(@Valid @RequestBody AppointmentRequest request) {
        return ResponseEntity.ok(appointmentService.bookAppointment(request));
    }

    @GetMapping
    public ResponseEntity<List<AppointmentResponse>> getAllAppointments() {
        return ResponseEntity.ok(appointmentService.getAllAppointments());
    }

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<AppointmentResponse>> getPatientAppointments(@PathVariable Long patientId) {
        return ResponseEntity.ok(appointmentService.getPatientAppointments(patientId));
    }

    @GetMapping("/provider/{providerId}")
    public ResponseEntity<List<AppointmentResponse>> getProviderAppointments(@PathVariable Long providerId) {
        return ResponseEntity.ok(appointmentService.getProviderAppointments(providerId));
    }

    @PutMapping("/{id}/status")
    public ResponseEntity<AppointmentResponse> updateStatus(
            @PathVariable Long id,
            @RequestParam AppointmentStatus status,
            @RequestParam(required = false) String notes) {
        return ResponseEntity.ok(appointmentService.updateStatus(id, status, notes));
    }
}
