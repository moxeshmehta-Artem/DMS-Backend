package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.dto.request.VitalsRequest;
import com.example.DMS_Backend.dto.response.VitalsResponse;
import com.example.DMS_Backend.services.VitalsService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/patients")
@RequiredArgsConstructor
public class VitalsController {

    private final VitalsService vitalsService;

    @PostMapping("/{patientId}/vitals")
    @PreAuthorize("hasRole('DOCTOR') or hasRole('NURSE') or hasRole('ADMIN') or hasRole('FRONTDESK')")
    public ResponseEntity<String> addVitals(@PathVariable Long patientId, @Valid @RequestBody VitalsRequest request) {
        vitalsService.addVitals(patientId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body("Vitals recorded successfully");
    }

    @GetMapping("/{patientId}/vitals")
    @PreAuthorize("hasRole('DOCTOR') or hasRole('NURSE') or hasRole('ADMIN') or hasRole('PATIENT') or hasRole('FRONTDESK')")
    public ResponseEntity<List<VitalsResponse>> getVitalsHistory(@PathVariable Long patientId) {
        List<VitalsResponse> history = vitalsService.getVitalsHistory(patientId);
        return ResponseEntity.ok(history);
    }
}
