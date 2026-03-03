package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.config.RequireRole;
import com.example.DMS_Backend.dto.request.VitalsRequest;
import com.example.DMS_Backend.dto.response.VitalsResponse;
import com.example.DMS_Backend.service.VitalsService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/patients")
@RequiredArgsConstructor
public class VitalsController {

    private final VitalsService vitalsService;

    @PostMapping("/{patientId}/vitals")
    @RequireRole({ "ROLE_FRONTDESK" })
    public ResponseEntity<VitalsResponse> addVitals(
            @PathVariable Long patientId,
            @Valid @RequestBody VitalsRequest request) {
        return ResponseEntity.ok(vitalsService.addVitals(patientId, request));
    }

    @GetMapping("/{patientId}/vitals")
    @RequireRole({ "ROLE_FRONTDESK", "ROLE_DIETITIAN", "ROLE_PATIENT" })
    public ResponseEntity<List<VitalsResponse>> getVitalsHistory(@PathVariable Long patientId) {
        return ResponseEntity.ok(vitalsService.getVitalsHistory(patientId));
    }

    @GetMapping("/{patientId}/vitals/latest")
    @RequireRole({ "ROLE_FRONTDESK", "ROLE_DIETITIAN", "ROLE_PATIENT" })
    public ResponseEntity<VitalsResponse> getLatestVitals(@PathVariable Long patientId) {
        return ResponseEntity.ok(vitalsService.getLatestVitals(patientId));
    }

    @PutMapping("/vitals/{vitalsId}")
    @RequireRole({ "ROLE_FRONTDESK" })
    public ResponseEntity<VitalsResponse> updateVitals(
            @PathVariable Long vitalsId,
            @Valid @RequestBody VitalsRequest request) {
        return ResponseEntity.ok(vitalsService.updateVitals(vitalsId, request));
    }
}
