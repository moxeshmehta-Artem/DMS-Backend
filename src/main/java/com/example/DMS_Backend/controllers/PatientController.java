package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.config.RequireRole;
import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.service.PatientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/patients")
@RequiredArgsConstructor
public class PatientController {

    private final PatientService patientService;

    @GetMapping("/{id}")
    @RequireRole({ "ROLE_PATIENT", "ROLE_ADMIN", "ROLE_DIETITIAN" })
    public ResponseEntity<PatientResponse> getPatientById(@PathVariable Long id) {
        return ResponseEntity.ok(patientService.getPatientById(id));
    }
}
