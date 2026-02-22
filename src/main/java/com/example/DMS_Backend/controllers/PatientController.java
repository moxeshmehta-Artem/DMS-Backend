package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.dto.request.PatientUpdateDTO;
import com.example.DMS_Backend.dto.response.PatientResponse;
import com.example.DMS_Backend.service.PatientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/patients")
@RequiredArgsConstructor
public class PatientController {

    private final PatientService patientService;

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN') or hasRole('DIETITIAN')")
    public ResponseEntity<PatientResponse> getPatientById(@PathVariable Long id) {
        return ResponseEntity.ok(patientService.getPatientById(id));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> updatePatientProfile(@PathVariable Long id,
            @RequestBody PatientUpdateDTO dto) {
        return ResponseEntity.ok(patientService.updatePatientProfile(id, dto));
    }
}
