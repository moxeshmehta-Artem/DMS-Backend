package com.example.DMS_Backend.controllers;

import com.example.DMS_Backend.config.RequireRole;
import com.example.DMS_Backend.dto.request.DietPlanRequest;
import com.example.DMS_Backend.dto.response.DietPlanResponse;
import com.example.DMS_Backend.service.DietPlanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/patients")
@RequiredArgsConstructor
public class DietPlanController {

    private final DietPlanService dietPlanService;

    @PostMapping("/{patientId}/diet-plans")
    @RequireRole("ROLE_DIETITIAN")
    public ResponseEntity<DietPlanResponse> createDietPlan(
            @PathVariable Long patientId,
            @Valid @RequestBody DietPlanRequest request) {
        return ResponseEntity.ok(dietPlanService.createDietPlan(patientId, request));
    }

    @GetMapping("/{patientId}/diet-plans/latest")
    @RequireRole({ "ROLE_PATIENT", "ROLE_DIETITIAN", "ROLE_FRONTDESK" })
    public ResponseEntity<DietPlanResponse> getLatestDietPlan(@PathVariable Long patientId) {
        DietPlanResponse response = dietPlanService.getLatestDietPlan(patientId);
        return response != null ? ResponseEntity.ok(response) : ResponseEntity.noContent().build();
    }

    @GetMapping("/{patientId}/diet-plans/history")
    @RequireRole({ "ROLE_PATIENT", "ROLE_DIETITIAN" })
    public ResponseEntity<List<DietPlanResponse>> getDietPlanHistory(@PathVariable Long patientId) {
        return ResponseEntity.ok(dietPlanService.getDietPlanHistory(patientId));
    }
}
