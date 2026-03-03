package com.example.DMS_Backend.service;

import com.example.DMS_Backend.dto.request.DietPlanRequest;
import com.example.DMS_Backend.dto.response.DietPlanResponse;

public interface DietPlanService {
        DietPlanResponse createDietPlan(Long patientId, DietPlanRequest request);

        DietPlanResponse getLatestDietPlan(Long patientId);
}
