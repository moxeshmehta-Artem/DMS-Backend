package com.example.DMS_Backend.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DietPlanRequest {
    @NotBlank(message = "Breakfast plan is required")
    private String breakfast;
    
    @NotBlank(message = "Lunch plan is required")
    private String lunch;
    
    @NotBlank(message = "Dinner plan is required")
    private String dinner;
    
    private String snacks;
    
    private Long dietitianId;
}
