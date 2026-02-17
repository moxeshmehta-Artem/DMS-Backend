package com.example.DMS_Backend.dto.response;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Builder
public class DietPlanResponse {
    private Long id;
    private Long patientId;
    private String patientName;
    private Long dietitianId;
    private String dietitianName;
    private String breakfast;
    private String lunch;
    private String dinner;
    private String snacks;
    private LocalDateTime createdAt;
}
